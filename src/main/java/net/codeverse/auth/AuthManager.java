package net.codeverse.auth;

import net.codeverse.config.PluginConfig;
import net.codeverse.crypto.PasswordHasher;
import net.codeverse.crypto.SessionTokenCodec;
import net.codeverse.crypto.TotpService;
import net.codeverse.identity.Identity;
import net.codeverse.identity.IdentityService;
import net.codeverse.identity.TrustTier;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.ThrottleRepository;

import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registration, login, second factor and throttling.
 *
 * Outcomes are returned as an enum rather than thrown, so every caller is
 * forced to handle failure explicitly and no path can accidentally treat an
 * exception as a successful login.
 *
 * Throttling counts failures against both the address and the account name.
 * Counting only the account lets an attacker spray many accounts from one
 * host; counting only the address lets a botnet grind a single account.
 */
public final class AuthManager {

    public enum Outcome {
        SUCCESS,
        AWAITING_TOTP,
        INVALID_CREDENTIALS,
        ALREADY_REGISTERED,
        NOT_REGISTERED,
        PASSWORD_TOO_SHORT,
        PASSWORD_TOO_LONG,
        PASSWORD_MISMATCH,
        LOCKED_OUT,
        TOTP_REQUIRED_NOT_ENROLLED,
        INVALID_TOTP,
        STORAGE_ERROR
    }

    public record Result(Outcome outcome, long lockedUntil) {
        public static Result of(Outcome outcome) {
            return new Result(outcome, 0L);
        }

        public boolean success() {
            return outcome == Outcome.SUCCESS;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private final PluginConfig config;
    private final AccountRepository accounts;
    private final ThrottleRepository throttle;
    private final IdentityService identities;
    private final PasswordHasher hasher;
    private final TotpService totp;
    private final SessionTokenCodec sessions;

    private final Map<UUID, AuthState> pending = new ConcurrentHashMap<>();

    public AuthManager(PluginConfig config,
                       AccountRepository accounts,
                       ThrottleRepository throttle,
                       IdentityService identities,
                       PasswordHasher hasher,
                       TotpService totp,
                       SessionTokenCodec sessions) {
        this.config = config;
        this.accounts = accounts;
        this.throttle = throttle;
        this.identities = identities;
        this.hasher = hasher;
        this.totp = totp;
        this.sessions = sessions;
    }

    public void beginSession(AuthState state) {
        pending.put(state.minecraftId(), state);
    }

    public Optional<AuthState> state(UUID minecraftId) {
        return Optional.ofNullable(pending.get(minecraftId));
    }

    public void endSession(UUID minecraftId) {
        pending.remove(minecraftId);
    }

    public boolean isAuthenticated(UUID minecraftId) {
        AuthState state = pending.get(minecraftId);
        return state != null && state.authenticated();
    }

    /** Verified origins never hold a password with this plugin. */
    public boolean requiresAuthentication(TrustTier tier) {
        return tier.requiresPassword();
    }

    public Result register(AuthState state, char[] password, char[] confirmation) {
        // A verified origin never holds a password here, and an already
        // authenticated session must not be able to set one. Without this a
        // premium or Bedrock player could attach a password to their account
        // that nothing in this plugin would ever check.
        if (!state.identity().tier().requiresPassword() || state.authenticated()) {
            return Result.of(Outcome.ALREADY_REGISTERED);
        }
        int length = password.length;
        if (length < config.security.minimumPasswordLength) {
            return Result.of(Outcome.PASSWORD_TOO_SHORT);
        }
        if (length > config.security.maximumPasswordLength) {
            return Result.of(Outcome.PASSWORD_TOO_LONG);
        }
        if (confirmation != null && !java.util.Arrays.equals(password, confirmation)) {
            return Result.of(Outcome.PASSWORD_MISMATCH);
        }
        try {
            Optional<AccountRepository.StoredAccount> stored = accounts.findByMinecraftId(state.minecraftId());
            if (stored.isPresent() && stored.get().isRegistered()) {
                return Result.of(Outcome.ALREADY_REGISTERED);
            }
            accounts.setPassword(state.minecraftId(), hasher.hash(password));
            accounts.recordLogin(state.minecraftId(), state.address());
            accounts.touchIdentity(state.identity().internalId());
            identities.invalidate(state.minecraftId());
            state.stage(AuthState.Stage.AUTHENTICATED);
            clearThrottle(state);
            return Result.of(Outcome.SUCCESS);
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    public Result login(AuthState state, char[] password) {
        long lockedUntil = lockoutExpiry(state);
        if (lockedUntil > System.currentTimeMillis()) {
            return new Result(Outcome.LOCKED_OUT, lockedUntil);
        }
        try {
            Optional<AccountRepository.StoredAccount> found = accounts.findByMinecraftId(state.minecraftId());
            if (found.isEmpty() || !found.get().isRegistered()) {
                return Result.of(Outcome.NOT_REGISTERED);
            }
            AccountRepository.StoredAccount stored = found.get();
            if (!hasher.verify(password, stored.passwordHash())) {
                return new Result(Outcome.INVALID_CREDENTIALS, registerFailure(state));
            }

            // Cost parameters raised in config are applied transparently on
            // the next correct password, so existing accounts strengthen
            // without anyone being forced to reset.
            if (hasher.needsRehash(stored.passwordHash())) {
                accounts.setPassword(state.minecraftId(), hasher.hash(password));
            }

            if (stored.hasTotp()) {
                state.stage(AuthState.Stage.AWAITING_TOTP);
                return Result.of(Outcome.AWAITING_TOTP);
            }
            if (config.security.requireTotpForStaff && !stored.hasTotp() && stored.tier() == TrustTier.PREMIUM) {
                return Result.of(Outcome.TOTP_REQUIRED_NOT_ENROLLED);
            }
            return completeLogin(state, stored);
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    public Result submitTotp(AuthState state, String code) {
        long lockedUntil = lockoutExpiry(state);
        if (lockedUntil > System.currentTimeMillis()) {
            return new Result(Outcome.LOCKED_OUT, lockedUntil);
        }
        try {
            Optional<AccountRepository.StoredAccount> found = accounts.findByMinecraftId(state.minecraftId());
            if (found.isEmpty() || !found.get().hasTotp()) {
                return Result.of(Outcome.INVALID_TOTP);
            }
            AccountRepository.StoredAccount stored = found.get();
            if (totp.verify(stored.totpSecret(), code)) {
                return completeLogin(state, stored);
            }
            if (consumeRecoveryCode(stored.internalId(), code)) {
                return completeLogin(state, stored);
            }
            return new Result(Outcome.INVALID_TOTP, registerFailure(state));
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    public Result changePassword(UUID minecraftId, char[] current, char[] replacement) {
        if (replacement.length < config.security.minimumPasswordLength) {
            return Result.of(Outcome.PASSWORD_TOO_SHORT);
        }
        if (replacement.length > config.security.maximumPasswordLength) {
            return Result.of(Outcome.PASSWORD_TOO_LONG);
        }
        try {
            Optional<AccountRepository.StoredAccount> found = accounts.findByMinecraftId(minecraftId);
            if (found.isEmpty() || !found.get().isRegistered()) {
                return Result.of(Outcome.NOT_REGISTERED);
            }
            if (!hasher.verify(current, found.get().passwordHash())) {
                return Result.of(Outcome.INVALID_CREDENTIALS);
            }
            accounts.setPassword(minecraftId, hasher.hash(replacement));
            return Result.of(Outcome.SUCCESS);
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    /** Generates a secret and provisioning uri for enrolment, not yet active. */
    public String beginTotpEnrolment() {
        return totp.generateSecret();
    }

    public String provisioningUri(String secret, String username) {
        return totp.provisioningUri(config.totp.issuer, username, secret);
    }

    /**
     * Activates a second factor only after the player proves they can
     * generate a valid code, so nobody locks themselves out by saving a
     * secret their authenticator never received.
     */
    public Result confirmTotpEnrolment(UUID minecraftId, UUID internalId, String secret, String code) {
        if (!totp.verify(secret, code)) {
            return Result.of(Outcome.INVALID_TOTP);
        }
        try {
            accounts.setTotpSecret(minecraftId, secret);
            identities.invalidate(minecraftId);
            return Result.of(Outcome.SUCCESS);
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    public Result disableTotp(UUID minecraftId, char[] password) {
        try {
            Optional<AccountRepository.StoredAccount> found = accounts.findByMinecraftId(minecraftId);
            if (found.isEmpty() || !found.get().isRegistered()) {
                return Result.of(Outcome.NOT_REGISTERED);
            }
            if (!hasher.verify(password, found.get().passwordHash())) {
                return Result.of(Outcome.INVALID_CREDENTIALS);
            }
            accounts.setTotpSecret(minecraftId, null);
            accounts.replaceRecoveryCodes(found.get().internalId(), List.of());
            identities.invalidate(minecraftId);
            return Result.of(Outcome.SUCCESS);
        } catch (SQLException failure) {
            return Result.of(Outcome.STORAGE_ERROR);
        }
    }

    /**
     * Issues single use recovery codes and stores only their hashes, so a
     * database leak does not hand over working second factors.
     */
    public List<String> issueRecoveryCodes(UUID internalId) throws SQLException {
        List<String> plain = new ArrayList<>(config.totp.recoveryCodeCount);
        List<String> hashes = new ArrayList<>(config.totp.recoveryCodeCount);
        for (int i = 0; i < config.totp.recoveryCodeCount; i++) {
            String code = randomRecoveryCode();
            plain.add(code);
            hashes.add(hasher.hash(code.toCharArray()));
        }
        accounts.replaceRecoveryCodes(internalId, hashes);
        return plain;
    }

    private boolean consumeRecoveryCode(UUID internalId, String submitted) throws SQLException {
        String normalised = submitted.trim().toUpperCase(Locale.ROOT).replace("-", "");
        for (String hash : accounts.unusedRecoveryCodeHashes(internalId)) {
            if (hasher.verify(normalised.toCharArray(), hash)) {
                accounts.consumeRecoveryCode(internalId, hash);
                return true;
            }
        }
        return false;
    }

    private Result completeLogin(AuthState state, AccountRepository.StoredAccount stored) throws SQLException {
        accounts.recordLogin(state.minecraftId(), state.address());
        accounts.touchIdentity(stored.internalId());
        state.stage(AuthState.Stage.AUTHENTICATED);
        clearThrottle(state);
        return Result.of(Outcome.SUCCESS);
    }

    public byte[] issueSessionToken(Identity identity) {
        if (!config.session.enabled) {
            return null;
        }
        return sessions.issue(identity.internalId(), config.session.lifetimeSeconds * 1000L);
    }

    public UUID verifySessionToken(byte[] token) {
        if (!config.session.enabled) {
            return null;
        }
        return sessions.verify(token);
    }

    private long lockoutExpiry(AuthState state) {
        try {
            long byAddress = throttle.lockedUntil("ip:" + state.address());
            long byAccount = throttle.lockedUntil("user:" + state.identity().username().toLowerCase(Locale.ROOT));
            return Math.max(byAddress, byAccount);
        } catch (SQLException failure) {
            // A throttle table that cannot be read must not become a way to
            // bypass the throttle, so treat the failure as locked.
            return System.currentTimeMillis() + config.security.lockoutSeconds * 1000L;
        }
    }

    private long registerFailure(AuthState state) {
        try {
            long lockoutMillis = config.security.lockoutSeconds * 1000L;
            long byAddress = throttle.recordFailure("ip:" + state.address(),
                    config.security.maximumFailedAttempts, lockoutMillis);
            long byAccount = throttle.recordFailure("user:" + state.identity().username().toLowerCase(Locale.ROOT),
                    config.security.maximumFailedAttempts, lockoutMillis);
            return Math.max(byAddress, byAccount);
        } catch (SQLException failure) {
            return 0L;
        }
    }

    private void clearThrottle(AuthState state) {
        try {
            throttle.clear("ip:" + state.address());
            throttle.clear("user:" + state.identity().username().toLowerCase(Locale.ROOT));
        } catch (SQLException ignored) {
            // A failure to clear only leaves a stale counter that expires on
            // its own, so it is not worth failing the login over.
        }
    }

    private static String randomRecoveryCode() {
        StringBuilder builder = new StringBuilder(11);
        for (int i = 0; i < 10; i++) {
            if (i == 5) {
                builder.append('-');
            }
            builder.append(RECOVERY_ALPHABET.charAt(RANDOM.nextInt(RECOVERY_ALPHABET.length())));
        }
        return builder.toString();
    }

    public int purgeExpiredThrottles() {
        try {
            return throttle.purgeExpired();
        } catch (SQLException failure) {
            return 0;
        }
    }

    public Map<UUID, AuthState> pendingStates() {
        return Map.copyOf(pending);
    }
}
