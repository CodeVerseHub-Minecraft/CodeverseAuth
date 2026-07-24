package net.codeverse.apiimpl;

import net.codeverse.api.event.IdentityLinkedEvent;
import net.codeverse.api.event.IdentityUnlinkedEvent;
import net.codeverse.api.event.TrustTierChangedEvent;
import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.TrustTier;
import net.codeverse.api.link.LinkCode;
import net.codeverse.api.link.LinkService;
import net.codeverse.cache.IdentityCache;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.LinkCodeRepository;

import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;

/**
 * Discord linking over the account and link code storage.
 *
 * The order of operations in {@link #redeem} is the security relevant part.
 * The code is consumed first, so a failure anywhere afterwards cannot leave a
 * redeemable code behind, and a code cannot be spent twice by two callers
 * racing. Only then is the link written and the promotion attempted.
 */
public final class AuthLinkService implements LinkService {

    private final AccountRepository accounts;
    private final LinkCodeRepository codes;
    private final IdentityCache cache;
    private final AuthEventBus events;
    private final ExecutorService executor;
    private final int codeLength;

    public AuthLinkService(AccountRepository accounts,
                           LinkCodeRepository codes,
                           IdentityCache cache,
                           AuthEventBus events,
                           ExecutorService executor,
                           int codeLength) {
        this.accounts = accounts;
        this.codes = codes;
        this.cache = cache;
        this.events = events;
        this.executor = executor;
        this.codeLength = codeLength;
    }

    @Override
    public CompletableFuture<LinkCode> issueCode(UUID internalId, Duration lifetime) {
        if (internalId == null || lifetime == null || lifetime.isNegative() || lifetime.isZero()) {
            throw new IllegalArgumentException("internalId and a positive lifetime are required");
        }
        return async(() -> {
            Instant issuedAt = Instant.now();
            String code = codes.issue(internalId, codeLength, lifetime.toMillis());
            return new LinkCode(code, internalId, issuedAt, issuedAt.plus(lifetime));
        });
    }

    @Override
    public CompletableFuture<Optional<Identity>> redeem(String code, String discordId) {
        if (code == null || code.isBlank() || discordId == null || discordId.isBlank()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return async(() -> {
            Optional<UUID> redeemed = codes.redeem(code);
            if (redeemed.isEmpty()) {
                // Unknown, expired and already redeemed are one outcome by
                // design. Distinguishing them tells an unauthenticated caller
                // which codes exist.
                return Optional.empty();
            }
            UUID internalId = redeemed.get();

            Optional<AccountRepository.StoredAccount> before = accounts.findByInternalId(internalId);
            if (before.isEmpty()) {
                // The code outlived the account it belonged to. Nothing to
                // link, and the code is already spent.
                return Optional.empty();
            }
            TrustTier previous = before.get().tier();

            accounts.setDiscordId(internalId, discordId);

            // Only from CRACKED, enforced in SQL rather than by checking
            // first. A PREMIUM account linking Discord must not be demoted:
            // DISCORD_LINKED sits lower on the ladder, and a check followed
            // by a write would still lose a race against a login that
            // upgraded the tier in between.
            int promoted = accounts.setTierForIdentity(internalId, TrustTier.DISCORD_LINKED, TrustTier.CRACKED);

            invalidateEvery(internalId);

            Optional<AccountRepository.StoredAccount> after = accounts.findByInternalId(internalId);
            if (after.isEmpty()) {
                return Optional.empty();
            }
            Identity identity = ApiIdentities.toApi(after.get());

            Instant now = Instant.now();
            events.publish(new IdentityLinkedEvent(identity, discordId, now, false));
            if (promoted > 0) {
                events.publish(new TrustTierChangedEvent(identity, previous, identity.tier(), now, false));
            }
            return Optional.of(identity);
        });
    }

    @Override
    public CompletableFuture<Boolean> unlink(UUID internalId) {
        if (internalId == null) {
            return CompletableFuture.completedFuture(false);
        }
        return async(() -> {
            Optional<AccountRepository.StoredAccount> before = accounts.findByInternalId(internalId);
            if (before.isEmpty() || !before.get().hasDiscordLink()) {
                return false;
            }
            return applyUnlink(internalId, before.get().discordId(), before.get().tier());
        });
    }

    @Override
    public CompletableFuture<Boolean> unlinkByDiscordId(String discordId) {
        if (discordId == null || discordId.isBlank()) {
            return CompletableFuture.completedFuture(false);
        }
        return async(() -> {
            Optional<AccountRepository.StoredAccount> before = accounts.findByDiscordId(discordId);
            if (before.isEmpty()) {
                return false;
            }
            return applyUnlink(before.get().internalId(), discordId, before.get().tier());
        });
    }

    @Override
    public CompletableFuture<Optional<String>> discordIdOf(UUID internalId) {
        if (internalId == null) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return async(() -> accounts.findByInternalId(internalId)
                .map(AccountRepository.StoredAccount::discordId)
                .filter(value -> value != null && !value.isBlank()));
    }

    @Override
    public CompletableFuture<Integer> purgeExpiredCodes() {
        return async(codes::purgeExpired);
    }

    /**
     * Removes a link and reverses the promotion it granted.
     *
     * Demotion is conditional on the tier still being DISCORD_LINKED for the
     * same reason promotion is conditional on CRACKED: an account that has
     * since been verified as premium must keep that tier, which it earned
     * from the connection rather than from the link being removed here.
     */
    private boolean applyUnlink(UUID internalId, String discordId, TrustTier previous) throws SQLException {
        accounts.setDiscordId(internalId, null);
        int demoted = accounts.setTierForIdentity(internalId, TrustTier.CRACKED, TrustTier.DISCORD_LINKED);
        codes.discardFor(internalId);
        invalidateEvery(internalId);

        Optional<AccountRepository.StoredAccount> after = accounts.findByInternalId(internalId);
        if (after.isPresent()) {
            Identity identity = ApiIdentities.toApi(after.get());
            Instant now = Instant.now();
            events.publish(new IdentityUnlinkedEvent(identity, discordId, now, false));
            if (demoted > 0) {
                events.publish(new TrustTierChangedEvent(identity, previous, identity.tier(), now, false));
            }
        }
        return true;
    }

    /**
     * Drops the cached view of every account belonging to the person.
     *
     * Linking and promotion are identity wide writes, so invalidating only
     * the account that happened to be looked up would leave the others
     * serving a stale tier until their entries expired. That window is
     * exactly when a player checks whether their link worked.
     */
    private void invalidateEvery(UUID internalId) throws SQLException {
        List<AccountRepository.StoredAccount> all = accounts.findAllByInternalId(internalId);
        for (AccountRepository.StoredAccount account : all) {
            cache.invalidateIdentity(account.minecraftId().toString());
        }
    }

    private <T> CompletableFuture<T> async(SqlWork<T> work) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return work.call();
            } catch (SQLException failure) {
                throw new CompletionException(failure);
            }
        }, executor);
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T call() throws SQLException;
    }
}
