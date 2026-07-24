package net.codeverse.http;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Decides whether a request is allowed to proceed.
 *
 * Checks run cheapest first and each one that fails ends the request. An
 * unauthorised caller should never reach credential comparison, and a caller
 * being rate limited should never cause an HMAC to be computed on their behalf.
 *
 * The order is: address, then lockout, then rate limit, then credential. A
 * caller can therefore exhaust nothing but their own budget.
 */
public final class ApiAuthenticator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MINIMUM_TOKEN_BYTES = 32;

    /** Outcome of examining a request, distinct enough to log usefully. */
    public enum Result {
        ALLOWED,
        ADDRESS_NOT_PERMITTED,
        LOCKED_OUT,
        RATE_LIMITED,
        MISSING_CREDENTIAL,
        BAD_CREDENTIAL,
        STALE_TIMESTAMP,
        REPLAYED;

        public boolean allowed() {
            return this == ALLOWED;
        }

        /**
         * Whether the caller should be told which check failed.
         *
         * Only the two that a legitimate integration can hit and fix on its own.
         * Telling an unauthenticated caller that their address was rejected, or
         * that a token existed but was wrong, hands them a way to map the
         * defences without ever authenticating.
         */
        public boolean isSafeToReport() {
            return this == RATE_LIMITED || this == STALE_TIMESTAMP;
        }
    }

    private final HttpApiConfig config;
    private final byte[] tokenBytes;
    private final AddressMatcher addresses;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> authFailures = new ConcurrentHashMap<>();
    private final Map<String, Long> lockouts = new ConcurrentHashMap<>();
    /** Recently seen nonces, keyed by signature, to refuse replays inside the window. */
    private final Map<String, Long> seenSignatures = new ConcurrentHashMap<>();

    public ApiAuthenticator(HttpApiConfig config) {
        this.config = config;
        this.tokenBytes = config.token == null
                ? new byte[0]
                : config.token.getBytes(StandardCharsets.UTF_8);
        this.addresses = new AddressMatcher(config.allowedAddresses);
    }

    /** Generates a token for first enable. */
    public static String generateToken() {
        byte[] buffer = new byte[48];
        RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    public static boolean isTokenStrongEnough(String token) {
        return token != null && token.getBytes(StandardCharsets.UTF_8).length >= MINIMUM_TOKEN_BYTES;
    }

    /**
     * Examines a request.
     *
     * @param remoteAddress caller's address, as reported by the socket
     * @param method        HTTP method, part of the signed material
     * @param path          request path, part of the signed material
     * @param body          request body, part of the signed material
     * @param headers       case insensitive view of the request headers
     */
    public Result check(String remoteAddress, String method, String path, byte[] body,
                        Map<String, String> headers) {
        long now = System.currentTimeMillis();

        if (!addresses.permits(remoteAddress)) {
            return Result.ADDRESS_NOT_PERMITTED;
        }
        Long lockedUntil = lockouts.get(remoteAddress);
        if (lockedUntil != null) {
            if (now < lockedUntil) {
                return Result.LOCKED_OUT;
            }
            lockouts.remove(remoteAddress);
            authFailures.remove(remoteAddress);
        }
        if (!withinRateLimit(remoteAddress, now)) {
            return Result.RATE_LIMITED;
        }

        Result credential = config.requireSignedRequests
                ? checkSignature(method, path, body, headers, now)
                : checkBearerToken(headers);

        if (credential.allowed()) {
            authFailures.remove(remoteAddress);
        } else if (credential != Result.STALE_TIMESTAMP) {
            recordAuthFailure(remoteAddress, now);
        }
        return credential;
    }

    private Result checkBearerToken(Map<String, String> headers) {
        String header = headers.get("authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Result.MISSING_CREDENTIAL;
        }
        byte[] presented = header.substring(7).trim().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(tokenBytes, presented) ? Result.ALLOWED : Result.BAD_CREDENTIAL;
    }

    /**
     * Verifies an HMAC over the request.
     *
     * Signed material is method, path, timestamp, nonce and body digest joined
     * by newlines. Each element earns its place. Method and path stop a
     * signature for a harmless read being replayed against a write endpoint.
     * The body digest stops the body being swapped underneath a valid
     * signature. The nonce makes otherwise identical requests distinguishable,
     * without which two legitimate calls in the same second would produce the
     * same signature and the second would be refused as a replay.
     */
    private Result checkSignature(String method, String path, byte[] body,
                                  Map<String, String> headers, long now) {
        String signature = headers.get("x-codeverse-signature");
        String timestamp = headers.get("x-codeverse-timestamp");
        String nonce = headers.get("x-codeverse-nonce");
        if (signature == null || signature.isBlank()
                || timestamp == null || timestamp.isBlank()
                || nonce == null || nonce.isBlank()) {
            return Result.MISSING_CREDENTIAL;
        }

        long sent;
        try {
            sent = Long.parseLong(timestamp.trim());
        } catch (NumberFormatException malformed) {
            return Result.BAD_CREDENTIAL;
        }
        long drift = Math.abs(now / 1000L - sent);
        if (drift > config.signatureToleranceSeconds) {
            return Result.STALE_TIMESTAMP;
        }

        // Verify before recording. A nonce presented with a bad signature must
        // not be able to burn that nonce for the legitimate caller.
        String expected = sign(method, path, sent, nonce, body);
        boolean valid = MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                signature.trim().getBytes(StandardCharsets.UTF_8));
        if (!valid) {
            return Result.BAD_CREDENTIAL;
        }

        // A nonce already seen inside the tolerance window is a replay, even
        // though the signature verifies correctly.
        purgeSeenSignatures(now);
        if (seenSignatures.putIfAbsent(nonce.trim(), now) != null) {
            return Result.REPLAYED;
        }
        return Result.ALLOWED;
    }

    /** Computes the expected signature. Exposed so integrations can be tested against it. */
    public String sign(String method, String path, long epochSeconds, String nonce, byte[] body) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            String bodyDigest = HexFormat.of().formatHex(sha.digest(body == null ? new byte[0] : body));
            String material = method.toUpperCase(Locale.ROOT) + "\n"
                    + path + "\n"
                    + epochSeconds + "\n"
                    + (nonce == null ? "" : nonce.trim()) + "\n"
                    + bodyDigest;

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(tokenBytes, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(material.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 unavailable", failure);
        }
    }

    private boolean withinRateLimit(String address, long now) {
        Window window = windows.computeIfAbsent(address, key -> new Window(now));
        synchronized (window) {
            if (now - window.startedAt >= 60_000L) {
                window.startedAt = now;
                window.count = 0;
            }
            window.count++;
            return window.count <= config.rateLimit.requestsPerMinute;
        }
    }

    private void recordAuthFailure(String address, long now) {
        int failures = authFailures.computeIfAbsent(address, key -> new AtomicInteger()).incrementAndGet();
        if (failures >= config.rateLimit.authFailuresBeforeLockout) {
            lockouts.put(address, now + config.rateLimit.lockoutSeconds * 1000L);
            authFailures.remove(address);
        }
    }

    private void purgeSeenSignatures(long now) {
        long cutoff = now - config.signatureToleranceSeconds * 1000L * 2L;
        seenSignatures.entrySet().removeIf(entry -> entry.getValue() < cutoff);
    }

    /** Discards per address state for callers that have gone quiet. */
    public void sweep() {
        long now = System.currentTimeMillis();
        windows.entrySet().removeIf(entry -> now - entry.getValue().startedAt > 300_000L);
        lockouts.entrySet().removeIf(entry -> now >= entry.getValue());
        purgeSeenSignatures(now);
    }

    public boolean isLockedOut(String address) {
        Long until = lockouts.get(address);
        return until != null && System.currentTimeMillis() < until;
    }

    private static final class Window {
        private long startedAt;
        private int count;

        private Window(long startedAt) {
            this.startedAt = startedAt;
        }
    }

    /** Matches addresses against plain entries and CIDR ranges. */
    public static final class AddressMatcher {
        private final java.util.List<String> exact = new java.util.ArrayList<>();
        private final java.util.List<Cidr> ranges = new java.util.ArrayList<>();
        private final boolean unrestricted;

        public AddressMatcher(java.util.List<String> entries) {
            if (entries == null || entries.isEmpty()) {
                unrestricted = true;
                return;
            }
            unrestricted = false;
            for (String entry : entries) {
                if (entry == null || entry.isBlank()) {
                    continue;
                }
                String trimmed = entry.trim();
                if (trimmed.contains("/")) {
                    Cidr parsed = Cidr.parse(trimmed);
                    if (parsed != null) {
                        ranges.add(parsed);
                    }
                } else {
                    exact.add(trimmed);
                }
            }
        }

        public boolean permits(String address) {
            if (unrestricted) {
                return true;
            }
            if (address == null) {
                return false;
            }
            if (exact.contains(address)) {
                return true;
            }
            for (Cidr range : ranges) {
                if (range.contains(address)) {
                    return true;
                }
            }
            return false;
        }
    }

    /** IPv4 CIDR range. IPv6 ranges are matched exactly rather than by prefix. */
    record Cidr(int network, int mask) {
        static Cidr parse(String text) {
            String[] parts = text.split("/", 2);
            if (parts.length != 2) {
                return null;
            }
            Integer address = toInt(parts[0]);
            if (address == null) {
                return null;
            }
            int prefix;
            try {
                prefix = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException malformed) {
                return null;
            }
            if (prefix < 0 || prefix > 32) {
                return null;
            }
            int mask = prefix == 0 ? 0 : (int) (-1L << (32 - prefix));
            return new Cidr(address & mask, mask);
        }

        boolean contains(String address) {
            Integer value = toInt(address);
            return value != null && (value & mask) == network;
        }

        private static Integer toInt(String address) {
            String[] octets = address.trim().split("\\.");
            if (octets.length != 4) {
                return null;
            }
            int result = 0;
            for (String octet : octets) {
                int value;
                try {
                    value = Integer.parseInt(octet);
                } catch (NumberFormatException malformed) {
                    return null;
                }
                if (value < 0 || value > 255) {
                    return null;
                }
                result = (result << 8) | value;
            }
            return result;
        }
    }
}
