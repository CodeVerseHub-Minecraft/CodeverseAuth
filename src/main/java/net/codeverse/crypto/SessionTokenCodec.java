package net.codeverse.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Signed session tokens stored client-side via Velocity 4 cookies.
 *
 * The token travels on the player's client, so it is treated as fully
 * untrusted input on the way back in. Integrity comes from an HMAC-SHA256
 * over every field using a server-side secret the client never sees; a
 * forged or edited token fails the MAC check and is discarded.
 *
 * Chosen over IP-keyed sessions because Bedrock and mobile players roam
 * between networks constantly, and an IP-keyed session either logs them out
 * on every network change or has to be loosened to the point of being
 * worthless. Binding to the account rather than the address avoids that.
 *
 * Wire format, all big endian:
 *   byte    version
 *   long    internal id high bits
 *   long    internal id low bits
 *   long    issued at, epoch millis
 *   long    expires at, epoch millis
 *   byte[8] random nonce, makes tokens unlinkable across logins
 *   byte[32] HMAC-SHA256 over all preceding bytes
 */
public final class SessionTokenCodec {

    private static final byte VERSION = 1;
    private static final int UUID_BYTES = 16;
    private static final int TIMESTAMP_BYTES = 16;
    private static final int NONCE_BYTES = 8;
    private static final int MAC_BYTES = 32;
    private static final int PAYLOAD_BYTES = 1 + UUID_BYTES + TIMESTAMP_BYTES + NONCE_BYTES;
    private static final int TOTAL_BYTES = PAYLOAD_BYTES + MAC_BYTES;
    private static final int MINIMUM_SECRET_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] secret;

    public SessionTokenCodec(String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("session secret must be set");
        }
        byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
        if (raw.length < MINIMUM_SECRET_BYTES) {
            throw new IllegalArgumentException(
                    "session secret must be at least " + MINIMUM_SECRET_BYTES + " bytes, got " + raw.length);
        }
        this.secret = raw;
    }

    public byte[] issue(UUID internalId, long lifetimeMillis) {
        if (lifetimeMillis <= 0) {
            throw new IllegalArgumentException("session lifetime must be positive");
        }
        long now = System.currentTimeMillis();
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        ByteBuffer buffer = ByteBuffer.allocate(TOTAL_BYTES);
        buffer.put(VERSION);
        buffer.putLong(internalId.getMostSignificantBits());
        buffer.putLong(internalId.getLeastSignificantBits());
        buffer.putLong(now);
        buffer.putLong(now + lifetimeMillis);
        buffer.put(nonce);

        byte[] payload = new byte[PAYLOAD_BYTES];
        buffer.position(0);
        buffer.get(payload);
        buffer.put(sign(payload));
        return buffer.array();
    }

    /**
     * Returns the session's internal id, or null when the token is absent,
     * truncated, the wrong version, forged, or expired. Callers treat null
     * as "no valid session" and fall through to a password prompt.
     */
    public UUID verify(byte[] token) {
        if (token == null || token.length != TOTAL_BYTES) {
            return null;
        }
        byte[] payload = new byte[PAYLOAD_BYTES];
        byte[] presentedMac = new byte[MAC_BYTES];
        System.arraycopy(token, 0, payload, 0, PAYLOAD_BYTES);
        System.arraycopy(token, PAYLOAD_BYTES, presentedMac, 0, MAC_BYTES);

        // MAC verified before any field is interpreted, so malformed or
        // hostile input never reaches the parsing logic.
        if (!MessageDigest.isEqual(sign(payload), presentedMac)) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(payload);
        if (buffer.get() != VERSION) {
            return null;
        }
        long high = buffer.getLong();
        long low = buffer.getLong();
        buffer.getLong();
        long expiresAt = buffer.getLong();
        if (System.currentTimeMillis() >= expiresAt) {
            return null;
        }
        return new UUID(high, low);
    }

    private byte[] sign(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 unavailable", failure);
        }
    }
}
