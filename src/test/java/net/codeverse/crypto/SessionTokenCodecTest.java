package net.codeverse.crypto;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Session cookies live on the client, so these tests exist to prove that a
 * modified or replayed cookie cannot authenticate anyone.
 */
class SessionTokenCodecTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef!";

    @Test
    void validTokenRoundTrips() {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        UUID identity = UUID.randomUUID();
        assertEquals(identity, codec.verify(codec.issue(identity, 60_000)));
    }

    @Test
    void rejectsTamperedPayload() {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        byte[] token = codec.issue(UUID.randomUUID(), 60_000);
        token[5] ^= 0x01;
        assertNull(codec.verify(token));
    }

    @Test
    void rejectsTamperedSignature() {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        byte[] token = codec.issue(UUID.randomUUID(), 60_000);
        token[token.length - 1] ^= 0x01;
        assertNull(codec.verify(token));
    }

    @Test
    void rejectsTokenSignedByADifferentSecret() {
        SessionTokenCodec issuer = new SessionTokenCodec(SECRET);
        SessionTokenCodec other = new SessionTokenCodec("ffffffffffffffffffffffffffffffff!");
        assertNull(other.verify(issuer.issue(UUID.randomUUID(), 60_000)));
    }

    @Test
    void rejectsExpiredToken() throws InterruptedException {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        byte[] token = codec.issue(UUID.randomUUID(), 1);
        Thread.sleep(20);
        assertNull(codec.verify(token));
    }

    @Test
    void rejectsTruncatedAndNullTokens() {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        assertNull(codec.verify(null));
        assertNull(codec.verify(new byte[0]));
        assertNull(codec.verify(new byte[]{1, 2, 3}));
    }

    @Test
    void tokensForTheSameIdentityAreNotLinkable() {
        SessionTokenCodec codec = new SessionTokenCodec(SECRET);
        UUID identity = UUID.randomUUID();
        assertFalse(java.util.Arrays.equals(codec.issue(identity, 60_000), codec.issue(identity, 60_000)));
    }

    @Test
    void refusesWeakSecret() {
        assertThrows(IllegalArgumentException.class, () -> new SessionTokenCodec("tooshort"));
        assertThrows(IllegalArgumentException.class, () -> new SessionTokenCodec(null));
    }
}
