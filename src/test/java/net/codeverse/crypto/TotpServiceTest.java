package net.codeverse.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the TOTP implementation against the complete RFC 6238 Appendix B
 * table. These vectors are the reason a hand written RFC 6238 implementation
 * is acceptable here: correctness is checkable against the specification
 * rather than taken on trust.
 */
class TotpServiceTest {

    private static final byte[] SEED_SHA1 =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA256 =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED_SHA512 =
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    private static String codeAt(String algorithm, byte[] seed, long epochSeconds) {
        return new TotpService(algorithm, 8, 30, 0, 16).generate(seed, Math.floorDiv(epochSeconds, 30L));
    }

    @Test
    void matchesRfc6238Sha1Vectors() {
        assertEquals("94287082", codeAt("SHA1", SEED_SHA1, 59L));
        assertEquals("07081804", codeAt("SHA1", SEED_SHA1, 1111111109L));
        assertEquals("14050471", codeAt("SHA1", SEED_SHA1, 1111111111L));
        assertEquals("89005924", codeAt("SHA1", SEED_SHA1, 1234567890L));
        assertEquals("69279037", codeAt("SHA1", SEED_SHA1, 2000000000L));
        assertEquals("65353130", codeAt("SHA1", SEED_SHA1, 20000000000L));
    }

    @Test
    void matchesRfc6238Sha256Vectors() {
        assertEquals("46119246", codeAt("SHA256", SEED_SHA256, 59L));
        assertEquals("68084774", codeAt("SHA256", SEED_SHA256, 1111111109L));
        assertEquals("67062674", codeAt("SHA256", SEED_SHA256, 1111111111L));
        assertEquals("91819424", codeAt("SHA256", SEED_SHA256, 1234567890L));
        assertEquals("90698825", codeAt("SHA256", SEED_SHA256, 2000000000L));
        assertEquals("77737706", codeAt("SHA256", SEED_SHA256, 20000000000L));
    }

    @Test
    void matchesRfc6238Sha512Vectors() {
        assertEquals("90693936", codeAt("SHA512", SEED_SHA512, 59L));
        assertEquals("25091201", codeAt("SHA512", SEED_SHA512, 1111111109L));
        assertEquals("99943326", codeAt("SHA512", SEED_SHA512, 1111111111L));
        assertEquals("93441116", codeAt("SHA512", SEED_SHA512, 1234567890L));
        assertEquals("38618901", codeAt("SHA512", SEED_SHA512, 2000000000L));
        assertEquals("47863826", codeAt("SHA512", SEED_SHA512, 20000000000L));
    }

    @Test
    void base32RoundTripsExactly() {
        assertArrayEquals(SEED_SHA1, TotpService.base32Decode(TotpService.base32Encode(SEED_SHA1)));
    }

    @Test
    void acceptsCodesInsideDriftWindowAndRejectsOutside() {
        TotpService service = new TotpService("SHA1", 6, 30, 1, 20);
        String secret = TotpService.base32Encode(SEED_SHA1);
        long now = 1234567890L;
        long counter = Math.floorDiv(now, 30L);

        assertTrue(service.verifyAt(secret, service.generate(SEED_SHA1, counter), now));
        assertTrue(service.verifyAt(secret, service.generate(SEED_SHA1, counter - 1), now));
        assertTrue(service.verifyAt(secret, service.generate(SEED_SHA1, counter + 1), now));
        assertFalse(service.verifyAt(secret, service.generate(SEED_SHA1, counter - 5), now));
    }

    @Test
    void rejectsMalformedInputWithoutThrowing() {
        TotpService service = new TotpService("SHA1", 6, 30, 1, 20);
        String secret = TotpService.base32Encode(SEED_SHA1);
        assertFalse(service.verifyAt("not valid base32 !!!", "123456", 1234567890L));
        assertFalse(service.verifyAt(secret, "1234", 1234567890L));
        assertFalse(service.verifyAt(secret, null, 1234567890L));
        assertFalse(service.verifyAt(null, "123456", 1234567890L));
    }

    @Test
    void rejectsUnsupportedConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new TotpService("MD5", 6, 30, 1, 20));
        assertThrows(IllegalArgumentException.class, () -> new TotpService("SHA1", 3, 30, 1, 20));
        assertThrows(IllegalArgumentException.class, () -> new TotpService("SHA1", 6, 30, 1, 8));
    }
}
