package net.codeverse.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;

/**
 * TOTP (RFC 6238) built on the JDK's HMAC primitives.
 *
 * This implements a fully specified IETF standard on top of the platform's
 * audited HMAC rather than inventing any cryptography. It is verified in the
 * test suite against the official RFC 6238 Appendix B vectors for SHA1,
 * SHA256 and SHA512.
 *
 * A dedicated library was considered and rejected: the widely used Java TOTP
 * wrappers are unmaintained and drag in a QR image dependency this plugin
 * does not need, since authenticator enrolment uses an otpauth:// URI that
 * the player's app scans or accepts as text.
 */
public final class TotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String algorithm;
    private final int digits;
    private final int periodSeconds;
    private final int allowedDrift;
    private final int secretBytes;

    /**
     * @param algorithm     HMAC algorithm: SHA1, SHA256 or SHA512
     * @param digits        code length, conventionally 6
     * @param periodSeconds time step, conventionally 30
     * @param allowedDrift  how many steps either side of now to accept,
     *                      tolerating clock skew on the player's device
     * @param secretBytes   generated shared-secret length in bytes
     */
    public TotpService(String algorithm, int digits, int periodSeconds, int allowedDrift, int secretBytes) {
        String normalised = algorithm == null ? "SHA1" : algorithm.toUpperCase(Locale.ROOT).replace("-", "");
        if (!normalised.equals("SHA1") && !normalised.equals("SHA256") && !normalised.equals("SHA512")) {
            throw new IllegalArgumentException("unsupported totp algorithm: " + algorithm);
        }
        if (digits < 6 || digits > 9) {
            throw new IllegalArgumentException("totp digits must be between 6 and 9, got " + digits);
        }
        if (periodSeconds < 1) {
            throw new IllegalArgumentException("totp period must be positive, got " + periodSeconds);
        }
        if (allowedDrift < 0) {
            throw new IllegalArgumentException("totp drift cannot be negative, got " + allowedDrift);
        }
        if (secretBytes < 16) {
            throw new IllegalArgumentException("totp secret must be at least 16 bytes, got " + secretBytes);
        }
        this.algorithm = normalised;
        this.digits = digits;
        this.periodSeconds = periodSeconds;
        this.allowedDrift = allowedDrift;
        this.secretBytes = secretBytes;
    }

    /** Generates a new Base32 shared secret for enrolment. */
    public String generateSecret() {
        byte[] buffer = new byte[secretBytes];
        RANDOM.nextBytes(buffer);
        return base32Encode(buffer);
    }

    /**
     * Builds the otpauth:// URI an authenticator app consumes. Label and
     * issuer are percent-encoded because network names may contain spaces.
     */
    public String provisioningUri(String issuer, String accountName, String base32Secret) {
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(accountName);
        return "otpauth://totp/" + encodedIssuer + ":" + encodedAccount
                + "?secret=" + base32Secret
                + "&issuer=" + encodedIssuer
                + "&algorithm=" + algorithm
                + "&digits=" + digits
                + "&period=" + periodSeconds;
    }

    /** Verifies a submitted code against the current time window plus drift. */
    public boolean verify(String base32Secret, String submittedCode) {
        return verifyAt(base32Secret, submittedCode, Instant.now().getEpochSecond());
    }

    /** Verification at an explicit epoch second, used by the test suite. */
    public boolean verifyAt(String base32Secret, String submittedCode, long epochSeconds) {
        if (base32Secret == null || submittedCode == null) {
            return false;
        }
        String cleaned = submittedCode.trim().replace(" ", "");
        if (cleaned.length() != digits) {
            return false;
        }
        byte[] key;
        try {
            key = base32Decode(base32Secret);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        long counter = Math.floorDiv(epochSeconds, periodSeconds);
        byte[] submitted = cleaned.getBytes(StandardCharsets.US_ASCII);
        boolean match = false;
        for (int offset = -allowedDrift; offset <= allowedDrift; offset++) {
            String candidate = generate(key, counter + offset);
            // Compared without early exit across the whole drift window so
            // timing does not reveal which window matched.
            if (MessageDigest.isEqual(candidate.getBytes(StandardCharsets.US_ASCII), submitted)) {
                match = true;
            }
        }
        return match;
    }

    /** Generates the code for an explicit counter value. */
    public String generate(byte[] key, long counter) {
        byte[] counterBytes = new byte[8];
        long value = counter;
        for (int i = 7; i >= 0; i--) {
            counterBytes[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        byte[] digest;
        try {
            Mac mac = Mac.getInstance("Hmac" + algorithm);
            mac.init(new SecretKeySpec(key, "Hmac" + algorithm));
            digest = mac.doFinal(counterBytes);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HMAC unavailable for " + algorithm, failure);
        }
        int offset = digest[digest.length - 1] & 0x0F;
        int binary = ((digest[offset] & 0x7F) << 24)
                | ((digest[offset + 1] & 0xFF) << 16)
                | ((digest[offset + 2] & 0xFF) << 8)
                | (digest[offset + 3] & 0xFF);
        int modulo = (int) Math.pow(10, digits);
        return String.format(Locale.ROOT, "%0" + digits + "d", binary % modulo);
    }

    public static String base32Encode(byte[] data) {
        StringBuilder out = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                out.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            out.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return out.toString();
    }

    public static byte[] base32Decode(String encoded) {
        String cleaned = encoded.trim().replace("=", "").replace(" ", "").toUpperCase(Locale.ROOT);
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("empty base32 secret");
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < cleaned.length(); i++) {
            int index = BASE32_ALPHABET.indexOf(cleaned.charAt(i));
            if (index < 0) {
                throw new IllegalArgumentException("invalid base32 character at position " + i);
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
