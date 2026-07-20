package net.codeverse.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Argon2id password hashing backed by BouncyCastle.
 *
 * Hashes are stored in the standard PHC string format
 * ($argon2id$v=19$m=,t=,p=$salt$hash) so they remain portable if this
 * plugin is ever replaced by another implementation.
 *
 * Cost parameters come from config and can be raised without recompiling.
 * Verification reads parameters back out of the stored hash, so raising the
 * config never invalidates existing passwords; needsRehash reports when an
 * account should be transparently upgraded on its next successful login.
 */
public final class PasswordHasher {

    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int MINIMUM_MEMORY_KIB = 8192;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final int memoryKib;
    private final int iterations;
    private final int parallelism;

    public PasswordHasher(int memoryKib, int iterations, int parallelism) {
        if (memoryKib < MINIMUM_MEMORY_KIB) {
            throw new IllegalArgumentException(
                    "argon2 memory must be at least " + MINIMUM_MEMORY_KIB + " KiB, got " + memoryKib);
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("argon2 iterations must be at least 1, got " + iterations);
        }
        if (parallelism < 1) {
            throw new IllegalArgumentException("argon2 parallelism must be at least 1, got " + parallelism);
        }
        this.memoryKib = memoryKib;
        this.iterations = iterations;
        this.parallelism = parallelism;
    }

    public String hash(char[] password) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, memoryKib, iterations, parallelism);
        try {
            return "$argon2id$v=19$m=" + memoryKib + ",t=" + iterations + ",p=" + parallelism
                    + "$" + ENCODER.encodeToString(salt)
                    + "$" + ENCODER.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * Constant-time comparison. A malformed stored hash returns false rather
     * than throwing, so a corrupted row cannot be used to distinguish
     * accounts by observing error behaviour.
     */
    public boolean verify(char[] password, String encoded) {
        Parsed parsed = parse(encoded);
        if (parsed == null) {
            return false;
        }
        byte[] actual = derive(password, parsed.salt(), parsed.memoryKib(), parsed.iterations(), parsed.parallelism());
        try {
            return MessageDigest.isEqual(parsed.hash(), actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    /** True when the stored hash uses weaker parameters than the current config. */
    public boolean needsRehash(String encoded) {
        Parsed parsed = parse(encoded);
        if (parsed == null) {
            return true;
        }
        return parsed.memoryKib() < memoryKib
                || parsed.iterations() < iterations
                || parsed.parallelism() < parallelism;
    }

    private static Parsed parse(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return null;
        }
        String[] parts = encoded.split("\\$");
        if (parts.length != 6 || !"argon2id".equals(parts[1])) {
            return null;
        }
        try {
            String[] params = parts[3].split(",");
            if (params.length != 3) {
                return null;
            }
            int memory = Integer.parseInt(params[0].substring(2));
            int iterations = Integer.parseInt(params[1].substring(2));
            int parallelism = Integer.parseInt(params[2].substring(2));
            byte[] salt = DECODER.decode(parts[4]);
            byte[] hash = DECODER.decode(parts[5]);
            return new Parsed(memory, iterations, parallelism, salt, hash);
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int memoryKib, int iterations, int parallelism) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryKib)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] out = new byte[HASH_LENGTH];
        byte[] passwordBytes = toBytes(password);
        try {
            generator.generateBytes(passwordBytes, out);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
        return out;
    }

    private static byte[] toBytes(char[] chars) {
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[buffer.remaining()];
        buffer.get(out);
        return out;
    }

    private record Parsed(int memoryKib, int iterations, int parallelism, byte[] salt, byte[] hash) {
    }
}
