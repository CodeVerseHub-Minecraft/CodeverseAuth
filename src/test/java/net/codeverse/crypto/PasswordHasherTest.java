package net.codeverse.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherTest {

    private static final int FAST_MEMORY = 8192;

    @Test
    void producesPhcFormattedHashes() {
        String hash = new PasswordHasher(FAST_MEMORY, 1, 1).hash("password".toCharArray());
        assertTrue(hash.startsWith("$argon2id$v=19$m=" + FAST_MEMORY + ",t=1,p=1$"));
    }

    @Test
    void verifiesCorrectPasswordAndRejectsWrongOne() {
        PasswordHasher hasher = new PasswordHasher(FAST_MEMORY, 1, 1);
        String hash = hasher.hash("correct horse".toCharArray());
        assertTrue(hasher.verify("correct horse".toCharArray(), hash));
        assertFalse(hasher.verify("wrong horse".toCharArray(), hash));
    }

    @Test
    void saltsEveryHashIndependently() {
        PasswordHasher hasher = new PasswordHasher(FAST_MEMORY, 1, 1);
        assertNotEquals(hasher.hash("same".toCharArray()), hasher.hash("same".toCharArray()));
    }

    @Test
    void treatsCorruptStoredHashAsNonMatchingRatherThanThrowing() {
        PasswordHasher hasher = new PasswordHasher(FAST_MEMORY, 1, 1);
        assertFalse(hasher.verify("x".toCharArray(), "$argon2id$garbage"));
        assertFalse(hasher.verify("x".toCharArray(), ""));
        assertFalse(hasher.verify("x".toCharArray(), null));
    }

    @Test
    void raisingCostParametersKeepsOldHashesValidButFlagsThemForRehash() {
        PasswordHasher weak = new PasswordHasher(FAST_MEMORY, 1, 1);
        PasswordHasher strong = new PasswordHasher(FAST_MEMORY * 2, 2, 2);
        String stored = weak.hash("secret".toCharArray());

        assertFalse(weak.needsRehash(stored));
        assertTrue(strong.needsRehash(stored));
        assertTrue(strong.verify("secret".toCharArray(), stored));
    }

    @Test
    void refusesDangerouslyWeakParameters() {
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasher(1024, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasher(FAST_MEMORY, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasher(FAST_MEMORY, 1, 0));
    }
}
