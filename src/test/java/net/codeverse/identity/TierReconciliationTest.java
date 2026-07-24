package net.codeverse.identity;

import net.codeverse.api.identity.TrustTier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * What a login is allowed to take from the database and what it must not.
 */
class TierReconciliationTest {

    /**
     * The bug this prevents is quiet and total: a linked player logs in,
     * the connection says CRACKED because a cracked connection is all it can
     * say, and the promotion the whole linking flow exists to grant is
     * written back over on every single login.
     */
    @Test
    @DisplayName("a discord link survives a cracked reconnection")
    void linkSurvivesRelogin() {
        assertEquals(TrustTier.DISCORD_LINKED,
                IdentityService.reconcileTier(TrustTier.CRACKED, TrustTier.DISCORD_LINKED));
    }

    /**
     * The opposite direction must not hold. PREMIUM and BEDROCK are claims
     * the connection proved, so a stale row must never be able to grant a
     * verification that did not happen on this connection.
     */
    @Test
    @DisplayName("a stored tier never grants a verification the connection did not prove")
    void storedTierCannotGrantVerification() {
        assertEquals(TrustTier.CRACKED,
                IdentityService.reconcileTier(TrustTier.CRACKED, TrustTier.PREMIUM),
                "an account that used to be premium connects as cracked until Mojang says otherwise");
        assertEquals(TrustTier.CRACKED,
                IdentityService.reconcileTier(TrustTier.CRACKED, TrustTier.BEDROCK));
    }

    @Test
    @DisplayName("a proven connection wins over anything stored")
    void provenConnectionWins() {
        assertEquals(TrustTier.PREMIUM,
                IdentityService.reconcileTier(TrustTier.PREMIUM, TrustTier.DISCORD_LINKED));
        assertEquals(TrustTier.PREMIUM,
                IdentityService.reconcileTier(TrustTier.PREMIUM, TrustTier.CRACKED));
        assertEquals(TrustTier.BEDROCK,
                IdentityService.reconcileTier(TrustTier.BEDROCK, TrustTier.DISCORD_LINKED));
    }
}
