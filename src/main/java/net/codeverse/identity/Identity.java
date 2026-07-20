package net.codeverse.identity;

import java.util.UUID;

/**
 * A player's resolved identity on the network.
 *
 * The internal id is the primary key in every table this network owns. The
 * Minecraft facing uuid is treated as an address, meaning where packets go,
 * rather than an identity, meaning who the player is. Keeping those separate
 * is what allows Java, Bedrock and cracked accounts to be unified later
 * without rewriting the in game uuid, which would break Floodgate and with
 * it Grim's Bedrock exemption.
 *
 * @param internalId  canonical network id, primary key for all owned data
 * @param minecraftId uuid the client connects with: real Mojang uuid for
 *                    premium, Floodgate uuid for Bedrock, deterministic
 *                    offline uuid of the prefixed name for cracked
 * @param username    in game name including any prefix
 * @param tier        trust tier governing permission eligibility
 * @param registeredAt epoch millis of first registration, 0 when never registered
 * @param lastLoginAt  epoch millis of last successful login, 0 when never
 * @param totpEnrolled whether a second factor is active on this account
 */
public record Identity(
        UUID internalId,
        UUID minecraftId,
        String username,
        TrustTier tier,
        long registeredAt,
        long lastLoginAt,
        boolean totpEnrolled
) {
    public Identity {
        if (internalId == null) {
            throw new IllegalArgumentException("internalId cannot be null");
        }
        if (minecraftId == null) {
            throw new IllegalArgumentException("minecraftId cannot be null");
        }
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username cannot be blank");
        }
        if (tier == null) {
            throw new IllegalArgumentException("tier cannot be null");
        }
    }

    public boolean isCracked() {
        return tier == TrustTier.CRACKED;
    }

    public boolean isVerifiedOrigin() {
        return tier.isVerifiedOrigin();
    }

    public boolean isRegistered() {
        return registeredAt > 0;
    }

    public Identity withTier(TrustTier newTier) {
        return new Identity(internalId, minecraftId, username, newTier, registeredAt, lastLoginAt, totpEnrolled);
    }

    public Identity withTotpEnrolled(boolean enrolled) {
        return new Identity(internalId, minecraftId, username, tier, registeredAt, lastLoginAt, enrolled);
    }
}
