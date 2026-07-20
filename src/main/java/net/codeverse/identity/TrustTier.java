package net.codeverse.identity;

/**
 * How much the network trusts a connection's claimed identity.
 *
 * The founding rule of this network is that a cracked client must never
 * hold a permission, because a cracked client's username is asserted rather
 * than proven. That rule is expressed here and enforced in two independent
 * places: the LuckPerms group mapping in config, and the hard predicate
 * below which the permission sync consults before applying any group.
 *
 * Ordered from least to most trusted.
 */
public enum TrustTier {

    /**
     * Offline account whose username was not verified against Mojang. Wears
     * the configured cracked prefix and a deterministic offline UUID.
     * Cannot impersonate a premium name because premium names are forced
     * through Mojang authentication before reaching this state, and the
     * prefix uses a character Mojang cannot issue.
     */
    CRACKED,

    /**
     * Cracked account whose owner proved control of a Discord account in the
     * community. Still not a paid Minecraft account, but now tied to an
     * identity that can be held accountable. Unoccupied until the Discord
     * bridge exists; the tier is defined now so the permission tracks and
     * database schema do not need migrating later.
     */
    DISCORD_LINKED,

    /**
     * Bedrock player through Geyser and Floodgate, authenticated by
     * Microsoft during the Bedrock login flow. A cryptographically verified
     * origin, so treated as trusted. Wears Floodgate's prefix, not ours.
     */
    BEDROCK,

    /**
     * Paid Java account verified against Mojang's session servers through
     * forced online mode. The username is proven. No prefix.
     */
    PREMIUM;

    /**
     * Whether this tier may hold any group above the network baseline.
     *
     * Consulted by the permission sync as a backstop independent of config,
     * so that a mistyped group name in config.json still cannot hand a
     * cracked connection elevated access.
     */
    public boolean eligibleForElevatedPermissions() {
        return this != CRACKED;
    }

    /** Whether the account's origin was cryptographically proven. */
    public boolean isVerifiedOrigin() {
        return this == PREMIUM || this == BEDROCK;
    }

    /** Whether the tier authenticates with a password stored by this plugin. */
    public boolean requiresPassword() {
        return this == CRACKED || this == DISCORD_LINKED;
    }
}
