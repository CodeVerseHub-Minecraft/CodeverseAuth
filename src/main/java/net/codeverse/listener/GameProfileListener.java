package net.codeverse.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.util.GameProfile;
import net.codeverse.config.PluginConfig;
import net.codeverse.identity.OfflineUuid;
import net.codeverse.api.identity.TrustTier;
import org.slf4j.Logger;

/**
 * Applies the cracked prefix and a deterministic offline uuid, and leaves
 * premium and Bedrock profiles untouched.
 *
 * The prefix becomes part of the real username the backends receive rather
 * than a display decoration. Combined with forced online mode for premium
 * names, that makes impersonation structurally impossible: Mojang cannot
 * issue a name containing the prefix character, so the cracked and premium
 * namespaces can never intersect.
 *
 * Bedrock profiles are rewritten by Floodgate before this runs. Rewriting
 * them again would break Floodgate's skin and api handling, and with it
 * Grim's Bedrock exemption, so they pass through.
 */
public final class GameProfileListener {

    private final PluginConfig config;
    private final Logger logger;

    public GameProfileListener(PluginConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
    }

    @Subscribe(priority = -500)
    public void onGameProfileRequest(GameProfileRequestEvent event) {
        GameProfile original = event.getGameProfile();
        if (tierOf(event) != TrustTier.CRACKED) {
            return;
        }

        String prefixed = config.naming.crackedPrefix + original.getName();
        event.setGameProfile(original.withName(prefixed).withId(OfflineUuid.of(prefixed)));
        logger.debug("Cracked profile rewritten: {} to {}", original.getName(), prefixed);
    }

    /**
     * Classifies a connection from the profile Velocity has assembled.
     * Shared with the login listener so both agree on the tier.
     */
    public TrustTier tierOf(GameProfileRequestEvent event) {
        String floodgatePrefix = config.naming.floodgatePrefix;
        if (floodgatePrefix != null && !floodgatePrefix.isEmpty()
                && event.getGameProfile().getName().startsWith(floodgatePrefix)) {
            return TrustTier.BEDROCK;
        }
        return event.isOnlineMode() ? TrustTier.PREMIUM : TrustTier.CRACKED;
    }
}
