package net.codeverse.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.ServerPostConnectEvent;
import com.velocitypowered.api.proxy.Player;
import net.codeverse.config.PluginConfig;
import net.codeverse.identity.Identity;
import net.codeverse.identity.IdentityService;
import net.codeverse.identity.TrustTier;
import net.codeverse.integration.LuckPermsTierSync;
import org.slf4j.Logger;

import java.sql.SQLException;

/**
 * Applies trust tier groups once a player has authenticated and landed on a
 * real backend.
 *
 * Deliberately not run at login. LuckPerms loads a user asynchronously and
 * writing groups while the player is still moving between servers races with
 * its own user load, producing intermittently missing permissions. Waiting
 * until the first post connect event costs nothing and removes the race.
 */
public final class PermissionSyncListener {

    private final LuckPermsTierSync sync;
    private final IdentityService identities;
    private final PluginConfig config;
    private final Logger logger;

    public PermissionSyncListener(LuckPermsTierSync sync,
                                  IdentityService identities,
                                  PluginConfig config,
                                  Logger logger) {
        this.sync = sync;
        this.identities = identities;
        this.config = config;
        this.logger = logger;
    }

    @Subscribe(priority = -500)
    public void onServerPostConnect(ServerPostConnectEvent event) {
        Player player = event.getPlayer();
        if (event.getPreviousServer() != null) {
            return;
        }
        TrustTier tier = tierOf(player);
        try {
            Identity identity = identities.resolve(player.getUniqueId(), player.getUsername(), tier);
            sync.apply(identity);
        } catch (SQLException failure) {
            logger.error("Could not sync permissions for {}", player.getUsername(), failure);
        }
    }

    private TrustTier tierOf(Player player) {
        String floodgatePrefix = config.naming.floodgatePrefix;
        if (floodgatePrefix != null && !floodgatePrefix.isEmpty()
                && player.getUsername().startsWith(floodgatePrefix)) {
            return TrustTier.BEDROCK;
        }
        if (player.getUsername().startsWith(config.naming.crackedPrefix)) {
            return TrustTier.CRACKED;
        }
        return TrustTier.PREMIUM;
    }
}
