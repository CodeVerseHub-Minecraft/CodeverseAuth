package net.codeverse.integration;

import net.codeverse.config.PluginConfig;
import org.slf4j.Logger;

import java.util.Optional;

/**
 * The only place in the plugin that reaches for LuckPerms.
 *
 * Isolated into its own class so that loading it is a decision the caller
 * makes rather than a side effect of loading the plugin. Once this class is
 * touched on a proxy without LuckPerms installed it will fail to link, so
 * {@link #load} is called only after the plugin has been confirmed present
 * by name, and it still catches LinkageError for the case where the plugin
 * is installed but its API is not on the class path.
 */
public final class LuckPermsHooks {

    private LuckPermsHooks() {
    }

    public static Optional<PermissionHooks> load(PluginConfig config, Logger logger) {
        try {
            return Optional.of(new LuckPermsTierSync(
                    net.luckperms.api.LuckPermsProvider.get(), config, logger));
        } catch (IllegalStateException notLoadedYet) {
            logger.error("LuckPerms is installed but has not finished loading, so trust tier "
                    + "enforcement is INACTIVE for this session. Restart the proxy.");
            return Optional.empty();
        } catch (LinkageError missingApi) {
            // Reachable when the plugin is present by name but its API classes
            // are not, which a partial or mismatched install produces.
            logger.error("The LuckPerms API could not be loaded, so trust tier enforcement is "
                    + "INACTIVE. Nothing is stripping groups from cracked accounts.", missingApi);
            return Optional.empty();
        }
    }
}
