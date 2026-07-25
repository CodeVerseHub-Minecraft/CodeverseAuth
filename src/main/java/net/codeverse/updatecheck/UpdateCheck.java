package net.codeverse.updatecheck;

import net.codeverse.updater.UpdateResult;
import net.codeverse.updater.Updater;
import net.codeverse.updater.UpdaterConfig;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Executor;

/**
 * Reports whether a newer release exists. It never stages one, and that is a
 * property of the platform rather than a policy choice.
 *
 * Velocity has no update folder. Paper watches plugins/update and swaps a jar
 * in on the next boot; the proxy has no equivalent, and a jar left in such a
 * folder is ignored forever. Staging here would therefore log that an update
 * was applied when nothing had been, which is worse than not offering it: an
 * operator who believes the update is handled stops checking. So this reports
 * the release and points at it, and replacing the jar stays a deliberate act.
 */
public final class UpdateCheck {

    private UpdateCheck() {
    }

    public static void run(String currentVersion,
                           Path dataDirectory,
                           boolean autoApplyRequested,
                           int checkIntervalHours,
                           Executor executor,
                           Logger logger) {
        if (autoApplyRequested) {
            logger.warn("updates.autoApply is enabled, but Velocity has no update folder, so a staged "
                    + "jar would never be applied. Updates will be reported only. Replace the jar in "
                    + "plugins and restart to update.");
        }

        Updater updater = new Updater(UpdaterConfig
                .forRepository("CodeVerseHub-Minecraft", "CodeverseAuth")
                .currentVersion(currentVersion)
                // Never true here, whatever config asks for, because this
                // platform cannot apply what would be staged.
                .autoApply(false)
                // Required by the builder but unused, since nothing is ever
                // downloaded. Pointing it at the plugin's own directory keeps
                // it from implying a staging location that does not work.
                .updateFolder(dataDirectory)
                .targetJarName("CodeverseAuth-" + currentVersion + ".jar")
                .checkInterval(Duration.ofHours(checkIntervalHours))
                .build());

        updater.checkAsync(executor, result -> {
            switch (result) {
                case UpdateResult.UpToDate ignored ->
                        logger.info("CodeverseAuth is up to date.");
                case UpdateResult.UpdateAvailable available ->
                        logger.info("CodeverseAuth {} is available (running {}). Download it from "
                                        + "https://github.com/CodeVerseHub-Minecraft/CodeverseAuth/releases "
                                        + "and replace the jar in plugins, then restart.",
                                available.release().tag(), currentVersion);
                case UpdateResult.Staged staged ->
                        logger.info("CodeverseAuth {} was staged at {}.",
                                staged.release().tag(), staged.stagedAt());
                case UpdateResult.Failed failed ->
                        logger.warn("Update check did not complete: {}", failed.reason());
            }
        });
    }
}
