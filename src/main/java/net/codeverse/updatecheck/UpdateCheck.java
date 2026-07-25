package net.codeverse.updatecheck;

import net.codeverse.updater.UpdateResult;
import net.codeverse.updater.Updater;
import net.codeverse.updater.UpdaterConfig;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Executor;

/**
 * Wires the update library into this plugin, so startup stays short.
 *
 * Reports each outcome the library distinguishes and stages nothing unless the
 * operator opted into auto apply. Auto apply defaults off for this plugin in
 * particular, and that is a security decision rather than caution: this is the
 * plugin that guards every account, so auto staging it would turn a
 * compromised release token into code that runs on the next restart. An
 * operator who accepts that tradeoff can turn it on in config.
 */
public final class UpdateCheck {

    private UpdateCheck() {
    }

    public static void run(String currentVersion,
                           Path updateFolder,
                           boolean autoApply,
                           Executor executor,
                           Logger logger) {
        Updater updater = new Updater(UpdaterConfig
                .forRepository("CodeVerseHub-Minecraft", "CodeverseAuth")
                .currentVersion(currentVersion)
                .updateFolder(updateFolder)
                .targetJarName("CodeverseAuth-" + currentVersion + ".jar")
                .autoApply(autoApply)
                .checkInterval(Duration.ofHours(6))
                .build());

        updater.checkAsync(executor, result -> {
            switch (result) {
                case UpdateResult.UpToDate ignored ->
                        logger.info("CodeverseAuth is up to date.");
                case UpdateResult.UpdateAvailable available ->
                        logger.info("CodeverseAuth {} is available (running {}). Auto apply is off, so "
                                        + "nothing was staged. Update from the release page when ready.",
                                available.release().tag(), currentVersion);
                case UpdateResult.Staged staged ->
                        logger.info("CodeverseAuth {} was downloaded, verified and staged. Restart to apply.",
                                staged.release().tag());
                case UpdateResult.Failed failed ->
                        logger.warn("Update check did not complete: {}", failed.reason());
            }
        });
    }
}
