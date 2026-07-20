package net.codeverse.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent.PreLoginComponentResult;
import net.codeverse.auth.PremiumResolver;
import net.codeverse.auth.PremiumResolver.PremiumStatus;
import net.codeverse.config.PluginConfig;
import net.codeverse.lang.LangManager;
import org.slf4j.Logger;

import java.util.concurrent.TimeUnit;

/**
 * Decides, per connection, whether Mojang should authenticate it.
 *
 * This is the most security critical class in the network. It calls exactly
 * one of forceOnlineMode, forceOfflineMode or denied.
 *
 * Fail closed contract: every failure path, whether the resolver throws,
 * times out, or returns an undetermined result, ends in forceOnlineMode.
 * Offline mode is granted only on positive evidence that a name is not a
 * paid account. The consequence of getting this backwards is that every
 * username on the network becomes spoofable silently, with nothing in the
 * log to show for it, so the asymmetry is deliberate and must not be
 * relaxed to let cracked players in during an outage.
 *
 * Bedrock never reaches here as a normal login: Floodgate intercepts those
 * connections first.
 */
public final class PreLoginListener {

    private final PluginConfig config;
    private final PremiumResolver resolver;
    private final LangManager lang;
    private final Logger logger;

    public PreLoginListener(PluginConfig config, PremiumResolver resolver, LangManager lang, Logger logger) {
        this.config = config;
        this.resolver = resolver;
        this.lang = lang;
        this.logger = logger;
    }

    @Subscribe(priority = 500)
    public EventTask onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();

        if (!isPlausibleUsername(username)) {
            event.setResult(PreLoginComponentResult.denied(lang.get("login.invalid-username")));
            return null;
        }

        return EventTask.resumeWhenComplete(
                resolver.resolve(username)
                        .orTimeout(config.security.premiumLookupTimeoutMillis, TimeUnit.MILLISECONDS)
                        .whenComplete((status, error) -> apply(event, username, status, error)));
    }

    private void apply(PreLoginEvent event, String username, PremiumStatus status, Throwable error) {
        if (error != null) {
            logger.warn("Premium lookup failed for '{}', failing closed to online mode: {}",
                    username, error.toString());
            event.setResult(PreLoginComponentResult.forceOnlineMode());
            return;
        }

        switch (status) {
            case PREMIUM -> event.setResult(PreLoginComponentResult.forceOnlineMode());
            case CRACKED -> {
                if (username.length() > config.naming.maximumCrackedNameLength) {
                    event.setResult(PreLoginComponentResult.denied(lang.get("login.name-too-long",
                            "max", String.valueOf(config.naming.maximumCrackedNameLength),
                            "prefix", config.naming.crackedPrefix)));
                    return;
                }
                event.setResult(PreLoginComponentResult.forceOfflineMode());
            }
            case UNKNOWN -> {
                logger.warn("Premium status undetermined for '{}', failing closed to online mode", username);
                event.setResult(PreLoginComponentResult.forceOnlineMode());
            }
        }
    }

    /** Mojang's legal character set, checked before any lookup is attempted. */
    private static boolean isPlausibleUsername(String name) {
        if (name == null) {
            return false;
        }
        int length = name.length();
        if (length < 1 || length > 16) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            char character = name.charAt(i);
            boolean legal = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '_';
            if (!legal) {
                return false;
            }
        }
        return true;
    }
}
