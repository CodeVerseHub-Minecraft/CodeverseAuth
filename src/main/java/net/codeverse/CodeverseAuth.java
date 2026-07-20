package net.codeverse;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.LuckPermsProvider;
import net.codeverse.auth.AuthManager;
import net.codeverse.auth.MojangPremiumResolver;
import net.codeverse.auth.PremiumResolver;
import net.codeverse.cache.IdentityCache;
import net.codeverse.command.AuthCommands;
import net.codeverse.config.PluginConfig;
import net.codeverse.crypto.PasswordHasher;
import net.codeverse.crypto.SessionTokenCodec;
import net.codeverse.crypto.TotpService;
import net.codeverse.identity.IdentityService;
import net.codeverse.lang.LangManager;
import net.codeverse.listener.AuthGateListener;
import net.codeverse.listener.GameProfileListener;
import net.codeverse.listener.PreLoginListener;
import net.codeverse.listener.SessionCookieListener;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.Database;
import net.codeverse.storage.ThrottleRepository;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Plugin entry point.
 *
 * Startup is deliberately all or nothing. If config, storage or messages
 * cannot be loaded, no listeners are registered at all, which leaves the
 * proxy holding every player at its own online mode rather than running with
 * a half initialised authentication layer.
 */
@Plugin(
        id = "codeverse-auth",
        name = "Codeverse Auth",
        version = "1.0.0",
        description = "Identity, authentication and trust tiers for a cracked, Bedrock and Java network",
        authors = {"CodeVerseHub-Minecraft Subteam"}
)
public final class CodeverseAuth {

    private static final List<String> BUNDLED_LOCALES = List.of("en", "de");

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;

    private PluginConfig config;
    private LangManager lang;
    private Database database;
    private IdentityCache cache;
    private ExecutorService executor;
    private AuthCommands commands;
    private boolean started;

    @Inject
    public CodeverseAuth(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            config = PluginConfig.load(dataDirectory);
            lang = new LangManager(dataDirectory, config.language.defaultLocale,
                    config.language.usePlayerLocale, BUNDLED_LOCALES);

            database = new Database(config.storage);
            database.applySchema();

            cache = new IdentityCache(config.redis);
            executor = Executors.newVirtualThreadPerTaskExecutor();

            AccountRepository accounts = new AccountRepository(database);
            ThrottleRepository throttle = new ThrottleRepository(database);
            IdentityService identities = new IdentityService(accounts, cache);

            PasswordHasher hasher = new PasswordHasher(
                    config.security.argon2MemoryKib,
                    config.security.argon2Iterations,
                    config.security.argon2Parallelism);
            TotpService totp = new TotpService(
                    config.totp.algorithm,
                    config.totp.digits,
                    config.totp.periodSeconds,
                    config.totp.allowedDrift,
                    config.totp.secretBytes);
            SessionTokenCodec sessions = new SessionTokenCodec(config.session.secret);

            PremiumResolver resolver = new MojangPremiumResolver(
                    cache,
                    config.security.premiumLookupEndpoints,
                    Duration.ofMillis(config.security.premiumLookupTimeoutMillis),
                    executor);

            AuthManager auth = new AuthManager(config, accounts, throttle, identities, hasher, totp, sessions);

            GameProfileListener profiles = new GameProfileListener(config, logger);
            AuthGateListener gate = new AuthGateListener(proxy, config, auth, identities, profiles, lang, logger);

            proxy.getEventManager().register(this, new PreLoginListener(config, resolver, lang, logger));
            proxy.getEventManager().register(this, profiles);
            proxy.getEventManager().register(this, gate);
            proxy.getEventManager().register(this, new SessionCookieListener(config, auth, gate, lang, logger));

            registerPermissionSync(identities);

            commands = new AuthCommands(this, proxy, config, auth, gate, lang, executor, logger);
            commands.registerAll();

            proxy.getScheduler().buildTask(this, () -> auth.purgeExpiredThrottles())
                    .repeat(15, TimeUnit.MINUTES)
                    .schedule();

            started = true;
            logger.info("Authentication ready. Cracked prefix '{}', limbo '{}', locales {}",
                    config.naming.crackedPrefix, config.routing.limboServer, lang.availableLocales());

        } catch (Exception failure) {
            logger.error("Startup failed, no authentication listeners were registered. "
                    + "The proxy will fall back to its own online-mode setting, which means cracked "
                    + "players cannot join until this is fixed.", failure);
            shutdownResources();
        }
    }

    /**
     * LuckPerms is optional at load time so the plugin still starts on a
     * proxy that has not installed it yet, but trust tier enforcement only
     * exists when it is present, so its absence is logged loudly.
     */
    private void registerPermissionSync(IdentityService identities) {
        if (!config.permissions.enforceTrustTiers) {
            logger.warn("permissions.enforceTrustTiers is disabled. Cracked accounts will not be "
                    + "prevented from holding groups.");
            return;
        }
        try {
            LuckPerms luckPerms = LuckPermsProvider.get();
            proxy.getEventManager().register(this,
                    new net.codeverse.listener.PermissionSyncListener(
                            new net.codeverse.integration.LuckPermsTierSync(luckPerms, config, logger),
                            identities, config, logger));
            logger.info("LuckPerms trust tier enforcement active.");
        } catch (IllegalStateException notLoaded) {
            logger.error("LuckPerms is not installed. Trust tier enforcement is INACTIVE, which means "
                    + "nothing is stripping groups from cracked accounts. Install LuckPerms.");
        }
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        shutdownResources();
    }

    private void shutdownResources() {
        started = false;
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
        }
        if (cache != null) {
            cache.close();
        }
        if (database != null) {
            database.close();
        }
    }

    public boolean isStarted() {
        return started;
    }
}
