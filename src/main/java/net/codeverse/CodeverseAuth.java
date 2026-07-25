package net.codeverse;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
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
import net.codeverse.listener.PermissionSyncListener;
import net.codeverse.listener.PreLoginListener;
import net.codeverse.listener.SessionCookieListener;
import net.codeverse.api.CodeverseApiProvider;
import net.codeverse.apiimpl.AuthEventBus;
import net.codeverse.apiimpl.AuthIdentityService;
import net.codeverse.apiimpl.AuthLinkService;
import net.codeverse.apiimpl.CodeverseApiImpl;
import net.codeverse.command.LinkCommands;
import net.codeverse.integration.LuckPermsHooks;
import net.codeverse.updatecheck.UpdateCheck;
import net.codeverse.integration.PermissionHooks;
import net.codeverse.http.ApiAuthenticator;
import net.codeverse.http.HttpApiServer;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.Database;
import net.codeverse.storage.LinkCodeRepository;
import net.codeverse.storage.ThrottleRepository;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
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
        version = "0.2.0",
        description = "Identity, authentication and trust tiers for a cracked, Bedrock and Java network",
        authors = {"CodeVerseHub-Minecraft Subteam"}
)
public final class CodeverseAuth {

    private static final List<String> BUNDLED_LOCALES = List.of("en", "de");
    private static final String LUCKPERMS_PLUGIN_ID = "luckperms";
    private static final String PLUGIN_ID = "codeverse-auth";

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;

    private PluginConfig config;
    private LangManager lang;
    private Database database;
    private IdentityCache cache;
    private ExecutorService executor;
    private AuthCommands commands;
    private LinkCommands linkCommands;
    private HttpApiServer httpApi;
    private CodeverseApiImpl api;
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
            LinkCodeRepository linkCodes = new LinkCodeRepository(database);
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

            AuthEventBus eventBus = new AuthEventBus(logger);
            AuthIdentityService apiIdentities = new AuthIdentityService(accounts, cache, executor);
            AuthLinkService apiLinks = new AuthLinkService(
                    accounts, linkCodes, cache, eventBus, executor, config.http.linkCodeLength);

            // Registered before commands and the HTTP interface so nothing
            // that depends on the API can observe it missing, and before the
            // proxy finishes initialising so plugins loading after this one
            // find it already present.
            api = new CodeverseApiImpl(apiIdentities, apiLinks, eventBus);
            CodeverseApiProvider.register(api);

            commands = new AuthCommands(this, proxy, config, auth, gate, lang, executor, logger);
            commands.registerAll();

            linkCommands = new LinkCommands(this, proxy, config, auth, apiLinks, lang, logger);
            linkCommands.registerAll();

            startHttpInterface(apiIdentities, apiLinks);

            proxy.getScheduler().buildTask(this, () -> apiLinks.purgeExpiredCodes())
                    .repeat(10, TimeUnit.MINUTES)
                    .schedule();

            proxy.getScheduler().buildTask(this, () -> auth.purgeExpiredThrottles())
                    .repeat(15, TimeUnit.MINUTES)
                    .schedule();

            if (config.updates.checkOnStartup) {
                // The running version is read from the proxy rather than held
                // in a constant here. A constant would be a third place the
                // version lives, and the one that decides both what counts as
                // newer and what the staged jar is named, so forgetting it
                // would have this plugin stage the version it is already
                // running.
                String runningVersion = proxy.getPluginManager().getPlugin(PLUGIN_ID)
                        .flatMap(container -> container.getDescription().getVersion())
                        .orElse(null);
                if (runningVersion == null) {
                    logger.warn("The proxy did not report this plugin's version, so update checks "
                            + "are disabled for this session.");
                } else {
                    // Repeats rather than running once: a proxy that stays up
                    // for a fortnight would otherwise never learn about a
                    // release published an hour after it booted. Runs on a
                    // scheduler thread because it makes a network request. The
                    // update folder sits beside the plugins directory, which is
                    // where a replacement jar is picked up on the next boot.
                    Path updateFolder = dataDirectory.getParent().resolve("update");
                    proxy.getScheduler().buildTask(this, () -> UpdateCheck.run(
                                    runningVersion, updateFolder, config.updates.autoApply,
                                    config.updates.checkIntervalHours, Runnable::run, logger))
                            .repeat(config.updates.checkIntervalHours, TimeUnit.HOURS)
                            .schedule();
                }
            }

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
     * Starts the external interface, or explains why it did not.
     *
     * A failure to bind is logged and swallowed rather than aborting startup.
     * The interface exists so a Discord bot can reach the network; the
     * network working without its bot is a degraded state, while a proxy
     * refusing to start because a port was taken is an outage.
     */
    private void startHttpInterface(AuthIdentityService identities, AuthLinkService links) {
        if (!config.http.enabled) {
            return;
        }
        try {
            httpApi = new HttpApiServer(config.http, new ApiAuthenticator(config.http),
                    identities, links, dataDirectory, logger);
            httpApi.start();
        } catch (Exception failure) {
            httpApi = null;
            logger.error("The HTTP interface could not start. Authentication is unaffected, but the "
                    + "Discord bot cannot reach this proxy until it is fixed.", failure);
        }
    }

    /**
     * Wires trust tier enforcement, when a permission plugin is there to
     * enforce it with.
     *
     * The plugin is looked up by name before anything that references the
     * LuckPerms API is loaded. Calling LuckPermsProvider directly and
     * catching the failure does not work: the class naming it fails to link
     * on a proxy without LuckPerms, and the resulting NoClassDefFoundError
     * is an Error rather than an Exception, so it escapes the catch, aborts
     * ProxyInitializeEvent and leaves the proxy with no authentication
     * listeners registered at all.
     */
    private void registerPermissionSync(IdentityService identities) {
        if (!config.permissions.enforceTrustTiers) {
            logger.warn("permissions.enforceTrustTiers is disabled. Cracked accounts will not be "
                    + "prevented from holding groups.");
            return;
        }
        if (proxy.getPluginManager().getPlugin(LUCKPERMS_PLUGIN_ID).isEmpty()) {
            logger.error("LuckPerms is not installed. Trust tier enforcement is INACTIVE, which means "
                    + "nothing is stripping groups from cracked accounts. Install LuckPerms.");
            return;
        }
        Optional<PermissionHooks> hooks = LuckPermsHooks.load(config, logger);
        if (hooks.isEmpty()) {
            return;
        }
        proxy.getEventManager().register(this,
                new PermissionSyncListener(hooks.get(), identities, config, logger));
        logger.info("LuckPerms trust tier enforcement active.");
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        shutdownResources();
    }

    private void shutdownResources() {
        started = false;
        if (api != null) {
            CodeverseApiProvider.unregister(api);
            api = null;
        }
        if (httpApi != null) {
            httpApi.stop();
            httpApi = null;
        }
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
