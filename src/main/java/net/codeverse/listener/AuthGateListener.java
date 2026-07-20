package net.codeverse.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.key.Key;
import net.codeverse.auth.AuthManager;
import net.codeverse.auth.AuthState;
import net.codeverse.config.PluginConfig;
import net.codeverse.identity.Identity;
import net.codeverse.identity.IdentityService;
import net.codeverse.identity.TrustTier;
import net.codeverse.lang.LangManager;
import org.slf4j.Logger;

import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Holds unauthenticated players in limbo and releases them once auth
 * completes.
 *
 * Everything an unauthenticated player could do is blocked here rather than
 * relying on backend plugins, because an unauthenticated connection should
 * never reach a backend at all. Chat is suppressed so passwords typed into
 * the wrong box are not broadcast, and commands are restricted to the small
 * allowlist needed to authenticate.
 */
public final class AuthGateListener {

    private final ProxyServer proxy;
    private final PluginConfig config;
    private final AuthManager auth;
    private final IdentityService identities;
    private final GameProfileListener profiles;
    private final LangManager lang;
    private final Logger logger;
    private final Key sessionCookieKey;

    private static final Set<String> ALLOWED_WHILE_UNAUTHENTICATED =
            Set.of("login", "l", "register", "reg", "2fa", "totp", "help");

    public AuthGateListener(ProxyServer proxy,
                            PluginConfig config,
                            AuthManager auth,
                            IdentityService identities,
                            GameProfileListener profiles,
                            LangManager lang,
                            Logger logger) {
        this.proxy = proxy;
        this.config = config;
        this.auth = auth;
        this.identities = identities;
        this.profiles = profiles;
        this.lang = lang;
        this.logger = logger;
        this.sessionCookieKey = Key.key(config.session.cookieKey);
    }

    /**
     * Establishes auth state as soon as the player exists. Verified origins
     * are marked authenticated immediately since Microsoft or Mojang already
     * proved who they are.
     */
    @Subscribe(priority = 500)
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        String address = player.getRemoteAddress().getAddress().getHostAddress();
        TrustTier tier = tierOf(player);

        try {
            Identity identity = identities.resolve(player.getUniqueId(), player.getUsername(), tier);
            AuthState.Stage stage;
            if (!auth.requiresAuthentication(tier)) {
                stage = AuthState.Stage.AUTHENTICATED;
            } else if (identity.isRegistered()) {
                stage = AuthState.Stage.AWAITING_PASSWORD;
            } else {
                stage = AuthState.Stage.AWAITING_REGISTRATION;
            }
            AuthState state = new AuthState(identity, address, stage);
            auth.beginSession(state);

            if (stage == AuthState.Stage.AUTHENTICATED) {
                return;
            }

            // Ask the client for a stored session cookie. The reply arrives
            // asynchronously and is handled in SessionCookieListener.
            if (config.session.enabled) {
                player.requestCookie(sessionCookieKey);
            }

            player.sendMessage(stage == AuthState.Stage.AWAITING_REGISTRATION
                    ? lang.get("auth.prompt-register", player.getEffectiveLocale())
                    : lang.get("auth.prompt-login", player.getEffectiveLocale()));

        } catch (SQLException failure) {
            // Identity storage is unavailable. Refusing the connection is the
            // only safe option, because letting the player through would mean
            // running without knowing who they are.
            logger.error("Identity resolution failed for {}, disconnecting", player.getUsername(), failure);
            player.disconnect(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
        }
    }

    /** Unauthenticated players start in limbo, never a real backend. */
    @Subscribe(priority = 500)
    public void onChooseInitialServer(PlayerChooseInitialServerEvent event) {
        Player player = event.getPlayer();
        Optional<RegisteredServer> limbo = proxy.getServer(config.routing.limboServer);

        if (auth.isAuthenticated(player.getUniqueId())) {
            // Falls back to limbo rather than passing null, which would leave
            // Velocity to pick a server itself and could place a player on a
            // backend this plugin never intended to route them to.
            Optional<RegisteredServer> destination = firstAvailablePostAuthServer().or(() -> limbo);
            if (destination.isEmpty()) {
                player.disconnect(lang.get("error.no-server-available", player.getEffectiveLocale()));
                return;
            }
            event.setInitialServer(destination.get());
            return;
        }

        if (limbo.isEmpty()) {
            logger.error("Limbo server '{}' is not defined in velocity.toml, refusing the connection",
                    config.routing.limboServer);
            player.disconnect(lang.get("error.no-server-available", player.getEffectiveLocale()));
            return;
        }
        event.setInitialServer(limbo.get());
    }

    /**
     * Blocks server switching while unauthenticated. Without this, a plugin
     * message or a forced host could move a player past the gate.
     */
    @Subscribe(priority = 500)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        Player player = event.getPlayer();
        if (auth.isAuthenticated(player.getUniqueId())) {
            return;
        }
        Optional<RegisteredServer> limbo = proxy.getServer(config.routing.limboServer);
        if (limbo.isEmpty()) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return;
        }
        RegisteredServer target = event.getOriginalServer();
        if (!target.getServerInfo().getName().equalsIgnoreCase(config.routing.limboServer)) {
            event.setResult(ServerPreConnectEvent.ServerResult.allowed(limbo.get()));
        }
    }

    /**
     * Chat from unauthenticated players is warned about but deliberately not
     * cancelled.
     *
     * Denying PlayerChatEvent disconnects clients on 1.19.1 and newer,
     * because signed chat cannot be silently dropped. Cancelling here would
     * turn a mistyped password into a kick, which is worse than the problem
     * it solves. Confidentiality is instead provided structurally: an
     * unauthenticated player is confined to the limbo server, which does not
     * relay chat to anyone, and cannot reach a backend that would.
     */
    @Subscribe(priority = 1000)
    public void onChat(PlayerChatEvent event) {
        Player player = event.getPlayer();
        if (auth.isAuthenticated(player.getUniqueId())) {
            return;
        }
        player.sendMessage(lang.get("auth.chat-blocked", player.getEffectiveLocale()));
    }

    @Subscribe(priority = 1000)
    public void onCommand(CommandExecuteEvent event) {
        if (!(event.getCommandSource() instanceof Player player)) {
            return;
        }
        if (auth.isAuthenticated(player.getUniqueId())) {
            return;
        }
        String root = event.getCommand().split(" ", 2)[0].toLowerCase(Locale.ROOT);
        if (ALLOWED_WHILE_UNAUTHENTICATED.contains(root)) {
            return;
        }
        event.setResult(CommandExecuteEvent.CommandResult.denied());
        player.sendMessage(lang.get("auth.command-blocked", player.getEffectiveLocale()));
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        auth.endSession(event.getPlayer().getUniqueId());
    }

    /**
     * Moves a freshly authenticated player out of limbo and issues a session
     * cookie so the next join can skip the password prompt.
     */
    public void releaseFromLimbo(Player player) {
        UUID id = player.getUniqueId();
        Optional<AuthState> state = auth.state(id);
        if (state.isEmpty() || !state.get().authenticated()) {
            return;
        }

        if (config.session.enabled) {
            byte[] token = auth.issueSessionToken(state.get().identity());
            if (token != null) {
                player.storeCookie(sessionCookieKey, token);
            }
        }

        Optional<RegisteredServer> destination = resolveDestination(player);
        if (destination.isEmpty()) {
            player.disconnect(lang.get("error.no-server-available", player.getEffectiveLocale()));
            return;
        }
        player.createConnectionRequest(destination.get()).fireAndForget();
    }

    /**
     * Honours a forced host when configured, so a player who connected
     * through an smp subdomain lands there rather than the lobby. The forced
     * host is a destination hint applied after authentication, never a way
     * around it.
     */
    private Optional<RegisteredServer> resolveDestination(Player player) {
        if (config.routing.honourForcedHosts) {
            Optional<String> virtualHost = player.getVirtualHost()
                    .map(host -> host.getHostString().toLowerCase(Locale.ROOT));
            if (virtualHost.isPresent()) {
                List<String> forced = proxy.getConfiguration().getForcedHosts().get(virtualHost.get());
                if (forced != null) {
                    for (String name : forced) {
                        Optional<RegisteredServer> server = proxy.getServer(name);
                        if (server.isPresent()) {
                            return server;
                        }
                    }
                }
            }
        }
        return firstAvailablePostAuthServer();
    }

    private Optional<RegisteredServer> firstAvailablePostAuthServer() {
        for (String name : config.routing.postAuthServers) {
            Optional<RegisteredServer> server = proxy.getServer(name);
            if (server.isPresent()) {
                return server;
            }
        }
        return Optional.empty();
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
