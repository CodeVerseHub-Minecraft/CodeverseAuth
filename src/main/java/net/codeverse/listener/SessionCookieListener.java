package net.codeverse.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.CookieReceiveEvent;
import com.velocitypowered.api.proxy.Player;
import net.codeverse.auth.AuthManager;
import net.codeverse.auth.AuthState;
import net.codeverse.config.PluginConfig;
import net.codeverse.lang.LangManager;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;

/**
 * Consumes the session cookie the client returns and skips the password
 * prompt when it is valid.
 *
 * The cookie lives on the client, so it is treated as hostile input. The
 * codec verifies the signature before any field is read, and the internal id
 * inside the token must match the identity the proxy independently resolved
 * for this connection. Without that second check, a valid token for account
 * A could be replayed by whoever holds it to authenticate as account A while
 * connecting under a different name.
 */
public final class SessionCookieListener {

    private final PluginConfig config;
    private final AuthManager auth;
    private final AuthGateListener gate;
    private final LangManager lang;
    private final Logger logger;

    public SessionCookieListener(PluginConfig config,
                                 AuthManager auth,
                                 AuthGateListener gate,
                                 LangManager lang,
                                 Logger logger) {
        this.config = config;
        this.auth = auth;
        this.gate = gate;
        this.lang = lang;
        this.logger = logger;
    }

    @Subscribe(priority = 500)
    public void onCookieReceive(CookieReceiveEvent event) {
        if (!config.session.enabled) {
            return;
        }
        if (!event.getOriginalKey().asString().equals(config.session.cookieKey)) {
            return;
        }

        Player player = event.getPlayer();
        event.setResult(CookieReceiveEvent.ForwardResult.handled());

        Optional<AuthState> maybeState = auth.state(player.getUniqueId());
        if (maybeState.isEmpty()) {
            return;
        }
        AuthState state = maybeState.get();
        if (state.authenticated()) {
            return;
        }

        UUID tokenIdentity = auth.verifySessionToken(event.getOriginalData());
        if (tokenIdentity == null) {
            return;
        }
        if (!tokenIdentity.equals(state.identity().internalId())) {
            logger.warn("Session cookie for {} carried identity {} but the connection resolved to {}, rejecting",
                    player.getUsername(), tokenIdentity, state.identity().internalId());
            return;
        }
        if (config.session.bindToAddress
                && !state.address().equals(player.getRemoteAddress().getAddress().getHostAddress())) {
            return;
        }

        state.stage(AuthState.Stage.AUTHENTICATED);
        player.sendMessage(lang.get("auth.session-restored", player.getEffectiveLocale()));
        gate.releaseFromLimbo(player);
    }
}
