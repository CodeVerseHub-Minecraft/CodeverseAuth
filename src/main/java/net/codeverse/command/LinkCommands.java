package net.codeverse.command;

import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import net.codeverse.api.link.LinkCode;
import net.codeverse.api.link.LinkService;
import net.codeverse.auth.AuthManager;
import net.codeverse.auth.AuthState;
import net.codeverse.config.PluginConfig;
import net.codeverse.lang.LangManager;
import org.slf4j.Logger;

import java.time.Duration;
import java.util.Optional;

/**
 * Issues Discord link codes to players in game.
 *
 * The command deliberately does the in game half of the flow only. A code
 * proves control of the Minecraft account; presenting it through Discord
 * proves control of the Discord account. Letting a player supply their own
 * Discord id here would collapse the two proofs into one and make linking
 * an assertion rather than a demonstration.
 */
public final class LinkCommands {

    private final ProxyServer proxy;
    private final PluginConfig config;
    private final AuthManager auth;
    private final LinkService links;
    private final LangManager lang;
    private final Logger logger;
    private final Object plugin;

    public LinkCommands(Object plugin,
                        ProxyServer proxy,
                        PluginConfig config,
                        AuthManager auth,
                        LinkService links,
                        LangManager lang,
                        Logger logger) {
        this.plugin = plugin;
        this.proxy = proxy;
        this.config = config;
        this.auth = auth;
        this.links = links;
        this.lang = lang;
        this.logger = logger;
    }

    public void registerAll() {
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("link").plugin(plugin).build(),
                linkCommand());
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("unlink").plugin(plugin).build(),
                unlinkCommand());
    }

    private BrigadierCommand linkCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("link")
                .executes(context -> {
                    player(context.getSource()).ifPresent(this::issue);
                    return 1;
                });
        return new BrigadierCommand(node);
    }

    private BrigadierCommand unlinkCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("unlink")
                .executes(context -> {
                    player(context.getSource()).ifPresent(this::unlink);
                    return 1;
                });
        return new BrigadierCommand(node);
    }

    private void issue(Player player) {
        Optional<AuthState> state = authenticatedState(player);
        if (state.isEmpty()) {
            return;
        }
        Duration lifetime = Duration.ofSeconds(config.http.linkCodeLifetimeSeconds);
        links.issueCode(state.get().identity().internalId(), lifetime)
                .whenComplete((code, failure) -> {
                    if (failure != null) {
                        logger.error("Could not issue a link code for {}", player.getUsername(), failure);
                        player.sendMessage(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
                        return;
                    }
                    sendCode(player, code, lifetime);
                });
    }

    private void sendCode(Player player, LinkCode code, Duration lifetime) {
        player.sendMessage(lang.get("link.issued", player.getEffectiveLocale(),
                "code", code.code(),
                "minutes", String.valueOf(Math.max(1, lifetime.toMinutes()))));
    }

    private void unlink(Player player) {
        Optional<AuthState> state = authenticatedState(player);
        if (state.isEmpty()) {
            return;
        }
        links.unlink(state.get().identity().internalId())
                .whenComplete((removed, failure) -> {
                    if (failure != null) {
                        logger.error("Could not unlink {}", player.getUsername(), failure);
                        player.sendMessage(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
                        return;
                    }
                    player.sendMessage(lang.get(
                            Boolean.TRUE.equals(removed) ? "link.removed" : "link.not-linked",
                            player.getEffectiveLocale()));
                });
    }

    /**
     * Refuses the command until the player has signed in.
     *
     * Without this an unauthenticated session sitting in limbo could mint a
     * code for an account it has not proven it owns, which is precisely the
     * proof the code is supposed to carry.
     */
    private Optional<AuthState> authenticatedState(Player player) {
        Optional<AuthState> state = auth.state(player.getUniqueId());
        if (state.isEmpty() || !state.get().authenticated()) {
            player.sendMessage(lang.get("link.must-be-authenticated", player.getEffectiveLocale()));
            return Optional.empty();
        }
        return state;
    }

    private Optional<Player> player(CommandSource source) {
        if (source instanceof Player player) {
            return Optional.of(player);
        }
        source.sendMessage(lang.get("link.players-only"));
        return Optional.empty();
    }
}
