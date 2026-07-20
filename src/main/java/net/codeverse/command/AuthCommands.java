package net.codeverse.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.velocitypowered.api.command.BrigadierCommand;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.codeverse.auth.AuthManager;
import net.codeverse.auth.AuthState;
import net.codeverse.config.PluginConfig;
import net.codeverse.lang.LangManager;
import net.codeverse.listener.AuthGateListener;
import org.slf4j.Logger;

import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutorService;

/**
 * Player facing authentication commands.
 *
 * Passwords arrive as command arguments because Minecraft offers no masked
 * input. Two mitigations apply: command execution logging can be disabled
 * for these specific commands in velocity.toml, and every argument is copied
 * into a char array and cleared after use so it is not left sitting in the
 * string pool longer than necessary.
 *
 * All work touching the database runs on the plugin executor rather than the
 * event thread, since Argon2 verification is intentionally slow and would
 * otherwise stall the proxy.
 */
public final class AuthCommands {

    private final ProxyServer proxy;
    private final PluginConfig config;
    private final AuthManager auth;
    private final AuthGateListener gate;
    private final LangManager lang;
    private final ExecutorService executor;
    private final Logger logger;
    private final Object plugin;

    public AuthCommands(Object plugin,
                        ProxyServer proxy,
                        PluginConfig config,
                        AuthManager auth,
                        AuthGateListener gate,
                        LangManager lang,
                        ExecutorService executor,
                        Logger logger) {
        this.plugin = plugin;
        this.proxy = proxy;
        this.config = config;
        this.auth = auth;
        this.gate = gate;
        this.lang = lang;
        this.executor = executor;
        this.logger = logger;
    }

    public void registerAll() {
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("login").aliases("l").plugin(plugin).build(),
                loginCommand());
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("register").aliases("reg").plugin(plugin).build(),
                registerCommand());
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("changepassword").aliases("changepw").plugin(plugin).build(),
                changePasswordCommand());
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("2fa").aliases("totp").plugin(plugin).build(),
                totpCommand());
    }

    private BrigadierCommand loginCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("login")
                .executes(context -> {
                    source(context.getSource()).ifPresent(player ->
                            player.sendMessage(lang.get("login.usage", player.getEffectiveLocale())));
                    return 1;
                })
                .then(BrigadierCommand.requiredArgumentBuilder("password", StringArgumentType.string())
                        .executes(context -> {
                            Optional<Player> maybePlayer = source(context.getSource());
                            if (maybePlayer.isEmpty()) {
                                return 1;
                            }
                            Player player = maybePlayer.get();
                            char[] password = context.getArgument("password", String.class).toCharArray();
                            executor.execute(() -> handleLogin(player, password));
                            return 1;
                        }));
        return new BrigadierCommand(node);
    }

    private void handleLogin(Player player, char[] password) {
        Optional<AuthState> maybeState = auth.state(player.getUniqueId());
        if (maybeState.isEmpty()) {
            return;
        }
        AuthState state = maybeState.get();
        try {
            if (state.authenticated()) {
                player.sendMessage(lang.get("login.already", player.getEffectiveLocale()));
                return;
            }
            if (state.stage() == AuthState.Stage.AWAITING_TOTP) {
                player.sendMessage(lang.get("totp.prompt", player.getEffectiveLocale()));
                return;
            }
            AuthManager.Result result = auth.login(state, password);
            switch (result.outcome()) {
                case SUCCESS -> {
                    player.sendMessage(lang.get("login.success", player.getEffectiveLocale()));
                    gate.releaseFromLimbo(player);
                }
                case AWAITING_TOTP -> player.sendMessage(lang.get("totp.prompt", player.getEffectiveLocale()));
                case NOT_REGISTERED -> player.sendMessage(lang.get("login.not-registered", player.getEffectiveLocale()));
                case INVALID_CREDENTIALS -> player.sendMessage(lang.get("login.invalid", player.getEffectiveLocale()));
                case LOCKED_OUT -> player.sendMessage(lang.get("login.locked",
                        player.getEffectiveLocale(), "duration", humanDuration(result.lockedUntil())));
                case TOTP_REQUIRED_NOT_ENROLLED ->
                        player.sendMessage(lang.get("totp.required-not-enrolled", player.getEffectiveLocale()));
                default -> player.sendMessage(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
            }
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private BrigadierCommand registerCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("register")
                .executes(context -> {
                    source(context.getSource()).ifPresent(player ->
                            player.sendMessage(lang.get("register.usage", player.getEffectiveLocale())));
                    return 1;
                })
                .then(BrigadierCommand.requiredArgumentBuilder("password", StringArgumentType.string())
                        .then(BrigadierCommand.requiredArgumentBuilder("confirm", StringArgumentType.string())
                                .executes(context -> {
                                    Optional<Player> maybePlayer = source(context.getSource());
                                    if (maybePlayer.isEmpty()) {
                                        return 1;
                                    }
                                    Player player = maybePlayer.get();
                                    char[] password = context.getArgument("password", String.class).toCharArray();
                                    char[] confirm = context.getArgument("confirm", String.class).toCharArray();
                                    executor.execute(() -> handleRegister(player, password, confirm));
                                    return 1;
                                })));
        return new BrigadierCommand(node);
    }

    private void handleRegister(Player player, char[] password, char[] confirm) {
        Optional<AuthState> maybeState = auth.state(player.getUniqueId());
        if (maybeState.isEmpty()) {
            return;
        }
        try {
            AuthManager.Result result = auth.register(maybeState.get(), password, confirm);
            switch (result.outcome()) {
                case SUCCESS -> {
                    player.sendMessage(lang.get("register.success", player.getEffectiveLocale()));
                    gate.releaseFromLimbo(player);
                }
                case ALREADY_REGISTERED ->
                        player.sendMessage(lang.get("register.already", player.getEffectiveLocale()));
                case PASSWORD_TOO_SHORT -> player.sendMessage(lang.get("password.too-short",
                        player.getEffectiveLocale(), "min", String.valueOf(config.security.minimumPasswordLength)));
                case PASSWORD_TOO_LONG -> player.sendMessage(lang.get("password.too-long",
                        player.getEffectiveLocale(), "max", String.valueOf(config.security.maximumPasswordLength)));
                case PASSWORD_MISMATCH -> player.sendMessage(lang.get("password.mismatch", player.getEffectiveLocale()));
                default -> player.sendMessage(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
            }
        } finally {
            java.util.Arrays.fill(password, '\0');
            java.util.Arrays.fill(confirm, '\0');
        }
    }

    private BrigadierCommand changePasswordCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("changepassword")
                .executes(context -> {
                    source(context.getSource()).ifPresent(player ->
                            player.sendMessage(lang.get("password.usage", player.getEffectiveLocale())));
                    return 1;
                })
                .then(BrigadierCommand.requiredArgumentBuilder("current", StringArgumentType.string())
                        .then(BrigadierCommand.requiredArgumentBuilder("replacement", StringArgumentType.string())
                                .executes(context -> {
                                    Optional<Player> maybePlayer = source(context.getSource());
                                    if (maybePlayer.isEmpty()) {
                                        return 1;
                                    }
                                    Player player = maybePlayer.get();
                                    char[] current = context.getArgument("current", String.class).toCharArray();
                                    char[] replacement = context.getArgument("replacement", String.class).toCharArray();
                                    executor.execute(() -> {
                                        try {
                                            AuthManager.Result result =
                                                    auth.changePassword(player.getUniqueId(), current, replacement);
                                            player.sendMessage(switch (result.outcome()) {
                                                case SUCCESS -> lang.get("password.changed", player.getEffectiveLocale());
                                                case INVALID_CREDENTIALS ->
                                                        lang.get("password.wrong-current", player.getEffectiveLocale());
                                                case PASSWORD_TOO_SHORT -> lang.get("password.too-short",
                                                        player.getEffectiveLocale(), "min",
                                                        String.valueOf(config.security.minimumPasswordLength));
                                                case PASSWORD_TOO_LONG -> lang.get("password.too-long",
                                                        player.getEffectiveLocale(), "max",
                                                        String.valueOf(config.security.maximumPasswordLength));
                                                case NOT_REGISTERED ->
                                                        lang.get("login.not-registered", player.getEffectiveLocale());
                                                default -> lang.get("error.storage-unavailable",
                                                        player.getEffectiveLocale());
                                            });
                                        } finally {
                                            java.util.Arrays.fill(current, '\0');
                                            java.util.Arrays.fill(replacement, '\0');
                                        }
                                    });
                                    return 1;
                                })));
        return new BrigadierCommand(node);
    }

    private BrigadierCommand totpCommand() {
        LiteralArgumentBuilder<CommandSource> node = BrigadierCommand.literalArgumentBuilder("2fa")
                .executes(context -> {
                    source(context.getSource()).ifPresent(player ->
                            player.sendMessage(lang.get("totp.usage", player.getEffectiveLocale())));
                    return 1;
                })
                .then(BrigadierCommand.literalArgumentBuilder("enable")
                        .executes(context -> {
                            source(context.getSource()).ifPresent(player ->
                                    executor.execute(() -> beginEnrolment(player)));
                            return 1;
                        }))
                .then(BrigadierCommand.literalArgumentBuilder("confirm")
                        .then(BrigadierCommand.requiredArgumentBuilder("code", StringArgumentType.word())
                                .executes(context -> {
                                    Optional<Player> maybePlayer = source(context.getSource());
                                    if (maybePlayer.isEmpty()) {
                                        return 1;
                                    }
                                    Player player = maybePlayer.get();
                                    String code = context.getArgument("code", String.class);
                                    executor.execute(() -> confirmEnrolment(player, code));
                                    return 1;
                                })))
                .then(BrigadierCommand.literalArgumentBuilder("disable")
                        .then(BrigadierCommand.requiredArgumentBuilder("password", StringArgumentType.string())
                                .executes(context -> {
                                    Optional<Player> maybePlayer = source(context.getSource());
                                    if (maybePlayer.isEmpty()) {
                                        return 1;
                                    }
                                    Player player = maybePlayer.get();
                                    char[] password = context.getArgument("password", String.class).toCharArray();
                                    executor.execute(() -> {
                                        try {
                                            AuthManager.Result result =
                                                    auth.disableTotp(player.getUniqueId(), password);
                                            player.sendMessage(result.success()
                                                    ? lang.get("totp.disabled", player.getEffectiveLocale())
                                                    : lang.get("password.wrong-current", player.getEffectiveLocale()));
                                        } finally {
                                            java.util.Arrays.fill(password, '\0');
                                        }
                                    });
                                    return 1;
                                })))
                .then(BrigadierCommand.requiredArgumentBuilder("code", StringArgumentType.word())
                        .executes(context -> {
                            Optional<Player> maybePlayer = source(context.getSource());
                            if (maybePlayer.isEmpty()) {
                                return 1;
                            }
                            Player player = maybePlayer.get();
                            String code = context.getArgument("code", String.class);
                            executor.execute(() -> submitTotp(player, code));
                            return 1;
                        }));
        return new BrigadierCommand(node);
    }

    private void beginEnrolment(Player player) {
        if (!config.totp.enabled) {
            player.sendMessage(lang.get("totp.disabled-globally", player.getEffectiveLocale()));
            return;
        }
        Optional<AuthState> state = auth.state(player.getUniqueId());
        if (state.isEmpty() || !state.get().authenticated()) {
            player.sendMessage(lang.get("totp.must-be-authenticated", player.getEffectiveLocale()));
            return;
        }
        String secret = auth.beginTotpEnrolment();
        pendingEnrolments.put(player.getUniqueId(), secret);
        String uri = auth.provisioningUri(secret, player.getUsername());
        player.sendMessage(lang.get("totp.enrolment-started", player.getEffectiveLocale(),
                "secret", secret, "uri", uri));
    }

    private void confirmEnrolment(Player player, String code) {
        String secret = pendingEnrolments.get(player.getUniqueId());
        if (secret == null) {
            player.sendMessage(lang.get("totp.no-pending-enrolment", player.getEffectiveLocale()));
            return;
        }
        Optional<AuthState> state = auth.state(player.getUniqueId());
        if (state.isEmpty()) {
            return;
        }
        AuthManager.Result result = auth.confirmTotpEnrolment(
                player.getUniqueId(), state.get().identity().internalId(), secret, code);
        if (!result.success()) {
            player.sendMessage(lang.get("totp.invalid-code", player.getEffectiveLocale()));
            return;
        }
        pendingEnrolments.remove(player.getUniqueId());
        player.sendMessage(lang.get("totp.enabled", player.getEffectiveLocale()));
        try {
            List<String> codes = auth.issueRecoveryCodes(state.get().identity().internalId());
            player.sendMessage(lang.get("totp.recovery-codes", player.getEffectiveLocale(),
                    "codes", String.join("  ", codes)));
        } catch (SQLException failure) {
            logger.error("Failed to issue recovery codes for {}", player.getUsername(), failure);
            player.sendMessage(lang.get("totp.recovery-codes-failed", player.getEffectiveLocale()));
        }
    }

    private void submitTotp(Player player, String code) {
        Optional<AuthState> maybeState = auth.state(player.getUniqueId());
        if (maybeState.isEmpty()) {
            return;
        }
        AuthState state = maybeState.get();
        if (state.stage() != AuthState.Stage.AWAITING_TOTP) {
            player.sendMessage(lang.get("totp.not-awaiting", player.getEffectiveLocale()));
            return;
        }
        AuthManager.Result result = auth.submitTotp(state, code);
        switch (result.outcome()) {
            case SUCCESS -> {
                player.sendMessage(lang.get("login.success", player.getEffectiveLocale()));
                gate.releaseFromLimbo(player);
            }
            case LOCKED_OUT -> player.sendMessage(lang.get("login.locked",
                    player.getEffectiveLocale(), "duration", humanDuration(result.lockedUntil())));
            case INVALID_TOTP -> player.sendMessage(lang.get("totp.invalid-code", player.getEffectiveLocale()));
            default -> player.sendMessage(lang.get("error.storage-unavailable", player.getEffectiveLocale()));
        }
    }

    private final java.util.concurrent.ConcurrentHashMap<java.util.UUID, String> pendingEnrolments =
            new java.util.concurrent.ConcurrentHashMap<>();

    public void forgetEnrolment(java.util.UUID playerId) {
        pendingEnrolments.remove(playerId);
    }

    private static Optional<Player> source(CommandSource source) {
        return source instanceof Player player ? Optional.of(player) : Optional.empty();
    }

    private String humanDuration(long until) {
        long remaining = Math.max(0L, until - System.currentTimeMillis());
        Duration duration = Duration.ofMillis(remaining);
        long minutes = duration.toMinutes();
        if (minutes >= 1) {
            return minutes + "m";
        }
        return Math.max(1, duration.toSeconds()) + "s";
    }
}
