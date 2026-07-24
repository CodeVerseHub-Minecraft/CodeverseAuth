package net.codeverse.http;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.IdentityService;
import net.codeverse.api.link.LinkCode;
import net.codeverse.api.link.LinkService;
import org.slf4j.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * The external HTTP interface.
 *
 * Built on the JDK's own server rather than a framework, because the surface is
 * small, the throughput is low, and a web framework inside a Minecraft proxy is
 * a large amount of code running in the most security sensitive process on the
 * network.
 *
 * Two rules govern every handler here.
 *
 * No response ever contains a secret. Not a password hash, not a TOTP secret,
 * not a session token, not a recovery code, not even to a caller that
 * authenticated successfully. An integration needs identities and links; giving
 * it anything more means a compromised integration is a compromised network.
 *
 * No error tells an unauthenticated caller anything they did not already know.
 * A rejected request returns 401 whether the address was wrong, the signature
 * was wrong, or the account does not exist, so the interface cannot be mapped
 * from outside.
 */
public final class HttpApiServer {

    private static final Gson GSON = new Gson();
    private static final int SHUTDOWN_GRACE_SECONDS = 3;

    private final HttpApiConfig config;
    private final ApiAuthenticator authenticator;
    private final IdentityService identities;
    private final LinkService links;
    private final Logger logger;
    private final Path dataDirectory;

    private HttpServer server;
    private ExecutorService executor;

    public HttpApiServer(HttpApiConfig config,
                         ApiAuthenticator authenticator,
                         IdentityService identities,
                         LinkService links,
                         Path dataDirectory,
                         Logger logger) {
        this.config = config;
        this.authenticator = authenticator;
        this.identities = identities;
        this.links = links;
        this.dataDirectory = dataDirectory;
        this.logger = logger;
    }

    /** Binds and begins serving. Returns false when the interface is disabled. */
    public boolean start() throws IOException {
        if (!config.enabled) {
            return false;
        }
        for (String warning : config.securityWarnings()) {
            logger.warn("HTTP interface: {}", warning);
        }

        InetSocketAddress address = new InetSocketAddress(config.bindAddress, config.port);
        server = config.tls.enabled ? createHttpsServer(address) : HttpServer.create(address, 0);

        // Virtual threads: requests are almost entirely waiting on storage, and
        // a fixed pool would either be wasteful or a bottleneck.
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);

        server.createContext("/v1/health", this::handle);
        server.createContext("/v1/identity", this::handle);
        server.createContext("/v1/link", this::handle);
        server.start();

        logger.info("HTTP interface listening on {}:{} ({}, {} authentication)",
                config.bindAddress, config.port,
                config.tls.enabled ? "TLS" : "plaintext",
                config.requireSignedRequests ? "signed request" : "bearer token");
        return true;
    }

    private HttpServer createHttpsServer(InetSocketAddress address) throws IOException {
        Path keystorePath = dataDirectory.resolve(config.tls.keystorePath);
        if (!Files.exists(keystorePath)) {
            throw new IOException("TLS is enabled but the keystore was not found at " + keystorePath);
        }
        try {
            char[] password = config.tls.keystorePassword.toCharArray();
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            try (InputStream stream = Files.newInputStream(keystorePath)) {
                keystore.load(stream, password);
            }
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keystore, password);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), null, null);

            HttpsServer https = HttpsServer.create(address, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(context));
            return https;
        } catch (java.security.GeneralSecurityException failure) {
            throw new IOException("Could not initialise TLS from " + keystorePath, failure);
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(SHUTDOWN_GRACE_SECONDS);
            server = null;
        }
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(SHUTDOWN_GRACE_SECONDS, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                executor.shutdownNow();
            }
            executor = null;
        }
    }

    private void handle(HttpExchange exchange) {
        String address = exchange.getRemoteAddress().getAddress().getHostAddress();
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        try {
            byte[] body = exchange.getRequestBody().readAllBytes();
            ApiAuthenticator.Result outcome = authenticator.check(address, method, path, body, headersOf(exchange));

            if (!outcome.allowed()) {
                // Only outcomes a legitimate integration can act on are named.
                // Everything else is an undifferentiated 401, so the interface
                // cannot be probed for which control rejected the caller.
                logger.warn("HTTP interface refused {} {} from {}: {}", method, path, address, outcome);
                if (outcome == ApiAuthenticator.Result.RATE_LIMITED) {
                    respond(exchange, 429, error("rate_limited", "Too many requests."));
                } else if (outcome == ApiAuthenticator.Result.STALE_TIMESTAMP) {
                    respond(exchange, 401, error("stale_timestamp",
                            "Request timestamp outside the accepted window. Check the caller's clock."));
                } else {
                    respond(exchange, 401, error("unauthorized", "Unauthorized."));
                }
                return;
            }

            route(exchange, method, path, body, address);

        } catch (Exception failure) {
            // The message is deliberately generic. An exception's text can name
            // tables, columns and file paths, none of which a caller needs.
            logger.error("HTTP interface failed handling {} {} from {}", method, path, address, failure);
            try {
                respond(exchange, 500, error("internal_error", "The request could not be completed."));
            } catch (IOException unwritable) {
                // The caller has already gone. Nothing further to do, and the
                // original failure is already logged above.
                logger.debug("Could not write the error response to {}", address, unwritable);
            }
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange, String method, String path, byte[] body, String address)
            throws IOException {
        String normalised = path.endsWith("/") && path.length() > 1
                ? path.substring(0, path.length() - 1)
                : path;

        if (normalised.equals("/v1/health") && method.equals("GET")) {
            JsonObject payload = new JsonObject();
            payload.addProperty("status", "ok");
            payload.addProperty("linkageAvailable", identities.isLinkageAvailable());
            respond(exchange, 200, payload);
            return;
        }

        if (normalised.startsWith("/v1/identity/") && method.equals("GET")) {
            handleIdentityLookup(exchange, normalised.substring("/v1/identity/".length()));
            return;
        }

        if (normalised.equals("/v1/link/code") && method.equals("POST")) {
            requireWrites(exchange, () -> handleIssueCode(exchange, body, address));
            return;
        }

        if (normalised.equals("/v1/link/redeem") && method.equals("POST")) {
            requireWrites(exchange, () -> handleRedeem(exchange, body, address));
            return;
        }

        if (normalised.startsWith("/v1/link/discord/")) {
            String discordId = normalised.substring("/v1/link/discord/".length());
            if (method.equals("GET")) {
                handleLookupByDiscord(exchange, discordId);
                return;
            }
            if (method.equals("DELETE")) {
                requireWrites(exchange, () -> handleUnlink(exchange, discordId, address));
                return;
            }
        }

        respond(exchange, 404, error("not_found", "No such endpoint."));
    }

    private void requireWrites(HttpExchange exchange, IoRunnable action) throws IOException {
        if (!config.allowWrites) {
            respond(exchange, 403, error("writes_disabled",
                    "This interface is configured for read only access."));
            return;
        }
        action.run();
    }

    private void handleIdentityLookup(HttpExchange exchange, String identifier) throws IOException {
        Optional<Identity> found = resolveIdentifier(identifier).join();
        if (found.isEmpty()) {
            respond(exchange, 404, error("not_found", "No such identity."));
            return;
        }
        respond(exchange, 200, toJson(found.get()));
    }

    /** Accepts a uuid or a username, so callers do not need to know which they hold. */
    private java.util.concurrent.CompletableFuture<Optional<Identity>> resolveIdentifier(String identifier) {
        String decoded = java.net.URLDecoder.decode(identifier, StandardCharsets.UTF_8);
        try {
            return identities.byMinecraftId(UUID.fromString(decoded));
        } catch (IllegalArgumentException notAUuid) {
            return identities.byUsername(decoded);
        }
    }

    private void handleIssueCode(HttpExchange exchange, byte[] body, String address) throws IOException {
        JsonObject request = parse(body);
        String player = optionalString(request, "player");
        if (player == null) {
            respond(exchange, 400, error("bad_request", "A player uuid or username is required."));
            return;
        }
        Optional<Identity> identity = resolveIdentifier(player).join();
        if (identity.isEmpty()) {
            respond(exchange, 404, error("not_found", "No such identity."));
            return;
        }

        LinkCode code = links.issueCode(identity.get().internalId(),
                Duration.ofSeconds(config.linkCodeLifetimeSeconds)).join();

        logger.info("HTTP interface issued a link code for {} to {}", identity.get().username(), address);

        JsonObject payload = new JsonObject();
        payload.addProperty("code", code.code());
        payload.addProperty("expiresAt", code.expiresAt().toString());
        payload.addProperty("lifetimeSeconds", config.linkCodeLifetimeSeconds);
        respond(exchange, 200, payload);
    }

    private void handleRedeem(HttpExchange exchange, byte[] body, String address) throws IOException {
        JsonObject request = parse(body);
        String code = optionalString(request, "code");
        String discordId = optionalString(request, "discordId");
        if (code == null || discordId == null) {
            respond(exchange, 400, error("bad_request", "Both code and discordId are required."));
            return;
        }

        Optional<Identity> linked = links.redeem(code, discordId).join();
        if (linked.isEmpty()) {
            // Unknown, expired and already redeemed are deliberately identical.
            // Distinguishing them turns the code space into something worth
            // guessing at, since a caller could learn which codes ever existed.
            logger.warn("HTTP interface rejected a link redemption from {}", address);
            respond(exchange, 404, error("invalid_code", "That code is not valid."));
            return;
        }
        logger.info("HTTP interface linked {} to a Discord identity, requested by {}",
                linked.get().username(), address);
        respond(exchange, 200, toJson(linked.get()));
    }

    private void handleLookupByDiscord(HttpExchange exchange, String discordId) throws IOException {
        Optional<Identity> found = identities.byDiscordId(discordId).join();
        if (found.isEmpty()) {
            respond(exchange, 404, error("not_found", "No identity is linked to that Discord account."));
            return;
        }
        respond(exchange, 200, toJson(found.get()));
    }

    private void handleUnlink(HttpExchange exchange, String discordId, String address) throws IOException {
        boolean removed = links.unlinkByDiscordId(discordId).join();
        logger.info("HTTP interface unlink for a Discord identity requested by {}, existed: {}",
                address, removed);

        JsonObject payload = new JsonObject();
        payload.addProperty("unlinked", removed);
        respond(exchange, removed ? 200 : 404, payload);
    }

    /**
     * Renders an identity for the wire.
     *
     * Every field here is deliberate. There is no password hash, no TOTP
     * secret, no recovery code and no session token, and none should ever be
     * added: an integration that needs them is an integration doing something
     * it should not.
     */
    private static JsonObject toJson(Identity identity) {
        JsonObject payload = new JsonObject();
        payload.addProperty("internalId", identity.internalId().toString());
        payload.addProperty("minecraftId", identity.minecraftId().toString());
        payload.addProperty("username", identity.username());
        payload.addProperty("tier", identity.tier().name());
        payload.addProperty("registered", identity.isRegistered());
        payload.addProperty("totpEnrolled", identity.totpEnrolled());
        identity.registeredAt().ifPresent(value -> payload.addProperty("registeredAt", value.toString()));
        identity.lastLoginAt().ifPresent(value -> payload.addProperty("lastLoginAt", value.toString()));
        identity.discordId().ifPresent(value -> payload.addProperty("discordId", value));
        return payload;
    }

    private static JsonObject error(String code, String message) {
        JsonObject payload = new JsonObject();
        payload.addProperty("error", code);
        payload.addProperty("message", message);
        return payload;
    }

    private static JsonObject parse(byte[] body) {
        if (body == null || body.length == 0) {
            return new JsonObject();
        }
        try {
            JsonObject parsed = GSON.fromJson(new String(body, StandardCharsets.UTF_8), JsonObject.class);
            return parsed == null ? new JsonObject() : parsed;
        } catch (RuntimeException malformed) {
            return new JsonObject();
        }
    }

    private static String optionalString(JsonObject object, String key) {
        if (!object.has(key) || object.get(key).isJsonNull()) {
            return null;
        }
        String value = object.get(key).getAsString();
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static Map<String, String> headersOf(HttpExchange exchange) {
        Map<String, String> headers = new HashMap<>();
        exchange.getRequestHeaders().forEach((name, values) -> {
            if (!values.isEmpty()) {
                headers.put(name.toLowerCase(Locale.ROOT), values.get(0));
            }
        });
        return headers;
    }

    private static void respond(HttpExchange exchange, int status, JsonObject payload) throws IOException {
        byte[] bytes = GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        // Nothing here should be cached by an intermediary.
        exchange.getResponseHeaders().add("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    @FunctionalInterface
    private interface IoRunnable {
        void run() throws IOException;
    }

    /** Endpoints this interface serves, for documentation and tests. */
    public static List<String> endpoints() {
        return List.of(
                "GET    /v1/health",
                "GET    /v1/identity/{uuid|username}",
                "GET    /v1/link/discord/{discordId}",
                "POST   /v1/link/code      {player}",
                "POST   /v1/link/redeem    {code, discordId}",
                "DELETE /v1/link/discord/{discordId}");
    }
}
