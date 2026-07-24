package net.codeverse.http;

import net.codeverse.api.identity.*;
import net.codeverse.api.link.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boots the real server and drives it over real HTTP.
 *
 * Deliberately not a mock. The properties worth protecting here, that no
 * response carries a secret and that a rejected caller learns nothing, are
 * properties of what goes over the socket rather than of the handler code.
 */
class HttpApiServerTest {

    private static void assertTrue2(String label, boolean condition) {
        assertTrue(condition, label);
    }

    
    static final UUID INTERNAL = UUID.fromString("11111111-1111-1111-1111-111111111111");
    static final UUID MINECRAFT = UUID.fromString("22222222-2222-2222-2222-222222222222");
    static Identity STEVE = Identity.builder(INTERNAL, MINECRAFT, "Steve", TrustTier.PREMIUM)
            .registeredAtMillis(1_700_000_000_000L).build();
    static final Map<String,LinkCode> CODES = new HashMap<>();
    static String linkedDiscord = null;

    static IdentityService identityService() {
        return new IdentityService() {
            public CompletableFuture<Optional<Identity>> byMinecraftId(UUID id) {
                return CompletableFuture.completedFuture(MINECRAFT.equals(id) ? Optional.of(STEVE) : Optional.empty()); }
            public CompletableFuture<Optional<Identity>> byUsername(String n) {
                return CompletableFuture.completedFuture("Steve".equals(n) ? Optional.of(STEVE) : Optional.empty()); }
            public CompletableFuture<Optional<Identity>> byInternalId(UUID id) {
                return CompletableFuture.completedFuture(INTERNAL.equals(id) ? Optional.of(STEVE) : Optional.empty()); }
            public CompletableFuture<Optional<Identity>> byDiscordId(String d) {
                return CompletableFuture.completedFuture(d.equals(linkedDiscord) ? Optional.of(STEVE) : Optional.empty()); }
            public CompletableFuture<List<Identity>> linkedAccounts(UUID id) {
                return CompletableFuture.completedFuture(List.of(STEVE)); }
            public Optional<Identity> cachedByMinecraftId(UUID id) { return Optional.of(STEVE); }
            public CompletableFuture<Void> preload(Collection<UUID> ids) { return CompletableFuture.completedFuture(null); }
            public void invalidate(UUID id) { }
            public boolean isLinkageAvailable() { return true; }
        };
    }

    static LinkService linkService() {
        return new LinkService() {
            public CompletableFuture<LinkCode> issueCode(UUID internalId, Duration lifetime) {
                LinkCode c = new LinkCode("TESTCODE", internalId, Instant.now(), Instant.now().plus(lifetime));
                CODES.put(c.code(), c);
                return CompletableFuture.completedFuture(c); }
            public CompletableFuture<Optional<Identity>> redeem(String code, String discordId) {
                LinkCode c = CODES.remove(code);
                if (c == null || !c.isRedeemable(Instant.now())) return CompletableFuture.completedFuture(Optional.empty());
                linkedDiscord = discordId;
                // The contract requires the post link state, not the stale one.
                return CompletableFuture.completedFuture(Optional.of(
                    Identity.builder(INTERNAL, MINECRAFT, "Steve", TrustTier.PREMIUM)
                        .registeredAtMillis(1_700_000_000_000L)
                        .discordId(discordId).build())); }
            public CompletableFuture<Boolean> unlink(UUID internalId) { return CompletableFuture.completedFuture(true); }
            public CompletableFuture<Boolean> unlinkByDiscordId(String d) {
                boolean had = d.equals(linkedDiscord);
                if (had) linkedDiscord = null;
                return CompletableFuture.completedFuture(had); }
            public CompletableFuture<Optional<String>> discordIdOf(UUID id) {
                return CompletableFuture.completedFuture(Optional.ofNullable(linkedDiscord)); }
            public CompletableFuture<Integer> purgeExpiredCodes() { return CompletableFuture.completedFuture(0); }
        };
    }

    static HttpApiConfig config;
    static ApiAuthenticator auth;
    static HttpClient client = HttpClient.newHttpClient();
    static int port = 18789;

    static HttpResponse<String> signed(String method, String path, String body) throws Exception {
        long ts = System.currentTimeMillis()/1000L;
        String nonce = UUID.randomUUID().toString();
        byte[] raw = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        String sig = auth.sign(method, path, ts, nonce, raw);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path))
            .header("X-Codeverse-Signature", sig)
            .header("X-Codeverse-Timestamp", String.valueOf(ts))
            .header("X-Codeverse-Nonce", nonce);
        b = switch (method) {
            case "GET" -> b.GET();
            case "DELETE" -> b.DELETE();
            default -> b.method(method, HttpRequest.BodyPublishers.ofByteArray(raw));
        };
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    
    @Test
    @DisplayName("the interface serves identity and link requests and refuses everything else")
    void servesOverRealHttp() throws Exception {

        config = new HttpApiConfig();
        config.enabled = true;
        config.bindAddress = "127.0.0.1";
        config.port = port;
        config.token = ApiAuthenticator.generateToken();
        config.requireSignedRequests = true;
        config.allowedAddresses = List.of("127.0.0.1");
        config.validate();

        auth = new ApiAuthenticator(config);
        HttpApiServer server = new HttpApiServer(config, auth, identityService(), linkService(),
                java.nio.file.Path.of("."), org.slf4j.LoggerFactory.getLogger("test"));
        assertTrue2("server starts", server.start());
        Thread.sleep(300);

        var health = signed("GET","/v1/health",null);
        assertTrue2("health returns 200", health.statusCode()==200);
        assertTrue2("health reports linkage", health.body().contains("\"linkageAvailable\":true"));

        var byName = signed("GET","/v1/identity/Steve",null);
        assertTrue2("lookup by username works", byName.statusCode()==200 && byName.body().contains("\"username\":\"Steve\""));

        var byUuid = signed("GET","/v1/identity/"+MINECRAFT,null);
        assertTrue2("lookup by uuid works", byUuid.statusCode()==200);

        assertTrue2("response carries the internal id", byUuid.body().contains("\"internalId\":\""+INTERNAL+"\""));
        assertTrue2("response carries no secrets",
            !byUuid.body().contains("password") && !byUuid.body().contains("totpSecret")
            && !byUuid.body().contains("hash") && !byUuid.body().contains("token"));

        var missing = signed("GET","/v1/identity/Nobody",null);
        assertTrue2("unknown identity returns 404", missing.statusCode()==404);

        // unauthenticated
        var bare = client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/v1/health")).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        assertTrue2("unsigned request refused", bare.statusCode()==401);
        assertTrue2("refusal leaks nothing", bare.body().contains("unauthorized") && !bare.body().contains("signature"));

        // link flow
        var issue = signed("POST","/v1/link/code","{\"player\":\"Steve\"}");
        assertTrue2("link code issued", issue.statusCode()==200 && issue.body().contains("TESTCODE"));

        var redeem = signed("POST","/v1/link/redeem","{\"code\":\"TESTCODE\",\"discordId\":\"99887766\"}");
        assertTrue2("code redeemed", redeem.statusCode()==200 && redeem.body().contains("\"discordId\""));

        var reuse = signed("POST","/v1/link/redeem","{\"code\":\"TESTCODE\",\"discordId\":\"99887766\"}");
        assertTrue2("code is single use", reuse.statusCode()==404);

        var bogus = signed("POST","/v1/link/redeem","{\"code\":\"NEVEREXISTED\",\"discordId\":\"1\"}");
        assertTrue2("unknown and used codes are indistinguishable",
            bogus.statusCode()==reuse.statusCode() && bogus.body().equals(reuse.body()));

        var byDiscord = signed("GET","/v1/link/discord/99887766",null);
        assertTrue2("lookup by discord id works", byDiscord.statusCode()==200 && byDiscord.body().contains("Steve"));

        var unlink = signed("DELETE","/v1/link/discord/99887766",null);
        assertTrue2("unlink works", unlink.statusCode()==200 && unlink.body().contains("\"unlinked\":true"));

        var badBody = signed("POST","/v1/link/redeem","{\"code\":\"X\"}");
        assertTrue2("missing field returns 400", badBody.statusCode()==400);

        var notFound = signed("GET","/v1/nope",null);
        assertTrue2("unknown route returns 404", notFound.statusCode()==404);

        // read only mode
        config.allowWrites = false;
        var blocked = signed("POST","/v1/link/code","{\"player\":\"Steve\"}");
        assertTrue2("writes refused in read only mode", blocked.statusCode()==403);
        config.allowWrites = true;

        server.stop();
    }
}
