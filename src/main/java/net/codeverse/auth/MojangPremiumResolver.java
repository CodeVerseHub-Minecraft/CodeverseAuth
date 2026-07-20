package net.codeverse.auth;

import net.codeverse.cache.IdentityCache;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Cached premium lookup against Mojang, with configurable fallback
 * endpoints.
 *
 * The lookup sits on the critical join path and Mojang rate limits it, so
 * results are cached aggressively. A cached PREMIUM that has gone stale is
 * harmless, since the worst outcome is asking a renamed player to
 * authenticate. A cached CRACKED that has gone stale is corrected the next
 * time the cache entry expires.
 *
 * Endpoint failures escalate to the next configured endpoint. If all of
 * them fail the result is UNKNOWN, never CRACKED.
 */
public final class MojangPremiumResolver implements PremiumResolver {

    private final HttpClient httpClient;
    private final IdentityCache cache;
    private final List<String> endpoints;
    private final Duration timeout;
    private final Executor executor;

    public MojangPremiumResolver(IdentityCache cache, List<String> endpoints, Duration timeout, Executor executor) {
        if (endpoints == null || endpoints.isEmpty()) {
            throw new IllegalArgumentException("at least one premium lookup endpoint must be configured");
        }
        this.cache = cache;
        this.endpoints = List.copyOf(endpoints);
        this.timeout = timeout;
        this.executor = executor;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .executor(executor)
                .build();
    }

    @Override
    public CompletableFuture<PremiumStatus> resolve(String username) {
        Optional<String> cached = cache.getPremiumStatus(username);
        if (cached.isPresent()) {
            try {
                return CompletableFuture.completedFuture(PremiumStatus.valueOf(cached.get()));
            } catch (IllegalArgumentException corrupted) {
                cache.putPremiumStatus(username, PremiumStatus.UNKNOWN.name());
            }
        }
        return queryEndpoint(username, 0).thenApply(status -> {
            if (status != PremiumStatus.UNKNOWN) {
                cache.putPremiumStatus(username, status.name());
            }
            return status;
        });
    }

    private CompletableFuture<PremiumStatus> queryEndpoint(String username, int index) {
        if (index >= endpoints.size()) {
            return CompletableFuture.completedFuture(PremiumStatus.UNKNOWN);
        }
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoints.get(index) + java.net.URLEncoder.encode(username,
                            java.nio.charset.StandardCharsets.UTF_8)))
                    .timeout(timeout)
                    .header("User-Agent", "CodeverseAuth")
                    .GET()
                    .build();
        } catch (IllegalArgumentException malformedEndpoint) {
            return queryEndpoint(username, index + 1);
        }

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(response -> {
                    int code = response.statusCode();
                    if (code == 200 && !response.body().isBlank()) {
                        return CompletableFuture.completedFuture(PremiumStatus.PREMIUM);
                    }
                    // 204 and 404 are both "no such paid account" across the
                    // endpoints in use, and are the only positive evidence
                    // that a name may be treated as cracked.
                    if (code == 204 || code == 404) {
                        return CompletableFuture.completedFuture(PremiumStatus.CRACKED);
                    }
                    return queryEndpoint(username, index + 1);
                })
                .exceptionallyCompose(failure -> queryEndpoint(username, index + 1));
    }
}
