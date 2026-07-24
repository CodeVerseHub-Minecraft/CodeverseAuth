package net.codeverse.apiimpl;

import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.IdentityService;
import net.codeverse.cache.IdentityCache;
import net.codeverse.cache.IdentityPayloadCodec;
import net.codeverse.storage.AccountRepository;

import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;

/**
 * The proxy's implementation of the API identity contract.
 *
 * Lookups read storage rather than trusting the shared cache, because the
 * cache is a performance layer for placeholders and not a source of truth:
 * a lookup that decides anything reads the row. Successful lookups refresh
 * the cache on the way out so the cached view converges on reality without
 * a separate maintenance path.
 *
 * The contract's distinction between empty and exceptional completion is
 * load bearing here. Empty means the account does not exist; a storage
 * failure completes exceptionally, so a consumer cannot mistake an outage
 * for an absence and make an authorisation decision on it.
 */
public final class AuthIdentityService implements IdentityService {

    private final AccountRepository accounts;
    private final IdentityCache cache;
    private final ExecutorService executor;

    // Health is observed from real operations rather than probed, so the
    // flag can never disagree with what callers are actually experiencing.
    private volatile boolean storageHealthy = true;

    public AuthIdentityService(AccountRepository accounts, IdentityCache cache, ExecutorService executor) {
        this.accounts = accounts;
        this.cache = cache;
        this.executor = executor;
    }

    @Override
    public CompletableFuture<Optional<Identity>> byMinecraftId(UUID minecraftId) {
        return async(() -> accounts.findByMinecraftId(minecraftId).map(this::toApiAndCache));
    }

    @Override
    public CompletableFuture<Optional<Identity>> byUsername(String username) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return async(() -> accounts.findByUsername(username).map(this::toApiAndCache));
    }

    @Override
    public CompletableFuture<Optional<Identity>> byInternalId(UUID internalId) {
        return async(() -> accounts.findByInternalId(internalId).map(this::toApiAndCache));
    }

    @Override
    public CompletableFuture<Optional<Identity>> byDiscordId(String discordId) {
        if (discordId == null || discordId.isBlank()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return async(() -> accounts.findByDiscordId(discordId).map(this::toApiAndCache));
    }

    @Override
    public CompletableFuture<List<Identity>> linkedAccounts(UUID internalId) {
        return async(() -> accounts.findAllByInternalId(internalId).stream()
                .map(this::toApiAndCache)
                .toList());
    }

    @Override
    public Optional<Identity> cachedByMinecraftId(UUID minecraftId) {
        // Local layer only. This is the one method the contract permits on a
        // server thread, and a Redis read is a socket round trip.
        return cache.getIdentityLocal(minecraftId.toString())
                .flatMap(IdentityPayloadCodec::decode);
    }

    @Override
    public CompletableFuture<Void> preload(Collection<UUID> minecraftIds) {
        if (minecraftIds == null || minecraftIds.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }
        return async(() -> {
            for (UUID minecraftId : minecraftIds) {
                accounts.findByMinecraftId(minecraftId).ifPresent(this::toApiAndCache);
            }
            return null;
        });
    }

    @Override
    public void invalidate(UUID minecraftId) {
        cache.invalidateIdentity(minecraftId.toString());
    }

    @Override
    public boolean isLinkageAvailable() {
        return storageHealthy;
    }

    private Identity toApiAndCache(AccountRepository.StoredAccount stored) {
        Identity identity = ApiIdentities.toApi(stored);
        cache.putIdentity(identity.minecraftId().toString(), IdentityPayloadCodec.encode(identity));
        return identity;
    }

    private <T> CompletableFuture<T> async(SqlWork<T> work) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                T result = work.call();
                storageHealthy = true;
                return result;
            } catch (SQLException failure) {
                storageHealthy = false;
                throw new CompletionException(failure);
            }
        }, executor);
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T call() throws SQLException;
    }
}
