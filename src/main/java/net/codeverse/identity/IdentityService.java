package net.codeverse.identity;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import net.codeverse.cache.IdentityCache;
import net.codeverse.storage.AccountRepository;

import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

/**
 * Resolves the internal identity for a connection, creating one on first
 * sight.
 *
 * The internal id is generated once per account and never derived from the
 * Minecraft uuid, so linking several accounts to one identity later is a
 * matter of repointing rows rather than migrating keys.
 */
public final class IdentityService {

    private static final Gson GSON = new Gson();

    private final AccountRepository accounts;
    private final IdentityCache cache;

    public IdentityService(AccountRepository accounts, IdentityCache cache) {
        this.accounts = accounts;
        this.cache = cache;
    }

    /**
     * Returns the stored identity for this connection, registering a new one
     * when the account has never been seen. The tier is always taken from
     * the live connection rather than from storage, so an account cannot
     * retain a trusted tier it no longer qualifies for.
     */
    public Identity resolve(UUID minecraftId, String username, TrustTier tier) throws SQLException {
        Optional<AccountRepository.StoredAccount> existing = accounts.findByMinecraftId(minecraftId);
        if (existing.isPresent()) {
            AccountRepository.StoredAccount stored = existing.get();
            Identity identity = new Identity(
                    stored.internalId(),
                    stored.minecraftId(),
                    username,
                    tier,
                    stored.registeredAt(),
                    stored.lastLoginAt(),
                    stored.hasTotp());
            cacheIdentity(identity);
            return identity;
        }

        Identity created = new Identity(
                UUID.randomUUID(),
                minecraftId,
                username,
                tier,
                0L,
                0L,
                false);
        accounts.createAccount(created);
        cacheIdentity(created);
        return created;
    }

    public Optional<AccountRepository.StoredAccount> stored(UUID minecraftId) throws SQLException {
        return accounts.findByMinecraftId(minecraftId);
    }

    public void invalidate(UUID minecraftId) {
        cache.invalidateIdentity(minecraftId.toString());
    }

    private void cacheIdentity(Identity identity) {
        JsonObject payload = new JsonObject();
        payload.addProperty("internalId", identity.internalId().toString());
        payload.addProperty("username", identity.username());
        payload.addProperty("tier", identity.tier().name());
        payload.addProperty("registeredAt", identity.registeredAt());
        cache.putIdentity(identity.minecraftId().toString(), GSON.toJson(payload));
    }
}
