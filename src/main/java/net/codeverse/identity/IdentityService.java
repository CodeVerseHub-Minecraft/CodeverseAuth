package net.codeverse.identity;

import net.codeverse.api.identity.TrustTier;
import net.codeverse.cache.IdentityCache;
import net.codeverse.cache.IdentityPayloadCodec;
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

    private final AccountRepository accounts;
    private final IdentityCache cache;

    public IdentityService(AccountRepository accounts, IdentityCache cache) {
        this.accounts = accounts;
        this.cache = cache;
    }

    /**
     * Returns the stored identity for this connection, registering a new one
     * when the account has never been seen. The tier is taken from the live
     * connection, reconciled with storage by {@link #reconcileTier}, so an
     * account can neither retain a verified tier it no longer qualifies for
     * nor lose a linked tier that only storage can know about.
     */
    public Identity resolve(UUID minecraftId, String username, TrustTier tier) throws SQLException {
        Optional<AccountRepository.StoredAccount> existing = accounts.findByMinecraftId(minecraftId);
        if (existing.isPresent()) {
            AccountRepository.StoredAccount stored = existing.get();
            Identity identity = new Identity(
                    stored.internalId(),
                    stored.minecraftId(),
                    username,
                    reconcileTier(tier, stored.tier()),
                    stored.registeredAt(),
                    stored.lastLoginAt(),
                    stored.hasTotp());
            cacheIdentity(identity, stored.discordId());
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
        cacheIdentity(created, null);
        return created;
    }

    /**
     * What the connection proves wins, with one exception that only storage
     * can supply.
     *
     * PREMIUM and BEDROCK are properties of the live connection: Mojang's
     * session servers verified the one, Floodgate verified the other, and
     * taking either from a database row would mean a stale row grants a
     * verification that did not happen. DISCORD_LINKED is the opposite: it
     * cannot be observed on the wire at all, only in the row the redeemed
     * link code wrote. Without this exception a linked player would be
     * demoted back to CRACKED on every login and the promotion the whole
     * linking flow exists to grant would last exactly one session.
     */
    static TrustTier reconcileTier(TrustTier connection, TrustTier stored) {
        if (connection == TrustTier.CRACKED && stored == TrustTier.DISCORD_LINKED) {
            return TrustTier.DISCORD_LINKED;
        }
        return connection;
    }

    public Optional<AccountRepository.StoredAccount> stored(UUID minecraftId) throws SQLException {
        return accounts.findByMinecraftId(minecraftId);
    }

    public void invalidate(UUID minecraftId) {
        cache.invalidateIdentity(minecraftId.toString());
    }

    private void cacheIdentity(Identity identity, String discordId) {
        cache.putIdentity(identity.minecraftId().toString(), IdentityPayloadCodec.encode(
                identity.internalId(),
                identity.minecraftId(),
                identity.username(),
                identity.tier(),
                identity.registeredAt(),
                identity.lastLoginAt(),
                identity.totpEnrolled(),
                discordId));
    }
}
