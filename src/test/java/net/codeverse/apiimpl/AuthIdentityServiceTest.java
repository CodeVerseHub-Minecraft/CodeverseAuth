package net.codeverse.apiimpl;

import net.codeverse.api.event.CodeverseEvent;
import net.codeverse.api.event.EventBus;
import net.codeverse.api.event.IdentityLinkedEvent;
import net.codeverse.api.event.TrustTierChangedEvent;
import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.TrustTier;
import net.codeverse.cache.IdentityCache;
import net.codeverse.cache.IdentityPayloadCodec;
import net.codeverse.config.PluginConfig;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.Database;
import net.codeverse.storage.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthIdentityServiceTest {

    private Database database;
    private AccountRepository accounts;
    private AuthIdentityService identities;
    private IdentityCache cache;
    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        database = TestDatabase.openOrSkip("test_ident_");
        accounts = new AccountRepository(database);

        PluginConfig.Redis redisSettings = new PluginConfig.Redis();
        redisSettings.enabled = false;
        cache = new IdentityCache(redisSettings);

        executor = Executors.newVirtualThreadPerTaskExecutor();
        identities = new AuthIdentityService(accounts, cache, executor);
    }

    @AfterEach
    void tearDown() {
        if (executor != null) {
            executor.shutdownNow();
        }
        if (cache != null) {
            cache.close();
        }
        TestDatabase.drop(database);
    }

    private UUID create(UUID internalId, String username, TrustTier tier) throws SQLException {
        UUID minecraftId = UUID.randomUUID();
        accounts.createAccount(new net.codeverse.identity.Identity(
                internalId, minecraftId, username, tier, 0L, 0L, false));
        return minecraftId;
    }

    @Test
    @DisplayName("an account resolves by uuid, name and internal id")
    void lookupsAgree() throws Exception {
        UUID internalId = UUID.randomUUID();
        UUID minecraftId = create(internalId, "Elchi", TrustTier.PREMIUM);

        Identity byUuid = identities.byMinecraftId(minecraftId).get().orElseThrow();
        Identity byName = identities.byUsername("Elchi").get().orElseThrow();
        Identity byInternal = identities.byInternalId(internalId).get().orElseThrow();

        assertEquals(internalId, byUuid.internalId());
        assertEquals(byUuid, byName);
        assertEquals(byUuid, byInternal);
        assertEquals(TrustTier.PREMIUM, byUuid.tier());
    }

    /**
     * The case the internal id exists for: two accounts, one person. A
     * consumer keying on the Minecraft uuid would see two players here and
     * a restriction on one would be shed by connecting with the other.
     */
    @Test
    @DisplayName("linked java and bedrock accounts resolve to one person")
    void linkedAccountsShareAnIdentity() throws Exception {
        UUID internalId = UUID.randomUUID();
        UUID java = create(internalId, "Elchi", TrustTier.PREMIUM);
        UUID bedrock = create(internalId, ".ElchiBR", TrustTier.BEDROCK);

        Identity fromJava = identities.byMinecraftId(java).get().orElseThrow();
        Identity fromBedrock = identities.byMinecraftId(bedrock).get().orElseThrow();

        assertEquals(fromJava.internalId(), fromBedrock.internalId(), "one person");
        assertFalse(fromJava.minecraftId().equals(fromBedrock.minecraftId()), "two accounts");

        List<Identity> all = identities.linkedAccounts(internalId).get();
        assertEquals(2, all.size());
    }

    @Test
    @DisplayName("an absent account completes empty rather than exceptionally")
    void unknownAccountIsEmpty() throws Exception {
        assertEquals(Optional.empty(), identities.byMinecraftId(UUID.randomUUID()).get());
        assertEquals(Optional.empty(), identities.byUsername("NobodyHere").get());
        assertEquals(Optional.empty(), identities.byDiscordId("000").get());
    }

    /**
     * Empty means absent, an exception means unanswerable. Conflating them is
     * how a storage outage silently becomes an authorisation decision, so a
     * closed pool must not look like a missing account.
     */
    @Test
    @DisplayName("a storage failure completes exceptionally and is reported as degraded")
    void storageFailureIsNotAnAbsence() {
        database.close();

        assertThrows(ExecutionException.class, () -> identities.byMinecraftId(UUID.randomUUID()).get());
        assertFalse(identities.isLinkageAvailable(),
                "consumers relying on linkage must be able to see that it is unavailable");
    }

    @Test
    @DisplayName("a resolved lookup populates the cached view")
    void lookupWarmsTheCache() throws Exception {
        UUID internalId = UUID.randomUUID();
        UUID minecraftId = create(internalId, "Cached", TrustTier.PREMIUM);

        assertEquals(Optional.empty(), identities.cachedByMinecraftId(minecraftId));
        identities.byMinecraftId(minecraftId).get();

        Identity cached = identities.cachedByMinecraftId(minecraftId).orElseThrow();
        assertEquals(internalId, cached.internalId());
        assertEquals(Optional.of(TrustTier.PREMIUM), identities.cachedTier(minecraftId));

        identities.invalidate(minecraftId);
        assertEquals(Optional.empty(), identities.cachedByMinecraftId(minecraftId),
                "an invalidated entry must force the next lookup to read storage");
    }

    @Test
    @DisplayName("preload warms several accounts at once")
    void preloadWarmsEverythingAsked() throws Exception {
        UUID first = create(UUID.randomUUID(), "First", TrustTier.CRACKED);
        UUID second = create(UUID.randomUUID(), "Second", TrustTier.CRACKED);

        identities.preload(List.of(first, second)).get();

        assertTrue(identities.cachedByMinecraftId(first).isPresent());
        assertTrue(identities.cachedByMinecraftId(second).isPresent());
    }

    @Test
    @DisplayName("an unknown account never satisfies a trust requirement")
    void isAtLeastFailsClosed() throws Exception {
        UUID minecraftId = create(UUID.randomUUID(), "Cracked", TrustTier.CRACKED);

        assertTrue(identities.isAtLeast(minecraftId, TrustTier.CRACKED).get());
        assertFalse(identities.isAtLeast(minecraftId, TrustTier.PREMIUM).get());
        assertFalse(identities.isAtLeast(UUID.randomUUID(), TrustTier.CRACKED).get(),
                "an account that cannot be resolved must not clear the lowest bar either");
    }
}

class AuthEventBusTest {

    private final AuthEventBus bus = new AuthEventBus(LoggerFactory.getLogger("test"));

    private static Identity identity(TrustTier tier) {
        return Identity.builder(UUID.randomUUID(), UUID.randomUUID(), "Someone", tier).build();
    }

    private static IdentityLinkedEvent linked() {
        return new IdentityLinkedEvent(identity(TrustTier.DISCORD_LINKED), "1", Instant.now(), false);
    }

    @Test
    @DisplayName("a listener receives only the type it subscribed to")
    void deliveryIsTyped() {
        List<CodeverseEvent> linkedSeen = new CopyOnWriteArrayList<>();
        List<CodeverseEvent> tierSeen = new CopyOnWriteArrayList<>();
        bus.subscribe(this, IdentityLinkedEvent.class, linkedSeen::add);
        bus.subscribe(this, TrustTierChangedEvent.class, tierSeen::add);

        bus.publish(linked());

        assertEquals(1, linkedSeen.size());
        assertTrue(tierSeen.isEmpty());
    }

    @Test
    @DisplayName("closing a subscription stops delivery")
    void closingUnsubscribes() {
        AtomicInteger count = new AtomicInteger();
        EventBus.Subscription subscription = bus.subscribe(this, IdentityLinkedEvent.class, event -> count.incrementAndGet());

        bus.publish(linked());
        assertTrue(subscription.isActive());
        subscription.close();
        bus.publish(linked());

        assertEquals(1, count.get());
        assertFalse(subscription.isActive());
    }

    @Test
    @DisplayName("a plugin can drop every listener it registered")
    void bulkUnsubscribe() {
        Object plugin = new Object();
        AtomicInteger count = new AtomicInteger();
        bus.subscribe(plugin, IdentityLinkedEvent.class, event -> count.incrementAndGet());
        bus.subscribe(plugin, IdentityLinkedEvent.class, event -> count.incrementAndGet());

        bus.unsubscribeAll(plugin);
        bus.publish(linked());

        assertEquals(0, count.get());
        assertEquals(0, bus.registrationCount());
    }

    /**
     * One broken consumer must not be able to suppress events for every
     * other, which is what would happen if a thrown exception propagated out
     * of publish.
     */
    @Test
    @DisplayName("a listener that throws is removed and the rest still receive")
    void throwingListenerIsIsolated() {
        AtomicInteger healthy = new AtomicInteger();
        bus.subscribe(this, IdentityLinkedEvent.class, event -> {
            throw new IllegalStateException("deliberate");
        });
        bus.subscribe(this, IdentityLinkedEvent.class, event -> healthy.incrementAndGet());

        bus.publish(linked());
        bus.publish(linked());

        assertEquals(2, healthy.get(), "the working listener keeps receiving");
        assertEquals(1, bus.registrationCount(), "the broken one is gone");
    }
}

class IdentityPayloadCodecTest {

    @Test
    @DisplayName("an encoded identity survives a round trip")
    void roundTrip() {
        Identity original = Identity.builder(UUID.randomUUID(), UUID.randomUUID(), "Elchi", TrustTier.DISCORD_LINKED)
                .registeredAtMillis(1_700_000_000_000L)
                .lastLoginAtMillis(1_800_000_000_000L)
                .totpEnrolled(true)
                .discordId("998877")
                .build();

        Identity decoded = IdentityPayloadCodec.decode(IdentityPayloadCodec.encode(original)).orElseThrow();

        assertEquals(original, decoded);
    }

    @Test
    @DisplayName("an unlinked identity round trips without inventing a discord id")
    void roundTripWithoutDiscord() {
        Identity original = Identity.builder(UUID.randomUUID(), UUID.randomUUID(), "~Guest", TrustTier.CRACKED).build();

        Identity decoded = IdentityPayloadCodec.decode(IdentityPayloadCodec.encode(original)).orElseThrow();

        assertEquals(Optional.empty(), decoded.discordId());
        assertEquals(Optional.empty(), decoded.registeredAt());
    }

    /**
     * Entries written by v0.1.0 lack the fields the API needs. Treating them
     * as a miss sends the caller to storage, which is the right answer;
     * throwing would turn a stale cache entry into a failed lookup.
     */
    @Test
    @DisplayName("an unreadable or outdated payload reads as a cache miss")
    void unreadablePayloadIsAMiss() {
        assertEquals(Optional.empty(), IdentityPayloadCodec.decode(null));
        assertEquals(Optional.empty(), IdentityPayloadCodec.decode(""));
        assertEquals(Optional.empty(), IdentityPayloadCodec.decode("not json at all"));
        assertEquals(Optional.empty(), IdentityPayloadCodec.decode(
                "{\"internalId\":\"" + UUID.randomUUID() + "\",\"username\":\"Old\",\"tier\":\"PREMIUM\"}"),
                "a v0.1.0 entry has no minecraftId and cannot be decoded");
        assertEquals(Optional.empty(), IdentityPayloadCodec.decode(
                "{\"internalId\":\"" + UUID.randomUUID() + "\",\"minecraftId\":\"" + UUID.randomUUID()
                        + "\",\"username\":\"Future\",\"tier\":\"SOMETHING_NEW\"}"),
                "a tier from a newer release is not guessed at");
    }

    @Test
    @DisplayName("the encoded payload carries no secret")
    void payloadCarriesNoSecret() {
        String encoded = IdentityPayloadCodec.encode(
                Identity.builder(UUID.randomUUID(), UUID.randomUUID(), "Elchi", TrustTier.PREMIUM)
                        .totpEnrolled(true)
                        .build());

        assertNotNull(encoded);
        assertFalse(encoded.contains("password"));
        assertFalse(encoded.contains("secret"));
        assertFalse(encoded.contains("hash"));
    }
}
