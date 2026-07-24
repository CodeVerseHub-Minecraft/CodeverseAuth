package net.codeverse.apiimpl;

import net.codeverse.api.event.CodeverseEvent;
import net.codeverse.api.event.IdentityLinkedEvent;
import net.codeverse.api.event.IdentityUnlinkedEvent;
import net.codeverse.api.event.TrustTierChangedEvent;
import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.TrustTier;
import net.codeverse.api.link.LinkCode;
import net.codeverse.cache.IdentityCache;
import net.codeverse.config.PluginConfig;
import net.codeverse.storage.AccountRepository;
import net.codeverse.storage.Database;
import net.codeverse.storage.LinkCodeRepository;
import net.codeverse.storage.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The link service against real storage.
 *
 * The tier rules are the reason these run against a database rather than a
 * substitute: promotion and demotion are conditional updates whose row count
 * decides whether an event is published, and that is a property of the SQL.
 */
class AuthLinkServiceTest {

    private Database database;
    private AccountRepository accounts;
    private AuthLinkService links;
    private AuthEventBus events;
    private IdentityCache cache;
    private ExecutorService executor;
    private final List<CodeverseEvent> published = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        database = TestDatabase.openOrSkip("test_svc_");
        accounts = new AccountRepository(database);
        LinkCodeRepository codes = new LinkCodeRepository(database);

        PluginConfig.Redis redisSettings = new PluginConfig.Redis();
        redisSettings.enabled = false;
        cache = new IdentityCache(redisSettings);

        events = new AuthEventBus(LoggerFactory.getLogger("test"));
        events.subscribe(this, CodeverseEvent.class, published::add);

        executor = Executors.newVirtualThreadPerTaskExecutor();
        links = new AuthLinkService(accounts, codes, cache, events, executor, 8);
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

    private UUID account(String username, TrustTier tier) throws SQLException {
        UUID internalId = UUID.randomUUID();
        accounts.createAccount(new net.codeverse.identity.Identity(
                internalId, UUID.randomUUID(), username, tier, 0L, 0L, false));
        return internalId;
    }

    private <T> List<T> eventsOf(Class<T> type) {
        return published.stream().filter(type::isInstance).map(type::cast).toList();
    }

    @Test
    @DisplayName("redeeming links the account and promotes it out of cracked")
    void redeemPromotesCracked() throws Exception {
        UUID internalId = account("Newcomer", TrustTier.CRACKED);
        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();

        Optional<Identity> linked = links.redeem(code.code(), "998877").get();

        assertTrue(linked.isPresent());
        assertEquals(TrustTier.DISCORD_LINKED, linked.get().tier());
        assertEquals(Optional.of("998877"), linked.get().discordId(),
                "the contract requires the post link state, not the state before it");

        assertEquals(1, eventsOf(IdentityLinkedEvent.class).size());
        List<TrustTierChangedEvent> promotions = eventsOf(TrustTierChangedEvent.class);
        assertEquals(1, promotions.size());
        assertEquals(TrustTier.CRACKED, promotions.get(0).previous());
        assertEquals(TrustTier.DISCORD_LINKED, promotions.get(0).current());
        assertTrue(promotions.get(0).isPromotion());
    }

    /**
     * The case the conditional update exists for. DISCORD_LINKED sits below
     * PREMIUM, so an unconditional write here would take a paying player's
     * tier away as a reward for linking their Discord.
     */
    @Test
    @DisplayName("linking never demotes a premium account")
    void redeemDoesNotDemotePremium() throws Exception {
        UUID internalId = account("Paid", TrustTier.PREMIUM);
        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();

        Optional<Identity> linked = links.redeem(code.code(), "112233").get();

        assertTrue(linked.isPresent());
        assertEquals(TrustTier.PREMIUM, linked.get().tier(), "a premium account must keep its tier");
        assertEquals(Optional.of("112233"), linked.get().discordId(), "but it must still be linked");

        assertEquals(1, eventsOf(IdentityLinkedEvent.class).size());
        assertTrue(eventsOf(TrustTierChangedEvent.class).isEmpty(),
                "no tier changed, so no tier change event belongs on the bus");
    }

    @Test
    @DisplayName("unknown, expired and spent codes are one outcome")
    void failedRedemptionsAreIndistinguishable() throws Exception {
        UUID internalId = account("Someone", TrustTier.CRACKED);
        LinkCode spent = links.issueCode(internalId, Duration.ofMinutes(5)).get();
        links.redeem(spent.code(), "1").get();
        published.clear();

        assertEquals(Optional.empty(), links.redeem(spent.code(), "2").get(), "already redeemed");
        assertEquals(Optional.empty(), links.redeem("NOTACODE", "2").get(), "never existed");
        assertTrue(published.isEmpty(), "a failed redemption must not publish anything");
    }

    @Test
    @DisplayName("a link reaches every account belonging to the person")
    void linkAppliesToAllAccounts() throws Exception {
        UUID internalId = UUID.randomUUID();
        accounts.createAccount(new net.codeverse.identity.Identity(
                internalId, UUID.randomUUID(), "Elchi", TrustTier.CRACKED, 0L, 0L, false));
        accounts.createAccount(new net.codeverse.identity.Identity(
                internalId, UUID.randomUUID(), ".ElchiBR", TrustTier.CRACKED, 0L, 0L, false));

        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();
        links.redeem(code.code(), "555").get();

        List<AccountRepository.StoredAccount> all = accounts.findAllByInternalId(internalId);
        assertEquals(2, all.size());
        assertTrue(all.stream().allMatch(AccountRepository.StoredAccount::hasDiscordLink));
        assertTrue(all.stream().allMatch(account -> account.tier() == TrustTier.DISCORD_LINKED),
                "a restriction or promotion follows the person, not one of their accounts");
    }

    @Test
    @DisplayName("unlinking removes the link and reverses the promotion")
    void unlinkReversesPromotion() throws Exception {
        UUID internalId = account("Leaver", TrustTier.CRACKED);
        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();
        links.redeem(code.code(), "777").get();
        published.clear();

        assertTrue(links.unlinkByDiscordId("777").get());

        AccountRepository.StoredAccount after = accounts.findByInternalId(internalId).orElseThrow();
        assertFalse(after.hasDiscordLink());
        assertEquals(TrustTier.CRACKED, after.tier());
        assertEquals(1, eventsOf(IdentityUnlinkedEvent.class).size());
        assertEquals(1, eventsOf(TrustTierChangedEvent.class).size());
    }

    @Test
    @DisplayName("unlinking a premium account leaves its tier alone")
    void unlinkDoesNotDemotePremium() throws Exception {
        UUID internalId = account("StillPaid", TrustTier.PREMIUM);
        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();
        links.redeem(code.code(), "888").get();
        published.clear();

        assertTrue(links.unlink(internalId).get());

        assertEquals(TrustTier.PREMIUM, accounts.findByInternalId(internalId).orElseThrow().tier());
        assertTrue(eventsOf(TrustTierChangedEvent.class).isEmpty());
    }

    @Test
    @DisplayName("unlinking something that is not linked reports it rather than pretending")
    void unlinkOfUnlinkedIsFalse() throws Exception {
        UUID internalId = account("Unlinked", TrustTier.CRACKED);

        assertFalse(links.unlink(internalId).get());
        assertFalse(links.unlinkByDiscordId("does-not-exist").get());
    }

    @Test
    @DisplayName("the linked discord id can be read back")
    void discordIdIsReadable() throws Exception {
        UUID internalId = account("Readable", TrustTier.CRACKED);
        assertEquals(Optional.empty(), links.discordIdOf(internalId).get());

        LinkCode code = links.issueCode(internalId, Duration.ofMinutes(5)).get();
        links.redeem(code.code(), "343434").get();

        assertEquals(Optional.of("343434"), links.discordIdOf(internalId).get());
    }
}
