package net.codeverse.storage;

import net.codeverse.api.identity.TrustTier;
import net.codeverse.identity.Identity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LinkStorageTest {

    private Database database;
    private AccountRepository accounts;
    private LinkCodeRepository codes;

    @BeforeEach
    void setUp() {
        database = TestDatabase.openOrSkip("test_link_");
        accounts = new AccountRepository(database);
        codes = new LinkCodeRepository(database);
    }

    @AfterEach
    void tearDown() {
        TestDatabase.drop(database);
    }

    private UUID account(String username, TrustTier tier) throws SQLException {
        UUID internalId = UUID.randomUUID();
        accounts.createAccount(new Identity(internalId, UUID.randomUUID(), username, tier, 0L, 0L, false));
        return internalId;
    }

    @Test
    @DisplayName("a code is redeemable exactly once")
    void codeIsSingleUse() throws SQLException {
        UUID internalId = account("Elchi", TrustTier.CRACKED);
        String code = codes.issue(internalId, 8, 60_000L);

        assertEquals(Optional.of(internalId), codes.redeem(code));
        assertEquals(Optional.empty(), codes.redeem(code), "a redeemed code must not work twice");
    }

    @Test
    @DisplayName("issuing a second code invalidates the first")
    void reissueInvalidatesPrevious() throws SQLException {
        UUID internalId = account("Script", TrustTier.CRACKED);
        String first = codes.issue(internalId, 8, 60_000L);
        String second = codes.issue(internalId, 8, 60_000L);

        assertNotEquals(first, second);
        assertEquals(Optional.empty(), codes.redeem(first), "the abandoned code must stop working");
        assertEquals(Optional.of(internalId), codes.redeem(second));
    }

    @Test
    @DisplayName("an expired code cannot be redeemed")
    void expiredCodeIsRefused() throws SQLException {
        UUID internalId = account("Tomy", TrustTier.CRACKED);
        String code = codes.issue(internalId, 8, -1_000L);

        assertEquals(Optional.empty(), codes.redeem(code));
    }

    @Test
    @DisplayName("codes avoid characters that are misread")
    void alphabetExcludesAmbiguousCharacters() throws SQLException {
        UUID internalId = account("Reader", TrustTier.CRACKED);
        Set<Character> forbidden = Set.of('O', '0', 'I', 'l', '1');
        for (int i = 0; i < 40; i++) {
            String code = codes.issue(internalId, 10, 60_000L);
            for (char character : code.toCharArray()) {
                assertFalse(forbidden.contains(character), "code contained an ambiguous character: " + code);
            }
        }
    }

    /**
     * The property that matters most here. Two bots redeeming the same code
     * simultaneously must produce exactly one link, and the conditional
     * update is what guarantees it. A read followed by a write would pass
     * every single threaded test and fail exactly here.
     */
    @Test
    @DisplayName("concurrent redemption of one code succeeds exactly once")
    void concurrentRedemptionYieldsOneWinner() throws Exception {
        UUID internalId = account("Contended", TrustTier.CRACKED);
        String code = codes.issue(internalId, 8, 60_000L);

        int racers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(racers);
        try {
            List<Callable<Optional<UUID>>> attempts = java.util.Collections.nCopies(racers, () -> codes.redeem(code));
            List<Future<Optional<UUID>>> results = pool.invokeAll(attempts);
            long winners = results.stream().filter(future -> {
                try {
                    return future.get().isPresent();
                } catch (Exception failure) {
                    return false;
                }
            }).count();
            assertEquals(1L, winners, "exactly one caller may redeem a code");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("purging discards expired and redeemed codes")
    void purgeRemovesSpentCodes() throws SQLException {
        UUID live = account("Live", TrustTier.CRACKED);
        UUID spent = account("Spent", TrustTier.CRACKED);
        UUID stale = account("Stale", TrustTier.CRACKED);

        String liveCode = codes.issue(live, 8, 60_000L);
        String spentCode = codes.issue(spent, 8, 60_000L);
        codes.issue(stale, 8, -1_000L);
        codes.redeem(spentCode);

        assertEquals(2, codes.purgeExpired());
        assertEquals(Optional.of(live), codes.redeem(liveCode), "a live code must survive a purge");
    }

    @Test
    @DisplayName("a link applies to every account belonging to the person")
    void linkAppliesAcrossLinkedAccounts() throws SQLException {
        UUID internalId = UUID.randomUUID();
        UUID java = UUID.randomUUID();
        UUID bedrock = UUID.randomUUID();
        accounts.createAccount(new Identity(internalId, java, "Elchi", TrustTier.PREMIUM, 0L, 0L, false));
        accounts.createAccount(new Identity(internalId, bedrock, ".ElchiBR", TrustTier.BEDROCK, 0L, 0L, false));

        assertEquals(2, accounts.setDiscordId(internalId, "998877"));

        List<AccountRepository.StoredAccount> all = accounts.findAllByInternalId(internalId);
        assertEquals(2, all.size());
        assertTrue(all.stream().allMatch(AccountRepository.StoredAccount::hasDiscordLink),
                "a link belongs to the person, not to one of their accounts");
        assertEquals(Set.of("Elchi", ".ElchiBR"),
                all.stream().map(AccountRepository.StoredAccount::username).collect(Collectors.toSet()));
    }

    /**
     * Without the conditional argument, linking Discord would move a premium
     * account down the ladder to DISCORD_LINKED. The guard lives in SQL
     * rather than in the caller so no future caller can forget it.
     */
    @Test
    @DisplayName("promotion touches cracked accounts and leaves premium ones alone")
    void promotionIsConditional() throws SQLException {
        UUID crackedId = account("Newcomer", TrustTier.CRACKED);
        UUID premiumId = account("Paid", TrustTier.PREMIUM);

        assertEquals(1, accounts.setTierForIdentity(crackedId, TrustTier.DISCORD_LINKED, TrustTier.CRACKED));
        assertEquals(0, accounts.setTierForIdentity(premiumId, TrustTier.DISCORD_LINKED, TrustTier.CRACKED));

        assertEquals(TrustTier.DISCORD_LINKED, accounts.findByInternalId(crackedId).orElseThrow().tier());
        assertEquals(TrustTier.PREMIUM, accounts.findByInternalId(premiumId).orElseThrow().tier(),
                "a premium account must never be demoted by linking Discord");
    }

    @Test
    @DisplayName("an account can be found by its Discord id and released again")
    void discordLookupAndClear() throws SQLException {
        UUID internalId = account("Linked", TrustTier.CRACKED);
        accounts.setDiscordId(internalId, "424242");

        assertEquals(internalId, accounts.findByDiscordId("424242").orElseThrow().internalId());
        assertEquals(Optional.empty(), accounts.findByDiscordId("000000"));

        assertEquals(1, accounts.clearDiscordId("424242"));
        assertNull(accounts.findByInternalId(internalId).orElseThrow().discordId());
    }

    /**
     * applySchema runs unconditionally at every boot, so it has to be safe to
     * run against a database it has already migrated.
     */
    @Test
    @DisplayName("schema application is idempotent")
    void schemaIsIdempotent() throws SQLException {
        UUID internalId = account("Survivor", TrustTier.PREMIUM);
        database.applySchema();
        database.applySchema();

        assertEquals("Survivor", accounts.findByInternalId(internalId).orElseThrow().username(),
                "existing rows must survive a re-applied schema");
    }
}
