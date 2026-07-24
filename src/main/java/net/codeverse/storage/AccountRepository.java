package net.codeverse.storage;

import net.codeverse.identity.Identity;
import net.codeverse.api.identity.TrustTier;

import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * All account persistence.
 *
 * Every statement is parameterised. Usernames are matched on a lowercase
 * column with a unique index so two accounts cannot differ only by case,
 * which would otherwise let someone register a visually identical name.
 */
public final class AccountRepository {

    private static final String SELECT_COLUMNS =
            "SELECT minecraft_id, internal_id, username, tier, password_hash, totp_secret, "
                    + "registered_at, last_login_at, discord_id FROM ";

    private final Database database;

    public AccountRepository(Database database) {
        this.database = database;
    }

    public Optional<StoredAccount> findByMinecraftId(UUID minecraftId) throws SQLException {
        String sql = SELECT_COLUMNS + database.table("accounts") + " WHERE minecraft_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, toBytes(minecraftId));
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? Optional.of(read(results)) : Optional.empty();
            }
        }
    }

    public Optional<StoredAccount> findByUsername(String username) throws SQLException {
        String sql = SELECT_COLUMNS + database.table("accounts") + " WHERE username_lower = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username.toLowerCase(Locale.ROOT));
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? Optional.of(read(results)) : Optional.empty();
            }
        }
    }

    /**
     * Inserts the identity and account rows for a first time connection.
     * Uses INSERT IGNORE on the identity row so a race between two proxies
     * resolves to one identity rather than throwing.
     */
    public void createAccount(Identity identity) throws SQLException {
        long now = System.currentTimeMillis();
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT IGNORE INTO " + database.table("identities")
                                + " (internal_id, created_at, last_seen_at) VALUES (?, ?, ?)")) {
                    statement.setBytes(1, toBytes(identity.internalId()));
                    statement.setLong(2, now);
                    statement.setLong(3, now);
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + database.table("accounts")
                                + " (minecraft_id, internal_id, username, username_lower, tier, registered_at, last_login_at)"
                                + " VALUES (?, ?, ?, ?, ?, ?, ?)"
                                + " ON DUPLICATE KEY UPDATE username = VALUES(username), tier = VALUES(tier)")) {
                    statement.setBytes(1, toBytes(identity.minecraftId()));
                    statement.setBytes(2, toBytes(identity.internalId()));
                    statement.setString(3, identity.username());
                    statement.setString(4, identity.username().toLowerCase(Locale.ROOT));
                    statement.setString(5, identity.tier().name());
                    statement.setLong(6, identity.registeredAt());
                    statement.setLong(7, identity.lastLoginAt());
                    statement.executeUpdate();
                }
                connection.commit();
            } catch (SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    /** Any account belonging to an identity, most recently seen first. */
    public Optional<StoredAccount> findByInternalId(UUID internalId) throws SQLException {
        String sql = SELECT_COLUMNS + database.table("accounts")
                + " WHERE internal_id = ? ORDER BY last_login_at DESC LIMIT 1";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, toBytes(internalId));
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? Optional.of(read(results)) : Optional.empty();
            }
        }
    }

    public Optional<StoredAccount> findByDiscordId(String discordId) throws SQLException {
        String sql = SELECT_COLUMNS + database.table("accounts")
                + " WHERE discord_id = ? ORDER BY last_login_at DESC LIMIT 1";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, discordId);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? Optional.of(read(results)) : Optional.empty();
            }
        }
    }

    /** Every account belonging to one person. */
    public List<StoredAccount> findAllByInternalId(UUID internalId) throws SQLException {
        String sql = SELECT_COLUMNS + database.table("accounts")
                + " WHERE internal_id = ? ORDER BY last_login_at DESC";
        List<StoredAccount> found = new ArrayList<>();
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, toBytes(internalId));
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    found.add(read(results));
                }
            }
        }
        return found;
    }

    /**
     * Applies a Discord link to every account belonging to the identity.
     *
     * All of them, not just the one that generated the code. The link belongs
     * to the person, and someone who linked from their Java account then
     * connected from Bedrock would otherwise appear unlinked.
     */
    public int setDiscordId(UUID internalId, String discordId) throws SQLException {
        String sql = "UPDATE " + database.table("accounts")
                + " SET discord_id = ? WHERE internal_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            if (discordId == null) {
                statement.setNull(1, java.sql.Types.VARCHAR);
            } else {
                statement.setString(1, discordId);
            }
            statement.setBytes(2, toBytes(internalId));
            return statement.executeUpdate();
        }
    }

    public int clearDiscordId(String discordId) throws SQLException {
        String sql = "UPDATE " + database.table("accounts")
                + " SET discord_id = NULL WHERE discord_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, discordId);
            return statement.executeUpdate();
        }
    }

    /**
     * Records a tier for every account belonging to an identity.
     *
     * Used when a Discord link promotes someone out of CRACKED. Applying it to
     * one account would leave the person trusted on that account and untrusted
     * on the rest, which is exactly the split the internal id exists to avoid.
     */
    public int setTierForIdentity(UUID internalId, TrustTier tier, TrustTier onlyIfCurrently) throws SQLException {
        StringBuilder sql = new StringBuilder("UPDATE " + database.table("accounts")
                + " SET tier = ? WHERE internal_id = ?");
        if (onlyIfCurrently != null) {
            sql.append(" AND tier = ?");
        }
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql.toString())) {
            statement.setString(1, tier.name());
            statement.setBytes(2, toBytes(internalId));
            if (onlyIfCurrently != null) {
                statement.setString(3, onlyIfCurrently.name());
            }
            return statement.executeUpdate();
        }
    }

    public void setPassword(UUID minecraftId, String passwordHash) throws SQLException {
        String sql = "UPDATE " + database.table("accounts")
                + " SET password_hash = ?, registered_at = CASE WHEN registered_at = 0 THEN ? ELSE registered_at END"
                + " WHERE minecraft_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, passwordHash);
            statement.setLong(2, System.currentTimeMillis());
            statement.setBytes(3, toBytes(minecraftId));
            statement.executeUpdate();
        }
    }

    public void setTotpSecret(UUID minecraftId, String secret) throws SQLException {
        String sql = "UPDATE " + database.table("accounts") + " SET totp_secret = ? WHERE minecraft_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, secret);
            statement.setBytes(2, toBytes(minecraftId));
            statement.executeUpdate();
        }
    }

    public void recordLogin(UUID minecraftId, String address) throws SQLException {
        String sql = "UPDATE " + database.table("accounts")
                + " SET last_login_at = ?, last_login_ip = ? WHERE minecraft_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, System.currentTimeMillis());
            statement.setString(2, address);
            statement.setBytes(3, toBytes(minecraftId));
            statement.executeUpdate();
        }
    }

    public void touchIdentity(UUID internalId) throws SQLException {
        String sql = "UPDATE " + database.table("identities") + " SET last_seen_at = ? WHERE internal_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, System.currentTimeMillis());
            statement.setBytes(2, toBytes(internalId));
            statement.executeUpdate();
        }
    }

    public void replaceRecoveryCodes(UUID internalId, List<String> hashes) throws SQLException {
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM " + database.table("recovery_codes") + " WHERE internal_id = ?")) {
                    statement.setBytes(1, toBytes(internalId));
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + database.table("recovery_codes")
                                + " (internal_id, code_hash, used_at) VALUES (?, ?, 0)")) {
                    for (String hash : hashes) {
                        statement.setBytes(1, toBytes(internalId));
                        statement.setString(2, hash);
                        statement.addBatch();
                    }
                    statement.executeBatch();
                }
                connection.commit();
            } catch (SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    public List<String> unusedRecoveryCodeHashes(UUID internalId) throws SQLException {
        String sql = "SELECT code_hash FROM " + database.table("recovery_codes")
                + " WHERE internal_id = ? AND used_at = 0";
        List<String> hashes = new ArrayList<>();
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, toBytes(internalId));
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    hashes.add(results.getString(1));
                }
            }
        }
        return hashes;
    }

    public void consumeRecoveryCode(UUID internalId, String hash) throws SQLException {
        String sql = "UPDATE " + database.table("recovery_codes")
                + " SET used_at = ? WHERE internal_id = ? AND code_hash = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, System.currentTimeMillis());
            statement.setBytes(2, toBytes(internalId));
            statement.setString(3, hash);
            statement.executeUpdate();
        }
    }

    private static StoredAccount read(ResultSet results) throws SQLException {
        // An unrecognised tier degrades to the least trusted rather than
        // throwing. A row written by a newer release must not take this server
        // down, and treating the unknown as untrusted fails in the safe
        // direction.
        TrustTier tier = TrustTier.parse(results.getString("tier")).orElse(TrustTier.CRACKED);
        return new StoredAccount(
                fromBytes(results.getBytes("minecraft_id")),
                fromBytes(results.getBytes("internal_id")),
                results.getString("username"),
                tier,
                results.getString("password_hash"),
                results.getString("totp_secret"),
                results.getLong("registered_at"),
                results.getLong("last_login_at"),
                results.getString("discord_id"));
    }

    public static byte[] toBytes(UUID uuid) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        return buffer.array();
    }

    public static UUID fromBytes(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    public record StoredAccount(
            UUID minecraftId,
            UUID internalId,
            String username,
            TrustTier tier,
            String passwordHash,
            String totpSecret,
            long registeredAt,
            long lastLoginAt,
            String discordId
    ) {
        public boolean isRegistered() {
            return passwordHash != null && !passwordHash.isEmpty();
        }

        public boolean hasTotp() {
            return totpSecret != null && !totpSecret.isEmpty();
        }

        public boolean hasDiscordLink() {
            return discordId != null && !discordId.isEmpty();
        }
    }
}
