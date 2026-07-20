package net.codeverse.storage;

import net.codeverse.identity.Identity;
import net.codeverse.identity.TrustTier;

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

    private final Database database;

    public AccountRepository(Database database) {
        this.database = database;
    }

    public Optional<StoredAccount> findByMinecraftId(UUID minecraftId) throws SQLException {
        String sql = "SELECT minecraft_id, internal_id, username, tier, password_hash, totp_secret, "
                + "registered_at, last_login_at FROM " + database.table("accounts") + " WHERE minecraft_id = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, toBytes(minecraftId));
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? Optional.of(read(results)) : Optional.empty();
            }
        }
    }

    public Optional<StoredAccount> findByUsername(String username) throws SQLException {
        String sql = "SELECT minecraft_id, internal_id, username, tier, password_hash, totp_secret, "
                + "registered_at, last_login_at FROM " + database.table("accounts") + " WHERE username_lower = ?";
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
        return new StoredAccount(
                fromBytes(results.getBytes("minecraft_id")),
                fromBytes(results.getBytes("internal_id")),
                results.getString("username"),
                TrustTier.valueOf(results.getString("tier")),
                results.getString("password_hash"),
                results.getString("totp_secret"),
                results.getLong("registered_at"),
                results.getLong("last_login_at"));
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
            long lastLoginAt
    ) {
        public boolean isRegistered() {
            return passwordHash != null && !passwordHash.isEmpty();
        }

        public boolean hasTotp() {
            return totpSecret != null && !totpSecret.isEmpty();
        }
    }
}
