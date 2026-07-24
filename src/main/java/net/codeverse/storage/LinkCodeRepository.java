package net.codeverse.storage;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * Storage for the one time codes that link an in game account to a Discord one.
 *
 * The codes exist because a bot cannot be trusted to assert which Minecraft
 * account belongs to which Discord user. If linking were a direct write, one
 * leaked bot token would be account takeover for every player on the network.
 * A code proves control of the game account; presenting it through Discord
 * proves control of the Discord account; only the pair creates a link.
 */
public final class LinkCodeRepository {

    /**
     * Deliberately excludes characters that are read wrongly when someone
     * copies a code off their screen: no O or 0, no I, l or 1. A code that gets
     * mistyped is a support message, and the alphabet costs nothing to narrow.
     */
    private static final String ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Database database;

    public LinkCodeRepository(Database database) {
        this.database = database;
    }

    /**
     * Issues a code, replacing any the identity already holds.
     *
     * Replacing matters twice over. A player who generates a second code should
     * not have to wonder which one is live, and an abandoned code should not
     * stay redeemable by whoever glanced at their screen.
     */
    public String issue(UUID internalId, int length, long lifetimeMillis) throws SQLException {
        long now = System.currentTimeMillis();
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM " + database.table("link_codes") + " WHERE internal_id = ?")) {
                    statement.setBytes(1, VoiceSafeBytes.toBytes(internalId));
                    statement.executeUpdate();
                }

                // Retried rather than assumed unique. The space is large, but a
                // collision would otherwise surface as a primary key violation
                // in front of a confused player.
                String code = null;
                for (int attempt = 0; attempt < 8 && code == null; attempt++) {
                    String candidate = generate(length);
                    try (PreparedStatement statement = connection.prepareStatement(
                            "INSERT INTO " + database.table("link_codes")
                                    + " (code, internal_id, issued_at, expires_at) VALUES (?, ?, ?, ?)")) {
                        statement.setString(1, candidate);
                        statement.setBytes(2, VoiceSafeBytes.toBytes(internalId));
                        statement.setLong(3, now);
                        statement.setLong(4, now + lifetimeMillis);
                        statement.executeUpdate();
                        code = candidate;
                    } catch (SQLException collision) {
                        if (attempt == 7) {
                            throw collision;
                        }
                    }
                }
                connection.commit();
                return code;
            } catch (SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    /**
     * Consumes a code and returns the identity that issued it.
     *
     * The update is conditional on the code still being unredeemed and unexpired
     * and the row count decides the outcome, so two bots redeeming the same code
     * at the same moment cannot both succeed. Reading and then writing would
     * leave exactly that gap.
     */
    public Optional<UUID> redeem(String code) throws SQLException {
        if (code == null || code.isBlank()) {
            return Optional.empty();
        }
        String normalised = code.trim().toUpperCase(Locale.ROOT);
        long now = System.currentTimeMillis();

        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                UUID internalId;
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT internal_id FROM " + database.table("link_codes")
                                + " WHERE code = ? AND redeemed_at = 0 AND expires_at > ? FOR UPDATE")) {
                    statement.setString(1, normalised);
                    statement.setLong(2, now);
                    try (ResultSet results = statement.executeQuery()) {
                        if (!results.next()) {
                            connection.commit();
                            return Optional.empty();
                        }
                        internalId = VoiceSafeBytes.fromBytes(results.getBytes(1));
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE " + database.table("link_codes")
                                + " SET redeemed_at = ? WHERE code = ? AND redeemed_at = 0")) {
                    statement.setLong(1, now);
                    statement.setString(2, normalised);
                    if (statement.executeUpdate() == 0) {
                        connection.rollback();
                        return Optional.empty();
                    }
                }
                connection.commit();
                return Optional.of(internalId);
            } catch (SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    /** Discards codes past their lifetime, along with redeemed ones. */
    public int purgeExpired() throws SQLException {
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM " + database.table("link_codes")
                             + " WHERE expires_at <= ? OR redeemed_at > 0")) {
            statement.setLong(1, System.currentTimeMillis());
            return statement.executeUpdate();
        }
    }

    public void discardFor(UUID internalId) throws SQLException {
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM " + database.table("link_codes") + " WHERE internal_id = ?")) {
            statement.setBytes(1, VoiceSafeBytes.toBytes(internalId));
            statement.executeUpdate();
        }
    }

    private static String generate(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return builder.toString();
    }

    /** Shared uuid encoding, kept beside the repositories that use it. */
    static final class VoiceSafeBytes {
        private VoiceSafeBytes() {
        }

        static byte[] toBytes(UUID uuid) {
            return AccountRepository.toBytes(uuid);
        }

        static UUID fromBytes(byte[] bytes) {
            return AccountRepository.fromBytes(bytes);
        }
    }
}
