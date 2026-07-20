package net.codeverse.storage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Failed attempt counters and lockouts, persisted so a restart or a switch
 * between proxies does not reset an attacker's budget.
 *
 * Scope keys are namespaced by kind, for example "ip:1.2.3.4" or
 * "user:~steve", letting the same table throttle both dimensions.
 */
public final class ThrottleRepository {

    private final Database database;

    public ThrottleRepository(Database database) {
        this.database = database;
    }

    public long lockedUntil(String scope) throws SQLException {
        String sql = "SELECT locked_until FROM " + database.table("login_throttle") + " WHERE scope = ?";
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, scope);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getLong(1) : 0L;
            }
        }
    }

    /** Records a failure and returns the resulting lockout expiry, 0 when not locked. */
    public long recordFailure(String scope, int maximumFailures, long lockoutMillis) throws SQLException {
        long now = System.currentTimeMillis();
        try (Connection connection = database.connection()) {
            connection.setAutoCommit(false);
            try {
                int failures;
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT failures, locked_until FROM " + database.table("login_throttle")
                                + " WHERE scope = ? FOR UPDATE")) {
                    statement.setString(1, scope);
                    try (ResultSet results = statement.executeQuery()) {
                        failures = results.next() ? results.getInt(1) : 0;
                    }
                }
                failures++;
                long lockedUntil = failures >= maximumFailures ? now + lockoutMillis : 0L;
                if (lockedUntil > 0) {
                    failures = 0;
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + database.table("login_throttle")
                                + " (scope, failures, locked_until, updated_at) VALUES (?, ?, ?, ?)"
                                + " ON DUPLICATE KEY UPDATE failures = VALUES(failures),"
                                + " locked_until = VALUES(locked_until), updated_at = VALUES(updated_at)")) {
                    statement.setString(1, scope);
                    statement.setInt(2, failures);
                    statement.setLong(3, lockedUntil);
                    statement.setLong(4, now);
                    statement.executeUpdate();
                }
                connection.commit();
                return lockedUntil;
            } catch (SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    public void clear(String scope) throws SQLException {
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM " + database.table("login_throttle") + " WHERE scope = ?")) {
            statement.setString(1, scope);
            statement.executeUpdate();
        }
    }

    public int purgeExpired() throws SQLException {
        try (Connection connection = database.connection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM " + database.table("login_throttle")
                             + " WHERE locked_until > 0 AND locked_until < ?")) {
            statement.setLong(1, System.currentTimeMillis());
            return statement.executeUpdate();
        }
    }
}
