package net.codeverse.storage;

import net.codeverse.config.PluginConfig;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A real database for the tests that need one.
 *
 * Deliberately not an in memory substitute. The behaviour under test is the
 * behaviour of the SQL: conditional updates whose row count decides an
 * outcome, a unique index that turns a duplicate into an exception, and
 * metadata driven migration. An imitation would agree with whatever the
 * implementation happened to do and prove nothing.
 *
 * Connection details come from the environment so the same tests run against
 * a sandbox instance and a developer's own. Where no database is reachable
 * the tests skip rather than fail, since a missing local service is not a
 * defect in the code under test.
 */
public final class TestDatabase {

    private TestDatabase() {
    }

    static String url() {
        return System.getenv().getOrDefault("CODEVERSE_TEST_JDBC_URL",
                "jdbc:mysql://127.0.0.1:3306/codeverse?useSSL=false&characterEncoding=utf8");
    }

    static String user() {
        return System.getenv().getOrDefault("CODEVERSE_TEST_DB_USER", "codeverse");
    }

    static String password() {
        return System.getenv().getOrDefault("CODEVERSE_TEST_DB_PASSWORD", "codeverse");
    }

    /** Opens a database on a unique table prefix, or skips the calling test. */
    public static Database openOrSkip(String prefix) {
        PluginConfig.Storage settings = new PluginConfig.Storage();
        settings.jdbcUrl = url();
        settings.username = user();
        settings.password = password();
        settings.driverClassName = "com.mysql.cj.jdbc.Driver";
        settings.maximumPoolSize = 4;
        settings.minimumIdle = 1;
        settings.connectionTimeoutMillis = 3000;
        settings.tablePrefix = prefix;

        Database database = null;
        try {
            database = new Database(settings);
            try (Connection connection = database.connection()) {
                connection.isValid(2);
            }
            database.applySchema();
            return database;
        } catch (RuntimeException | SQLException unreachable) {
            if (database != null) {
                database.close();
            }
            assumeTrue(false, "No test database reachable at " + url() + ", skipping");
            throw new IllegalStateException("unreachable");
        }
    }

    public static void drop(Database database) {
        if (database == null) {
            return;
        }
        try (Connection connection = database.connection(); Statement statement = connection.createStatement()) {
            for (String table : new String[]{"link_codes", "recovery_codes", "login_throttle", "accounts", "identities"}) {
                statement.executeUpdate("DROP TABLE IF EXISTS " + database.table(table));
            }
        } catch (SQLException ignored) {
            // A leftover table in a test schema is not worth failing a run over.
        } finally {
            database.close();
        }
    }
}
