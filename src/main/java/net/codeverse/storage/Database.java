package net.codeverse.storage;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import net.codeverse.config.PluginConfig;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Connection pool and schema management.
 *
 * The schema is applied idempotently on startup so a fresh install needs no
 * manual SQL, and adding a column in a later release is a matter of adding
 * another guarded statement here.
 */
public final class Database implements AutoCloseable {

    private final HikariDataSource dataSource;
    private final String prefix;

    public Database(PluginConfig.Storage settings) {
        HikariConfig hikari = new HikariConfig();
        hikari.setJdbcUrl(settings.jdbcUrl);
        hikari.setUsername(settings.username);
        hikari.setPassword(settings.password);
        // Naming the driver is required, not optional. DriverManager only
        // auto discovers drivers visible to the system class loader, and a
        // driver shaded into a plugin jar is not. Without this the pool fails
        // with "No suitable driver" even though the driver is present.
        if (settings.driverClassName != null && !settings.driverClassName.isBlank()) {
            hikari.setDriverClassName(settings.driverClassName);
        }
        hikari.setMaximumPoolSize(settings.maximumPoolSize);
        hikari.setMinimumIdle(settings.minimumIdle);
        hikari.setConnectionTimeout(settings.connectionTimeoutMillis);
        hikari.setPoolName("CodeverseAuth");
        hikari.addDataSourceProperty("cachePrepStmts", "true");
        hikari.addDataSourceProperty("prepStmtCacheSize", "250");
        hikari.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        hikari.addDataSourceProperty("useServerPrepStmts", "true");
        this.dataSource = new HikariDataSource(hikari);
        this.prefix = settings.tablePrefix;
    }

    public Connection connection() throws SQLException {
        return dataSource.getConnection();
    }

    public String table(String name) {
        return prefix + name;
    }

    public void applySchema() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS %s (
                      internal_id   BINARY(16)   NOT NULL PRIMARY KEY,
                      created_at    BIGINT       NOT NULL,
                      last_seen_at  BIGINT       NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """.formatted(table("identities")));

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS %s (
                      minecraft_id   BINARY(16)   NOT NULL PRIMARY KEY,
                      internal_id    BINARY(16)   NOT NULL,
                      username       VARCHAR(16)  NOT NULL,
                      username_lower VARCHAR(16)  NOT NULL,
                      tier           VARCHAR(16)  NOT NULL,
                      password_hash  VARCHAR(255) NULL,
                      totp_secret    VARCHAR(128) NULL,
                      registered_at  BIGINT       NOT NULL DEFAULT 0,
                      last_login_at  BIGINT       NOT NULL DEFAULT 0,
                      last_login_ip  VARCHAR(45)  NULL,
                      UNIQUE KEY uq_username_lower (username_lower),
                      KEY idx_internal (internal_id)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """.formatted(table("accounts")));

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS %s (
                      internal_id   BINARY(16)   NOT NULL,
                      code_hash     VARCHAR(255) NOT NULL,
                      used_at       BIGINT       NOT NULL DEFAULT 0,
                      PRIMARY KEY (internal_id, code_hash)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """.formatted(table("recovery_codes")));

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS %s (
                      scope         VARCHAR(64)  NOT NULL PRIMARY KEY,
                      failures      INT          NOT NULL DEFAULT 0,
                      locked_until  BIGINT       NOT NULL DEFAULT 0,
                      updated_at    BIGINT       NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """.formatted(table("login_throttle")));
        }
    }

    @Override
    public void close() {
        dataSource.close();
    }
}
