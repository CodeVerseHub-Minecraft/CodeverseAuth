package net.codeverse.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import net.codeverse.config.PluginConfig;

import java.time.Duration;
import java.util.Optional;

/**
 * Two tier cache in front of the database and the Mojang API.
 *
 * Local Caffeine absorbs repeated lookups within one proxy; Redis shares
 * them across proxies so a second proxy added later does not double the
 * external API load. Redis is optional: when disabled or unreachable the
 * cache degrades to local only rather than failing the lookup, because a
 * cache outage must never become an authentication outage.
 */
public final class IdentityCache implements AutoCloseable {

    private final Cache<String, String> local;
    private final RedisClient redisClient;
    private final StatefulRedisConnection<String, String> redisConnection;
    private final String keyPrefix;
    private final Duration premiumTtl;
    private final Duration identityTtl;
    private volatile boolean redisHealthy;

    public IdentityCache(PluginConfig.Redis settings) {
        this.keyPrefix = settings.keyPrefix;
        this.premiumTtl = Duration.ofSeconds(settings.premiumCacheSeconds);
        this.identityTtl = Duration.ofSeconds(settings.identityCacheSeconds);
        this.local = Caffeine.newBuilder()
                .maximumSize(50_000)
                .expireAfterWrite(Duration.ofSeconds(Math.max(60, settings.identityCacheSeconds)))
                .build();

        if (settings.enabled) {
            RedisClient client = RedisClient.create(settings.uri);
            StatefulRedisConnection<String, String> connection = client.connect();
            this.redisClient = client;
            this.redisConnection = connection;
            this.redisHealthy = true;
        } else {
            this.redisClient = null;
            this.redisConnection = null;
            this.redisHealthy = false;
        }
    }

    public Optional<String> getPremiumStatus(String username) {
        return get("premium:" + username.toLowerCase(java.util.Locale.ROOT));
    }

    public void putPremiumStatus(String username, String status) {
        put("premium:" + username.toLowerCase(java.util.Locale.ROOT), status, premiumTtl);
    }

    public Optional<String> getIdentity(String minecraftId) {
        return get("identity:" + minecraftId);
    }

    public void putIdentity(String minecraftId, String payload) {
        put("identity:" + minecraftId, payload, identityTtl);
    }

    public void invalidateIdentity(String minecraftId) {
        String key = "identity:" + minecraftId;
        local.invalidate(key);
        if (redisAvailable()) {
            try {
                commands().del(keyPrefix + key);
            } catch (RuntimeException failure) {
                redisHealthy = false;
            }
        }
    }

    private Optional<String> get(String key) {
        String cached = local.getIfPresent(key);
        if (cached != null) {
            return Optional.of(cached);
        }
        if (!redisAvailable()) {
            return Optional.empty();
        }
        try {
            String value = commands().get(keyPrefix + key);
            if (value != null) {
                local.put(key, value);
                return Optional.of(value);
            }
            return Optional.empty();
        } catch (RuntimeException failure) {
            redisHealthy = false;
            return Optional.empty();
        }
    }

    private void put(String key, String value, Duration ttl) {
        local.put(key, value);
        if (!redisAvailable()) {
            return;
        }
        try {
            commands().setex(keyPrefix + key, ttl.toSeconds(), value);
        } catch (RuntimeException failure) {
            redisHealthy = false;
        }
    }

    private boolean redisAvailable() {
        return redisConnection != null && redisHealthy && redisConnection.isOpen();
    }

    private RedisCommands<String, String> commands() {
        return redisConnection.sync();
    }

    public boolean isRedisHealthy() {
        return redisAvailable();
    }

    /** Allows a reconnect attempt after a transient Redis outage. */
    public void markRedisHealthy() {
        if (redisConnection != null && redisConnection.isOpen()) {
            redisHealthy = true;
        }
    }

    @Override
    public void close() {
        if (redisConnection != null) {
            redisConnection.close();
        }
        if (redisClient != null) {
            redisClient.shutdown();
        }
    }
}
