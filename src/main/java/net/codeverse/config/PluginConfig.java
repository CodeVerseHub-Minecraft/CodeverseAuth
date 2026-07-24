package net.codeverse.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * Every tunable in the plugin, loaded from config.json.
 *
 * Nothing here is compiled in. The file is written with defaults on first
 * start and merged forward on upgrade, so a new release never silently
 * drops an operator's existing settings or requires a rebuild to change
 * behaviour.
 */
public final class PluginConfig {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public Storage storage = new Storage();
    public Redis redis = new Redis();
    public Security security = new Security();
    public Session session = new Session();
    public Totp totp = new Totp();
    public Naming naming = new Naming();
    public Routing routing = new Routing();
    public Permissions permissions = new Permissions();
    public Language language = new Language();
    public net.codeverse.http.HttpApiConfig http = new net.codeverse.http.HttpApiConfig();

    public static final class Storage {
        public String jdbcUrl = "jdbc:mysql://127.0.0.1:3306/network?useSSL=false&characterEncoding=utf8";
        public String username = "network";
        public String password = "";
        /**
         * Set explicitly because a JDBC driver bundled inside a plugin jar is
         * never auto discovered: DriverManager resolves drivers through the
         * system class loader, which cannot see the proxy's plugin class
         * loader. Naming the class forces it to load and register from here.
         * Change to org.mariadb.jdbc.Driver if using the MariaDB driver.
         */
        public String driverClassName = "com.mysql.cj.jdbc.Driver";
        public int maximumPoolSize = 10;
        public int minimumIdle = 2;
        public long connectionTimeoutMillis = 10000;
        public String tablePrefix = "codeverse_";
    }

    public static final class Redis {
        public boolean enabled = true;
        public String uri = "redis://127.0.0.1:6379/0";
        public String keyPrefix = "codeverse:";
        public long premiumCacheSeconds = 21600;
        public long identityCacheSeconds = 900;
    }

    public static final class Security {
        public int argon2MemoryKib = 65536;
        public int argon2Iterations = 3;
        public int argon2Parallelism = 2;
        public int minimumPasswordLength = 6;
        public int maximumPasswordLength = 128;
        public int maximumFailedAttempts = 5;
        public long lockoutSeconds = 300;
        public long premiumLookupTimeoutMillis = 4000;
        public long authTimeoutSeconds = 120;
        public boolean requireTotpForStaff = false;
        public List<String> premiumLookupEndpoints = List.of(
                "https://api.mojang.com/users/profiles/minecraft/",
                "https://api.ashcon.app/mojang/v2/user/");
    }

    public static final class Session {
        public boolean enabled = true;
        public String secret = "";
        public String cookieKey = "codeverse:session";
        public long lifetimeSeconds = 604800;
        public boolean bindToAddress = false;
    }

    public static final class Totp {
        public boolean enabled = true;
        public String issuer = "Codeverse Network";
        public String algorithm = "SHA1";
        public int digits = 6;
        public int periodSeconds = 30;
        public int allowedDrift = 1;
        public int secretBytes = 20;
        public int recoveryCodeCount = 10;
    }

    public static final class Naming {
        public String crackedPrefix = "~";
        public String floodgatePrefix = ".";
        public int maximumCrackedNameLength = 15;
        public boolean rejectMixedCaseConflicts = true;
    }

    public static final class Routing {
        public String limboServer = "limbo";
        public List<String> postAuthServers = List.of("lobby");
        public boolean honourForcedHosts = true;
    }

    public static final class Permissions {
        public boolean enforceTrustTiers = true;
        public String crackedGroup = "cracked";
        public String discordLinkedGroup = "linked";
        public String bedrockGroup = "default";
        public String premiumGroup = "default";
        public boolean stripElevatedGroupsFromCracked = true;
    }

    public static final class Language {
        public String defaultLocale = "en";
        public boolean usePlayerLocale = true;
    }

    /**
     * Loads config.json, creating it from defaults when absent and adding
     * any keys introduced by a newer version while preserving existing
     * values. A generated session secret is written back on first run so
     * operators never ship with an empty signing key.
     */
    public static PluginConfig load(Path directory) throws IOException {
        Files.createDirectories(directory);
        Path file = directory.resolve("config.json");

        PluginConfig config;
        if (Files.exists(file)) {
            String existing = Files.readString(file, StandardCharsets.UTF_8);
            config = GSON.fromJson(existing, PluginConfig.class);
            if (config == null) {
                throw new IOException("config.json is not valid JSON");
            }
        } else {
            config = new PluginConfig();
        }

        if (config.session.secret == null || config.session.secret.isBlank()) {
            byte[] generated = new byte[48];
            new SecureRandom().nextBytes(generated);
            config.session.secret = Base64.getEncoder().withoutPadding().encodeToString(generated);
        }

        // Generated here rather than at server start so the operator can read
        // it out of config.json to configure the bot, and so enabling the
        // interface never leaves it running with a blank credential.
        if (config.http.enabled && (config.http.token == null || config.http.token.isBlank())) {
            config.http.token = net.codeverse.http.ApiAuthenticator.generateToken();
        }

        config.validate();
        Files.writeString(file, GSON.toJson(config), StandardCharsets.UTF_8);
        return config;
    }

    /** Fails fast on values that would silently weaken security at runtime. */
    public void validate() {
        if (security.minimumPasswordLength < 1) {
            throw new IllegalStateException("security.minimumPasswordLength must be at least 1");
        }
        if (security.maximumPasswordLength < security.minimumPasswordLength) {
            throw new IllegalStateException("security.maximumPasswordLength is below minimumPasswordLength");
        }
        if (naming.crackedPrefix == null || naming.crackedPrefix.isEmpty()) {
            throw new IllegalStateException("naming.crackedPrefix cannot be empty, it is what makes premium names unspoofable");
        }
        if (naming.crackedPrefix.matches("[A-Za-z0-9_]+")) {
            throw new IllegalStateException(
                    "naming.crackedPrefix must use a character Mojang cannot issue, otherwise cracked names can collide with premium ones");
        }
        if (naming.maximumCrackedNameLength + naming.crackedPrefix.length() > 16) {
            throw new IllegalStateException("naming.maximumCrackedNameLength plus the prefix exceeds the 16 character username limit");
        }
        if (routing.limboServer == null || routing.limboServer.isBlank()) {
            throw new IllegalStateException("routing.limboServer must name a server defined in velocity.toml");
        }
        if (routing.postAuthServers == null || routing.postAuthServers.isEmpty()) {
            throw new IllegalStateException("routing.postAuthServers must list at least one server");
        }
        if (security.maximumFailedAttempts < 1) {
            throw new IllegalStateException("security.maximumFailedAttempts must be at least 1");
        }
        http.validate();
    }

    public JsonObject toJsonTree() {
        return GSON.toJsonTree(this).getAsJsonObject();
    }

    public static PluginConfig fromStream(InputStream stream) {
        return GSON.fromJson(new java.io.InputStreamReader(stream, StandardCharsets.UTF_8), PluginConfig.class);
    }
}
