package net.codeverse.lang;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Message catalogue backed by JSON files in the lang directory.
 *
 * Every player facing string in the plugin resolves through here, so any of
 * them can be reworded, translated or restyled without touching code. Files
 * are MiniMessage formatted. Bundled defaults are written out on first run
 * and missing keys fall back to the configured default locale, then to the
 * key itself, so a partial translation degrades gracefully rather than
 * showing blank messages.
 */
public final class LangManager {

    private static final Gson GSON = new Gson();
    private static final MiniMessage MINI = MiniMessage.miniMessage();

    private final Map<String, Map<String, String>> locales = new HashMap<>();
    private final String defaultLocale;
    private final boolean usePlayerLocale;

    public LangManager(Path directory, String defaultLocale, boolean usePlayerLocale, List<String> bundled)
            throws IOException {
        this.defaultLocale = defaultLocale == null ? "en" : defaultLocale.toLowerCase(Locale.ROOT);
        this.usePlayerLocale = usePlayerLocale;

        Path langDirectory = directory.resolve("lang");
        Files.createDirectories(langDirectory);

        for (String code : bundled) {
            Path target = langDirectory.resolve(code + ".json");
            if (!Files.exists(target)) {
                try (InputStream stream = LangManager.class.getResourceAsStream("/lang/" + code + ".json")) {
                    if (stream != null) {
                        Files.copy(stream, target);
                    }
                }
            }
        }

        try (Stream<Path> files = Files.list(langDirectory)) {
            files.filter(path -> path.getFileName().toString().endsWith(".json")).forEach(this::loadFile);
        }

        if (!locales.containsKey(this.defaultLocale)) {
            throw new IOException("default locale '" + this.defaultLocale + "' has no lang file in " + langDirectory);
        }
    }

    private void loadFile(Path path) {
        String name = path.getFileName().toString();
        String code = name.substring(0, name.length() - ".json".length()).toLowerCase(Locale.ROOT);
        try (InputStreamReader reader = new InputStreamReader(Files.newInputStream(path), StandardCharsets.UTF_8)) {
            JsonObject root = GSON.fromJson(reader, JsonObject.class);
            Map<String, String> flat = new HashMap<>();
            flatten(root, "", flat);
            locales.put(code, flat);
        } catch (IOException | RuntimeException failure) {
            throw new IllegalStateException("failed to load lang file " + path, failure);
        }
    }

    /** Nested JSON objects flatten to dotted keys so files stay readable. */
    private static void flatten(JsonObject object, String prefix, Map<String, String> out) {
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            JsonElement value = entry.getValue();
            if (value.isJsonObject()) {
                flatten(value.getAsJsonObject(), key, out);
            } else if (value.isJsonArray()) {
                StringBuilder joined = new StringBuilder();
                for (int i = 0; i < value.getAsJsonArray().size(); i++) {
                    if (i > 0) {
                        joined.append('\n');
                    }
                    joined.append(value.getAsJsonArray().get(i).getAsString());
                }
                out.put(key, joined.toString());
            } else {
                out.put(key, value.getAsString());
            }
        }
    }

    public Component get(String key, Locale playerLocale, String... placeholders) {
        return MINI.deserialize(raw(key, playerLocale), resolvers(placeholders));
    }

    public Component get(String key, String... placeholders) {
        return get(key, null, placeholders);
    }

    public String raw(String key, Locale playerLocale) {
        String code = resolveLocaleCode(playerLocale);
        Map<String, String> table = locales.get(code);
        if (table != null) {
            String value = table.get(key);
            if (value != null) {
                return value;
            }
        }
        Map<String, String> fallback = locales.get(defaultLocale);
        if (fallback != null) {
            String value = fallback.get(key);
            if (value != null) {
                return value;
            }
        }
        return key;
    }

    public boolean has(String key) {
        Map<String, String> table = locales.get(defaultLocale);
        return table != null && table.containsKey(key);
    }

    private String resolveLocaleCode(Locale playerLocale) {
        if (!usePlayerLocale || playerLocale == null) {
            return defaultLocale;
        }
        String full = playerLocale.toString().toLowerCase(Locale.ROOT).replace('-', '_');
        if (locales.containsKey(full)) {
            return full;
        }
        String language = playerLocale.getLanguage().toLowerCase(Locale.ROOT);
        if (locales.containsKey(language)) {
            return language;
        }
        return defaultLocale;
    }

    /** Placeholders arrive as alternating name and value pairs. */
    private static TagResolver resolvers(String... placeholders) {
        if (placeholders.length == 0) {
            return TagResolver.empty();
        }
        if (placeholders.length % 2 != 0) {
            throw new IllegalArgumentException("placeholders must be name and value pairs");
        }
        TagResolver.Builder builder = TagResolver.builder();
        for (int i = 0; i < placeholders.length; i += 2) {
            builder.resolver(Placeholder.unparsed(placeholders[i], placeholders[i + 1]));
        }
        return builder.build();
    }

    public java.util.Set<String> availableLocales() {
        return java.util.Collections.unmodifiableSet(locales.keySet());
    }
}
