package net.codeverse.cache;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import net.codeverse.api.identity.Identity;
import net.codeverse.api.identity.TrustTier;

import java.util.Optional;
import java.util.UUID;

/**
 * The one shape a cached identity takes.
 *
 * Both the authentication flow and the API implementation write identities
 * into the cache. Giving each its own encoding would mean whichever wrote
 * last decides what the reader can see, and the difference would only show
 * up as placeholders rendering stale or missing data. One codec, used by
 * every writer and every reader, removes that class of bug.
 */
public final class IdentityPayloadCodec {

    private static final Gson GSON = new Gson();

    private IdentityPayloadCodec() {
    }

    public static String encode(UUID internalId,
                                UUID minecraftId,
                                String username,
                                TrustTier tier,
                                long registeredAtMillis,
                                long lastLoginAtMillis,
                                boolean totpEnrolled,
                                String discordId) {
        JsonObject payload = new JsonObject();
        payload.addProperty("internalId", internalId.toString());
        payload.addProperty("minecraftId", minecraftId.toString());
        payload.addProperty("username", username);
        payload.addProperty("tier", tier.name());
        payload.addProperty("registeredAt", registeredAtMillis);
        payload.addProperty("lastLoginAt", lastLoginAtMillis);
        payload.addProperty("totpEnrolled", totpEnrolled);
        if (discordId != null && !discordId.isBlank()) {
            payload.addProperty("discordId", discordId);
        }
        return GSON.toJson(payload);
    }

    public static String encode(Identity identity) {
        return encode(
                identity.internalId(),
                identity.minecraftId(),
                identity.username(),
                identity.tier(),
                identity.registeredAt().map(java.time.Instant::toEpochMilli).orElse(0L),
                identity.lastLoginAt().map(java.time.Instant::toEpochMilli).orElse(0L),
                identity.totpEnrolled(),
                identity.discordId().orElse(null));
    }

    /**
     * Decodes a cached payload, treating anything unreadable as a miss.
     *
     * Entries written by v0.1.0 lack the minecraftId field, and an entry
     * that cannot be decoded is worth exactly as much as one that was never
     * cached. Returning empty sends the caller to storage, which is the
     * correct answer in both cases.
     */
    public static Optional<Identity> decode(String payload) {
        if (payload == null || payload.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonObject json = GSON.fromJson(payload, JsonObject.class);
            if (json == null
                    || !json.has("internalId") || !json.has("minecraftId")
                    || !json.has("username") || !json.has("tier")) {
                return Optional.empty();
            }
            Optional<TrustTier> tier = TrustTier.parse(json.get("tier").getAsString());
            if (tier.isEmpty()) {
                return Optional.empty();
            }
            Identity.Builder builder = Identity.builder(
                            UUID.fromString(json.get("internalId").getAsString()),
                            UUID.fromString(json.get("minecraftId").getAsString()),
                            json.get("username").getAsString(),
                            tier.get())
                    .registeredAtMillis(json.has("registeredAt") ? json.get("registeredAt").getAsLong() : 0L)
                    .lastLoginAtMillis(json.has("lastLoginAt") ? json.get("lastLoginAt").getAsLong() : 0L)
                    .totpEnrolled(json.has("totpEnrolled") && json.get("totpEnrolled").getAsBoolean());
            if (json.has("discordId")) {
                builder.discordId(json.get("discordId").getAsString());
            }
            return Optional.of(builder.build());
        } catch (JsonParseException | IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }
}
