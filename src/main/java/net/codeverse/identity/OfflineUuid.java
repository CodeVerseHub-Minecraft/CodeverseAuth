package net.codeverse.identity;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Vanilla compatible offline uuid derivation. */
public final class OfflineUuid {

    private OfflineUuid() {
    }

    /**
     * Produces the same version 3 name based uuid the vanilla server derives
     * for an offline player. Matching vanilla matters because the uuid must
     * be stable across every backend and every restart; if it drifted, a
     * cracked player would silently lose their data on reconnect.
     */
    public static UUID of(String prefixedName) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + prefixedName).getBytes(StandardCharsets.UTF_8));
    }
}
