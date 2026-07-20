package net.codeverse.auth;

import java.util.concurrent.CompletableFuture;

/**
 * Determines whether a username belongs to a paid Java account.
 *
 * Contract, relied on by the login listener: this never reports CRACKED as
 * a result of an error. Any failure produces UNKNOWN or an exceptional
 * completion, both of which the caller treats as a reason to demand Mojang
 * authentication rather than to grant offline mode.
 */
public interface PremiumResolver {

    CompletableFuture<PremiumStatus> resolve(String username);

    enum PremiumStatus {
        /** Confirmed to be a registered paid account. */
        PREMIUM,
        /** Confirmed not to be a paid account, safe to treat as cracked. */
        CRACKED,
        /** Undetermined. The caller must fail closed. */
        UNKNOWN
    }
}
