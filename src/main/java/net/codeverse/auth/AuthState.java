package net.codeverse.auth;

import net.codeverse.identity.Identity;

import java.util.UUID;

/**
 * Per connection authentication state, held only while a player is
 * unauthenticated.
 *
 * Stage exists so the command handlers can reject input that does not belong
 * to the current step, for example a second factor code arriving before a
 * password has been accepted.
 */
public final class AuthState {

    public enum Stage {
        /** Account has no password yet, the player must register. */
        AWAITING_REGISTRATION,
        /** Password required. */
        AWAITING_PASSWORD,
        /** Password accepted, second factor required. */
        AWAITING_TOTP,
        /** Fully authenticated, awaiting transfer out of limbo. */
        AUTHENTICATED
    }

    private final Identity identity;
    private final String address;
    private final long startedAt;
    private volatile Stage stage;

    public AuthState(Identity identity, String address, Stage stage) {
        this.identity = identity;
        this.address = address;
        this.stage = stage;
        this.startedAt = System.currentTimeMillis();
    }

    public Identity identity() {
        return identity;
    }

    public UUID minecraftId() {
        return identity.minecraftId();
    }

    public String address() {
        return address;
    }

    public Stage stage() {
        return stage;
    }

    public void stage(Stage next) {
        this.stage = next;
    }

    public boolean authenticated() {
        return stage == Stage.AUTHENTICATED;
    }

    public long elapsedMillis() {
        return System.currentTimeMillis() - startedAt;
    }
}
