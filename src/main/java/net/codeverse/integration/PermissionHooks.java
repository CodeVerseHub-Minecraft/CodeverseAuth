package net.codeverse.integration;

import net.codeverse.identity.Identity;

import java.util.concurrent.CompletableFuture;

/**
 * Trust tier enforcement, expressed without naming the permission plugin.
 *
 * The indirection exists because of how the JVM loads classes. A method that
 * mentions a type is verified when the enclosing class is initialised, not
 * when the method runs, so a guard around a LuckPerms call inside a class
 * that names LuckPerms is checked far too late: the class fails to link and
 * the failure is a NoClassDefFoundError, which is an Error rather than an
 * Exception and slips past a catch written for the absent plugin case.
 *
 * Keeping every LuckPerms reference behind this interface means the startup
 * path can decide whether to load the implementation at all, which is the
 * only point at which the decision can still be made safely.
 */
public interface PermissionHooks {

    /** Applies the groups an identity's tier entitles it to. */
    CompletableFuture<Void> apply(Identity identity);

    /** A no op used when no permission plugin is present. */
    PermissionHooks NONE = identity -> CompletableFuture.completedFuture(null);
}
