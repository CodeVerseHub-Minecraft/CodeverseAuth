package net.codeverse.http;

import java.util.List;

/**
 * Configuration for the external HTTP interface.
 *
 * The defaults assume the interface is reachable from the internet, because on
 * this network it is. Every control below exists to make that survivable rather
 * than to make it comfortable.
 *
 * The order the controls are applied in matters and is deliberate: address
 * first, then rate limit, then signature or token. An unauthorised caller
 * should be rejected by the cheapest check that can reject it, and should never
 * reach the code that compares credentials.
 */
public final class HttpApiConfig {

    /** Off until deliberately turned on. An unused open port is a liability. */
    public boolean enabled = false;

    /**
     * Interface to bind. 127.0.0.1 keeps it local, a tunnel address keeps it
     * private, 0.0.0.0 exposes it to everything that can route to the host.
     *
     * If this is 0.0.0.0, treat tls.enabled and allowedAddresses as mandatory
     * rather than optional. The plugin warns loudly at startup when they are not.
     */
    public String bindAddress = "127.0.0.1";
    public int port = 8787;

    /**
     * Addresses permitted to reach the interface at all, as plain addresses or
     * CIDR ranges. Empty means no restriction, which is only defensible on a
     * loopback or tunnel bind.
     *
     * This is the most effective control here by a wide margin. A caller not on
     * the list is dropped before any credential is examined, so a leaked token
     * is worthless from anywhere else.
     */
    public List<String> allowedAddresses = List.of("127.0.0.1", "::1");

    /**
     * Bearer token, generated on first enable when blank.
     *
     * Sent on every request, so on a plaintext connection it is exposed on
     * every request. Prefer signed requests when the interface is public.
     */
    public String token = "";

    /**
     * Requires each request to carry an HMAC signature over its method, path,
     * body and timestamp rather than only a bearer token.
     *
     * Worth the extra work on a public interface: a signature captured from a
     * log is valid for one request inside the replay window, while a captured
     * bearer token is valid until someone notices and rotates it.
     */
    public boolean requireSignedRequests = true;
    /** How far a request timestamp may drift before it is refused, in seconds. */
    public int signatureToleranceSeconds = 30;

    public Tls tls = new Tls();
    public RateLimit rateLimit = new RateLimit();

    /** Endpoints that change state can be disabled independently of reads. */
    public boolean allowWrites = true;
    /** How long a link code remains redeemable. */
    public int linkCodeLifetimeSeconds = 300;
    /** Length of generated link codes, in characters. */
    public int linkCodeLength = 8;

    public static final class Tls {
        public boolean enabled = false;
        /** Path to a PKCS12 keystore, relative to the plugin data folder. */
        public String keystorePath = "api-keystore.p12";
        public String keystorePassword = "";
    }

    public static final class RateLimit {
        /** Requests permitted per address per minute once authenticated. */
        public int requestsPerMinute = 120;
        /**
         * Failed authentication attempts tolerated per address before it is
         * locked out. Much tighter than the general limit, because a caller
         * failing authentication repeatedly is either broken or hostile and
         * neither deserves throughput.
         */
        public int authFailuresBeforeLockout = 5;
        public int lockoutSeconds = 900;
    }

    /** Rejects settings that would leave the interface indefensible. */
    public void validate() {
        if (!enabled) {
            return;
        }
        if (port < 1 || port > 65535) {
            throw new IllegalStateException("http.port must be between 1 and 65535, got " + port);
        }
        if (bindAddress == null || bindAddress.isBlank()) {
            throw new IllegalStateException("http.bindAddress cannot be blank");
        }
        if (signatureToleranceSeconds < 5 || signatureToleranceSeconds > 300) {
            throw new IllegalStateException(
                    "http.signatureToleranceSeconds must be between 5 and 300; a wider window enlarges "
                            + "the replay opportunity for no practical benefit");
        }
        if (linkCodeLength < 6) {
            throw new IllegalStateException(
                    "http.linkCodeLength below 6 is guessable within the code lifetime");
        }
        if (linkCodeLifetimeSeconds < 30 || linkCodeLifetimeSeconds > 3600) {
            throw new IllegalStateException("http.linkCodeLifetimeSeconds must be between 30 and 3600");
        }
        if (rateLimit.requestsPerMinute < 1) {
            throw new IllegalStateException("http.rateLimit.requestsPerMinute must be at least 1");
        }
        if (rateLimit.authFailuresBeforeLockout < 1) {
            throw new IllegalStateException("http.rateLimit.authFailuresBeforeLockout must be at least 1");
        }
        if (tls.enabled && (tls.keystorePassword == null || tls.keystorePassword.isBlank())) {
            throw new IllegalStateException("http.tls.keystorePassword must be set when tls is enabled");
        }
    }

    /** Whether the interface is reachable beyond the local host. */
    public boolean isPubliclyBound() {
        return !"127.0.0.1".equals(bindAddress)
                && !"localhost".equalsIgnoreCase(bindAddress)
                && !"::1".equals(bindAddress);
    }

    /**
     * Weaknesses worth telling the operator about at startup.
     *
     * Reported rather than enforced, because an operator running behind a
     * tunnel legitimately does not need TLS and should not be blocked from
     * starting. The warning exists so the choice is deliberate.
     */
    public List<String> securityWarnings() {
        List<String> warnings = new java.util.ArrayList<>();
        if (!enabled) {
            return warnings;
        }
        boolean publiclyBound = isPubliclyBound();
        if (publiclyBound && !tls.enabled) {
            warnings.add("The HTTP interface is bound to " + bindAddress + " without TLS. Credentials and "
                    + "responses cross the network in plaintext. Enable http.tls or bind to a tunnel.");
        }
        if (publiclyBound && (allowedAddresses == null || allowedAddresses.isEmpty())) {
            warnings.add("The HTTP interface is bound to " + bindAddress + " with no address allowlist. "
                    + "Anyone who can route to this host can attempt authentication. Set "
                    + "http.allowedAddresses to the addresses your integrations use.");
        }
        if (publiclyBound && !requireSignedRequests) {
            warnings.add("Signed requests are disabled on a publicly bound interface. A bearer token "
                    + "captured from any log remains valid until it is rotated by hand.");
        }
        return warnings;
    }
}
