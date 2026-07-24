package net.codeverse.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The security layer of the HTTP interface.
 *
 * Delivered as a standalone driver and converted here so the checks run in
 * the build rather than only when someone remembers to invoke them.
 */
class ApiAuthenticatorTest {

    private static void assertTrue2(String label, boolean condition) {
        assertTrue(condition, label);
    }

    private static Map<String, String> headers(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i].toLowerCase(), kv[i + 1]);
        }
        return m;
    }

    @Test
    @DisplayName("address allowlist, signatures, replay and lockout behave as specified")
    void securityLayer() throws Exception {

        // --- address allowlist ---
        HttpApiConfig c = new HttpApiConfig();
        c.enabled = true;
        c.token = ApiAuthenticator.generateToken();
        c.requireSignedRequests = false;
        c.allowedAddresses = List.of("10.0.0.5", "192.168.1.0/24", "172.18.0.0/16");
        ApiAuthenticator auth = new ApiAuthenticator(c);

        assertTrue2("exact address permitted",
            auth.check("10.0.0.5","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ALLOWED);
        assertTrue2("CIDR /24 permitted",
            auth.check("192.168.1.77","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ALLOWED);
        assertTrue2("CIDR /16 permitted",
            auth.check("172.18.44.9","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ALLOWED);
        assertTrue2("outside allowlist refused",
            auth.check("8.8.8.8","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ADDRESS_NOT_PERMITTED);
        assertTrue2("adjacent CIDR refused",
            auth.check("192.168.2.1","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ADDRESS_NOT_PERMITTED);

        // address check happens before credential check
        assertTrue2("bad address refused even with valid token",
            auth.check("8.8.8.8","GET","/v1/health",null,headers("Authorization","Bearer "+c.token)) == ApiAuthenticator.Result.ADDRESS_NOT_PERMITTED);

        // --- bearer token ---
        assertTrue2("wrong token refused",
            auth.check("10.0.0.5","GET","/v1/health",null,headers("Authorization","Bearer wrong")) == ApiAuthenticator.Result.BAD_CREDENTIAL);
        assertTrue2("missing header refused",
            auth.check("10.0.0.5","GET","/v1/health",null,headers()) == ApiAuthenticator.Result.MISSING_CREDENTIAL);

        // --- lockout after repeated failures ---
        HttpApiConfig lc = new HttpApiConfig();
        lc.enabled = true; lc.token = "x".repeat(48); lc.requireSignedRequests = false;
        lc.allowedAddresses = List.of();
        lc.rateLimit.authFailuresBeforeLockout = 3;
        ApiAuthenticator la = new ApiAuthenticator(lc);
        for (int i = 0; i < 3; i++) la.check("1.2.3.4","GET","/x",null,headers("Authorization","Bearer no"));
        assertTrue2("locked out after threshold",
            la.check("1.2.3.4","GET","/x",null,headers("Authorization","Bearer "+lc.token)) == ApiAuthenticator.Result.LOCKED_OUT);
        assertTrue2("lockout is per address",
            la.check("5.6.7.8","GET","/x",null,headers("Authorization","Bearer "+lc.token)) == ApiAuthenticator.Result.ALLOWED);

        // --- rate limit ---
        HttpApiConfig rc = new HttpApiConfig();
        rc.enabled = true; rc.token = "y".repeat(48); rc.requireSignedRequests = false;
        rc.allowedAddresses = List.of(); rc.rateLimit.requestsPerMinute = 5;
        ApiAuthenticator ra = new ApiAuthenticator(rc);
        for (int i = 0; i < 5; i++) ra.check("9.9.9.9","GET","/x",null,headers("Authorization","Bearer "+rc.token));
        assertTrue2("rate limited past the budget",
            ra.check("9.9.9.9","GET","/x",null,headers("Authorization","Bearer "+rc.token)) == ApiAuthenticator.Result.RATE_LIMITED);

        // --- signed requests ---
        HttpApiConfig sc = new HttpApiConfig();
        sc.enabled = true; sc.token = ApiAuthenticator.generateToken();
        sc.requireSignedRequests = true; sc.allowedAddresses = List.of();
        ApiAuthenticator sa = new ApiAuthenticator(sc);

        long now = System.currentTimeMillis()/1000L;
        byte[] body = "{\"code\":\"ABC123\"}".getBytes(StandardCharsets.UTF_8);
        String sig = sa.sign("POST","/v1/link/redeem",now,"nonce-1",body);

        assertTrue2("valid signed request accepted",
            sa.check("1.1.1.1","POST","/v1/link/redeem",body,
                headers("X-Codeverse-Signature",sig,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-1")) == ApiAuthenticator.Result.ALLOWED);

        assertTrue2("same nonce replayed is refused",
            sa.check("1.1.1.1","POST","/v1/link/redeem",body,
                headers("X-Codeverse-Signature",sig,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-1")) == ApiAuthenticator.Result.REPLAYED);

        // The flaw the nonce exists to fix: two legitimate identical requests
        // in the same second must both succeed.
        String sigB = sa.sign("POST","/v1/link/redeem",now,"nonce-2",body);
        assertTrue2("identical request with a fresh nonce still succeeds",
            sa.check("1.1.1.1","POST","/v1/link/redeem",body,
                headers("X-Codeverse-Signature",sigB,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-2")) == ApiAuthenticator.Result.ALLOWED);

        byte[] tampered = "{\"code\":\"EVIL99\"}".getBytes(StandardCharsets.UTF_8);
        String sigC = sa.sign("POST","/v1/link/redeem",now,"nonce-3",body);
        assertTrue2("body swapped under a valid signature is refused",
            sa.check("2.2.2.2","POST","/v1/link/redeem",tampered,
                headers("X-Codeverse-Signature",sigC,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-3")) == ApiAuthenticator.Result.BAD_CREDENTIAL);

        // A rejected signature must not consume the nonce, or an attacker
        // could burn nonces the legitimate caller intends to use.
        String sigD = sa.sign("POST","/v1/link/redeem",now,"nonce-3",body);
        assertTrue2("nonce survives a rejected signature",
            sa.check("2.2.2.2","POST","/v1/link/redeem",body,
                headers("X-Codeverse-Signature",sigD,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-3")) == ApiAuthenticator.Result.ALLOWED);

        String sigE = sa.sign("GET","/v1/identity/x",now,"nonce-5",null);
        assertTrue2("read signature replayed against a write path is refused",
            sa.check("3.3.3.3","POST","/v1/link/redeem",null,
                headers("X-Codeverse-Signature",sigE,"X-Codeverse-Timestamp",String.valueOf(now),
                        "X-Codeverse-Nonce","nonce-5")) == ApiAuthenticator.Result.BAD_CREDENTIAL);

        long old = now - 120;
        String oldSig = sa.sign("GET","/v1/health",old,"nonce-6",null);
        assertTrue2("stale timestamp refused",
            sa.check("4.4.4.4","GET","/v1/health",null,
                headers("X-Codeverse-Signature",oldSig,"X-Codeverse-Timestamp",String.valueOf(old),
                        "X-Codeverse-Nonce","nonce-6")) == ApiAuthenticator.Result.STALE_TIMESTAMP);

        assertTrue2("missing nonce refused",
            sa.check("6.6.6.6","GET","/v1/health",null,
                headers("X-Codeverse-Signature","abc","X-Codeverse-Timestamp",String.valueOf(now)))
                    == ApiAuthenticator.Result.MISSING_CREDENTIAL);

        // --- disclosure ---
        assertTrue2("only safe outcomes are reportable",
            ApiAuthenticator.Result.RATE_LIMITED.isSafeToReport()
            && ApiAuthenticator.Result.STALE_TIMESTAMP.isSafeToReport()
            && !ApiAuthenticator.Result.ADDRESS_NOT_PERMITTED.isSafeToReport()
            && !ApiAuthenticator.Result.BAD_CREDENTIAL.isSafeToReport()
            && !ApiAuthenticator.Result.LOCKED_OUT.isSafeToReport());

        // --- config warnings ---
        HttpApiConfig wc = new HttpApiConfig();
        wc.enabled = true; wc.bindAddress = "0.0.0.0";
        wc.tls.enabled = false; wc.allowedAddresses = List.of(); wc.requireSignedRequests = false;
        assertTrue2("public bind with no protections yields three warnings", wc.securityWarnings().size() == 3);
        wc.tls.enabled = true; wc.allowedAddresses = List.of("10.0.0.1"); wc.requireSignedRequests = true;
        assertTrue2("hardened public bind yields none", wc.securityWarnings().isEmpty());

        HttpApiConfig lo = new HttpApiConfig();
        lo.enabled = true;
        assertTrue2("loopback bind needs no warnings", lo.securityWarnings().isEmpty());
        assertTrue2("loopback is not publicly bound", !lo.isPubliclyBound());

        // --- token strength ---
        assertTrue2("generated token is strong enough", ApiAuthenticator.isTokenStrongEnough(ApiAuthenticator.generateToken()));
        assertTrue2("short token rejected", !ApiAuthenticator.isTokenStrongEnough("short"));
    }
}
