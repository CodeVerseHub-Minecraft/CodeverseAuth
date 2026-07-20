# Verification Record

What has actually been executed, and what has not. Read the second list
before calling this production ready.

Environment: Velocity 4.0.0 build 6, Java 25.0.3, MariaDB 10.11.14,
Redis 7, LuckPerms 5.5.53, protocol 771 (26.2).

## Verified by execution

### Build
- Gradle 9.6.1 `build` succeeds against `velocity-api:4.0.0`
- Zero compiler warnings under `-Xlint:deprecation`
- Shaded jar produced: `CodeverseAuth-1.0.0.jar`

### Unit tests, 21 passing
- All 18 RFC 6238 Appendix B vectors, SHA1 and SHA256 and SHA512
- Base32 round trip
- TOTP drift window accepts adjacent steps, rejects distant ones
- TOTP rejects malformed secrets, wrong length codes, nulls
- Session token round trip
- Session token rejects tampered payload, tampered MAC, foreign secret,
  expired token, truncated and null input
- Session tokens for one identity are not linkable to each other
- Weak session secrets refused at construction
- Argon2id PHC format, correct and incorrect password, independent salts
- Corrupt stored hash returns false rather than throwing
- Raising cost parameters keeps old hashes valid and flags them for rehash

### Live proxy startup
- Plugin loads on Velocity 4: `Loaded plugin codeverse-auth 1.0.0`
- HikariCP connects to MariaDB, pool starts
- All four tables created with correct columns, keys and indexes
- Redis connects through Lettuce
- LuckPerms detected: `LuckPerms trust tier enforcement active`
- `Authentication ready. Cracked prefix '~', limbo 'limbo', locales [de, en]`
- Session signing secret generated and written back to config, 64 chars
- Both lang files written to the data directory
- Zero ERROR lines in the proxy log
- Proxy binds, accepts connections, answers a status ping

### Live login flow, real protocol client
Tested by speaking the actual Minecraft login protocol to the proxy.

| Sent username | Result | Meaning |
|---|---|---|
| `Zqx9TestCrack` (not premium) | offline mode granted, returned as **`~Zqx9TestCrack`** | prefix applied on the wire |
| `Notch` (premium) | **EncryptionRequest** | Mojang authentication demanded |
| `Qwertyuiop12345` (premium) | **EncryptionRequest** | Mojang authentication demanded |
| `Zqx9Cracked16chr` (16 chars) | denied with the configured message | length cap enforced |

The second row is the founding requirement of the network holding on a live
connection: a client that cannot complete Mojang authentication cannot obtain
the name `Notch`, and a client that skips authentication is renamed with a
prefix Mojang cannot issue.

The denial message arrived as rendered MiniMessage with colours and with the
`<prefix>` and `<max>` placeholders substituted, which verifies the language
system end to end rather than only in isolation.

Redis contents after the run confirmed the resolver caching correctly:
`codeverse:premium:zqx9testcrack = CRACKED`,
`codeverse:premium:notch = PREMIUM`.

### Bugs this testing found
Two, both invisible to compilation and unit tests, both fixed:

1. **`No suitable driver`.** A JDBC driver shaded into a plugin jar is never
   auto discovered, because `DriverManager` resolves drivers through the
   system class loader, which cannot see the proxy's plugin class loader.
   Fixed by naming the driver class explicitly, now a config option.
2. **`ClassNotFoundException: SSMSW`.** Caffeine selects its cache
   implementation reflectively by generated class name, and shadow's
   `minimize()` stripped those classes as unreferenced. Fixed by removing
   minimization, with a comment recording why it must stay off.

## Not verified

These paths have not been executed. Several are core.

- **Account creation and every database write.** Schema creation is verified,
  but no row has ever been inserted by a live login. The test client cannot
  complete the configuration phase, so `PostLoginEvent` never fires. All of
  `AccountRepository` beyond `applySchema` is compile checked only.
- **`/login`, `/register`, `/changepassword`, `/2fa`.** No command has been
  executed by a real client.
- **Cookie sessions.** Issuing and restoring a session requires a client that
  stores cookies. The codec is unit tested; the round trip through Velocity
  is not.
- **Limbo routing and release.** No limbo server was running during testing.
  `PlayerChooseInitialServerEvent`, `ServerPreConnectEvent` and
  `releaseFromLimbo` are unexercised.
- **LuckPerms group stripping.** The integration loads and reports active,
  but no cracked account has had a group stripped in practice.
- **The entire Bedrock path.** Geyser and Floodgate were not installed. Tier
  classification for Bedrock, and the interaction between Floodgate's prefix
  and ours, are untested.
- **TOTP enrolment against a real authenticator app.** The algorithm matches
  the RFC vectors, but no phone has scanned a provisioning URI.
- **Throttling and lockout under real failed logins.**
- **Concurrency.** No two connections have ever been authenticated at once.
- **Load.** Argon2 at the configured cost has not been measured against a
  join burst. Tune `argon2MemoryKib` against real hardware before opening.

## Suggested first run

1. Stand up limbo, then start the proxy with this plugin and LuckPerms
2. Register and log in with a cracked client, confirm the row appears in
   `codeverse_accounts` with tier `CRACKED` and the `~` prefix
3. Reconnect and confirm the session cookie skips the password prompt
4. Enrol TOTP with a real authenticator, then reconnect
5. Grant a cracked account a staff group in LuckPerms by hand, reconnect,
   confirm it is stripped and logged
6. Connect from Bedrock and confirm no prefix collision
7. Fail five logins and confirm the lockout, then confirm it expires
