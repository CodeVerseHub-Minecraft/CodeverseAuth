# CodeverseAuth

Authentication and identity for Velocity networks that accept cracked, Bedrock
and premium Java players at the same time.

Built for **Velocity 4** and **Java 25**.

Mixing offline-mode players with premium ones is where most cracked networks
get compromised, because a client that skips Mojang authentication can claim
any username it likes. CodeverseAuth closes that by proving premium names
against Mojang and pushing everyone else into a separate namespace that Mojang
cannot issue names in.

## How it works

Every connection is sorted into a trust tier.

| Tier | Origin | Prefix | Password | Permissions |
|---|---|---|---|---|
| `PREMIUM` | verified against Mojang | none | no | full |
| `BEDROCK` | verified by Microsoft via Floodgate | `.` | no | full |
| `DISCORD_LINKED` | offline account with a linked Discord identity | `~` | yes | limited |
| `CRACKED` | unverified | `~` | yes | none |

Three properties hold this together, and each is useless without the others.

**Premium names are proven, not claimed.** On `PreLoginEvent` the plugin looks
up whether a username belongs to a paid account. If it does, the connection is
forced into online mode and Mojang's session servers do the verifying.

**Cracked names cannot collide with premium ones.** Everyone else is renamed to
`~name`, and their UUID is derived from the prefixed name. Mojang cannot issue
a username containing `~`, so the two namespaces never intersect. The plugin
refuses to start if the prefix is set to something Mojang could issue.

**Every failure fails closed.** A lookup that throws, times out, or comes back
undetermined ends in online mode, never offline mode. If the database is
unreachable the plugin registers no listeners at all and says so. A cracked
player being unable to log in during an outage is the design working; the
alternative is every username on the network silently becoming spoofable.

## Requirements

- Velocity 4.0.0 or newer
- Java 25
- MySQL or MariaDB
- LuckPerms on the proxy. Without it the plugin still starts, but tier
  enforcement is inactive and it says so loudly at startup.
- A limbo server for unauthenticated players
- Redis is optional. If it is disabled or unreachable the cache degrades to
  local only, because a cache outage should not become an auth outage.
- [CodeverseAPI](https://github.com/CodeVerseHub-Minecraft/CodeverseAPI) is
  bundled in the jar. This plugin provides it to the rest of the network, so
  nothing needs installing separately.

## Setup

Drop the jar in `plugins/`, start once to generate the config, fill in your
database details, restart.

Your `velocity.toml` needs:

```toml
online-mode = true
force-key-authentication = false
player-info-forwarding-mode = "MODERN"
try = ["limbo"]
```

`online-mode = true` is not a typo. The plugin downgrades individual
connections to offline mode after positively identifying them as non-premium.
Setting it to `false` globally removes the guarantee entirely.

## Commands

| Command | Purpose |
|---|---|
| `/login <password>` | sign in |
| `/register <password> <password>` | create an account |
| `/changepassword <current> <new>` | change password |
| `/2fa enable` | begin TOTP setup |
| `/2fa confirm <code>` | activate TOTP and receive recovery codes |
| `/2fa disable <password>` | turn TOTP off |
| `/2fa <code>` | submit a code while signing in |
| `/link` | issue a Discord link code |
| `/unlink` | remove a Discord link |

Only the authentication commands and `/help` work before signing in. `/link`
and `/unlink` require an authenticated session, since a code is supposed to
prove control of the account it belongs to.

## Discord linking

`DISCORD_LINKED` is the tier for an account that is not a paid Minecraft
account but is tied to a community identity that can be held accountable.
Promotion out of `CRACKED` is automatic once a link is made.

The flow proves both sides. A player runs `/link` and receives a short code;
they present it to the Discord bot, which redeems it. The code proves control
of the game account, presenting it through Discord proves control of the
Discord account, and only the pairing creates a link. A bot that could assert
the pairing directly would turn one leaked bot token into account takeover for
every player on the network.

Codes are single use, short lived, and replaced when a new one is issued.
Unknown, expired and already redeemed codes are deliberately indistinguishable
to the caller.

A link belongs to the person rather than to one account, so it applies to every
account sharing an internal id. Promotion and demotion are conditional updates:
linking never moves a `PREMIUM` account down to `DISCORD_LINKED`, and unlinking
never takes a tier the connection itself proved.

## HTTP interface

An optional interface, disabled by default, lets an external service such as a
Discord bot resolve identities and drive the link flow.

```
GET    /v1/health
GET    /v1/identity/{uuid|username}
GET    /v1/link/discord/{discordId}
POST   /v1/link/code      {"player": "Steve"}
POST   /v1/link/redeem    {"code": "ABC123", "discordId": "998877"}
DELETE /v1/link/discord/{discordId}
```

Requests carry an HMAC-SHA256 signature over method, path, timestamp, nonce and
a digest of the body. The nonce is load bearing: without it two identical
requests in the same second produce the same signature and the second is
refused as a replay, which would break a bot polling health.

Controls are applied cheapest first: address allowlist, then rate limit, then
signature. The allowlist is checked before any credential is examined, so a
token leaked from a log is useless from another address. Firewall the port to
the same address as well, so the two layers fail independently.

Two properties are asserted by tests and should stay. No response contains a
secret, not even for an authenticated caller. Failures are indistinguishable: a
wrong address, a wrong signature and a missing account all return the same 401.

## For plugin authors

CodeverseAuth registers the shared
[CodeverseAPI](https://github.com/CodeVerseHub-Minecraft/CodeverseAPI) on the
proxy, providing `IdentityService`, `LinkService` and an `EventBus` that
publishes link and trust tier events.

```kotlin
dependencies {
    compileOnly("com.github.CodeVerseHub-Minecraft.CodeverseAPI:api:0.2.0")
}
```

Key your data on `Identity.internalId()` rather than the Minecraft UUID.
Someone with linked Java and Bedrock accounts is one person, and a restriction
keyed on the wrong id is shed by connecting with the other account.

## Configuration

Everything lives in `config.json`, written with defaults on first start and
merged forward on upgrade. No setting requires a rebuild. A session signing
secret is generated on first run.

Raising the Argon2 cost parameters is safe at any time. Existing hashes keep
verifying and are transparently upgraded on each account's next correct
password.

## Messages and translations

`lang/en.json` and `lang/de.json` ship with the plugin and are written to the
data directory on first start. Every player-facing string resolves through the
catalogue, so all of them can be reworded or translated without touching code.
Files use MiniMessage. Nested objects flatten to dotted keys and arrays become
multi-line messages.

To add a language, drop `lang/fr.json` in the data directory. It is picked up
at startup. Player locale is detected automatically when
`language.usePlayerLocale` is enabled.

Translation contributions are welcome.

## Design notes

**Internal UUIDs.** Each account gets an internal UUID that is the primary key
in every table the plugin owns. The Minecraft-facing UUID is treated as an
address, not an identity. This keeps Java, Bedrock and cracked accounts
unifiable later without rewriting the in-game UUID, which would break Floodgate
and, through it, anti-cheat exemptions for Bedrock players.

**Cookie sessions.** Sessions are stored client-side using Velocity 4 cookies,
signed with HMAC-SHA256. Bedrock and mobile players change networks constantly,
and an IP-keyed session either logs them out every time or has to be loosened
until it is meaningless. The signature is verified before any field is parsed,
and the identity inside the token must match the one the proxy independently
resolved for that connection.

**Chat is not cancelled.** Denying `PlayerChatEvent` disconnects clients on
1.19.1 and newer, which would turn a mistyped password into a kick.
Unauthenticated players are confined to limbo instead, which relays chat to
nobody.

**Throttling counts both address and account.** Counting only the account lets
one host spray many accounts; counting only the address lets a botnet grind a
single one. Counters are persisted so a restart does not reset an attacker's
budget.

**TOTP is implemented against RFC 6238** on top of the JDK's HMAC, and the test
suite checks all eighteen vectors from Appendix B across SHA1, SHA256 and
SHA512. The common Java TOTP wrappers are unmaintained and pull in a QR image
dependency this plugin does not need.

**Tier enforcement does not trust config.** The LuckPerms sync strips groups
from cracked accounts regardless of what `config.json` says, so a mistyped
group name cannot hand out staff access.

**Optional dependencies stay off the startup path.** Every LuckPerms reference
sits behind an interface loaded only after the plugin has been confirmed
present by name. A guard around the call is not enough: a class that mentions
an absent type fails to link, and the resulting `NoClassDefFoundError` is an
`Error` rather than an `Exception`, so it escapes a catch written for the
missing plugin case and takes the whole startup down with it.

**A stored tier can only ever add a Discord link.** Login takes the tier from
the connection, because `PREMIUM` and `BEDROCK` are things the connection
proved and a stale row must not grant a verification that never happened.
`DISCORD_LINKED` is the one exception, since it exists only in storage; without
that exception a linked player would be demoted on every login.

## Building

```bash
./gradlew build
```

Output: `build/libs/CodeverseAuth-<version>.jar`

Requires a JDK 25 toolchain.

Note for contributors: shadow's `minimize()` must stay disabled. Caffeine,
Lettuce and the MySQL driver all resolve classes reflectively, and minimization
strips classes that are needed at runtime but invisible to static analysis. The
resulting failures only appear once the plugin is actually running.

## Testing

```bash
./gradlew test
```

Tests that exercise storage need a MySQL or MariaDB instance. They read
`CODEVERSE_TEST_JDBC_URL`, `CODEVERSE_TEST_DB_USER` and
`CODEVERSE_TEST_DB_PASSWORD`, defaulting to a local `codeverse` database, and
skip rather than fail when none is reachable.

### What has been verified by execution

Plugin startup on a real Velocity 4.0.0 proxy against real MariaDB and Redis;
schema creation and idempotent migration against a database with existing rows;
premium name verification forcing Mojang authentication; cracked prefixing on a
live connection; the full Discord link flow driven over real HTTP against the
running proxy, including promotion, unlinking, single use enforcement and the
rule that a premium account is never demoted by linking; concurrent redemption
of one code by eight threads resolving to exactly one winner.

### What has not

No account has been created by a live login, because the test client cannot
complete the configuration phase. Cookie sessions and TOTP enrolment have not
been exercised by a real client. Those gaps close on a server with real players
connecting, not in a test harness.

## Contributing

Issues and pull requests are welcome. If you are changing anything in
`PreLoginListener`, `GameProfileListener` or `AuthManager`, please explain in
the pull request how your change preserves the fail-closed behaviour described
above.

## License

MIT. See [LICENSE](LICENSE).

The distributed jar bundles its dependencies, one of which (the MySQL
driver) is GPL v2 with the Universal FOSS Exception. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the full list and for
two supported ways to avoid shipping a GPL component if you prefer.

## About

Built and maintained by the **CodeVerseHub-Minecraft Subteam**.

We work alongside the wider CodeVerseHub community but operate as a separate
team; CodeVerseHub is not responsible for this project.
