# Third-Party Notices

CodeverseAuth itself is MIT licensed. The distributed jar is a shaded
("fat") jar that bundles the libraries below, so distributing that jar means
redistributing them. Their licenses and notices apply to those portions.

Source for every dependency is available from Maven Central at the
coordinates listed.

## Bundled dependencies

| Library | Version | License |
|---|---|---|
| CodeverseAPI (`com.github.CodeVerseHub-Minecraft.CodeverseAPI:api`) | 0.2.0 | MIT License |
| BouncyCastle (`org.bouncycastle:bcprov-jdk18on`) | 1.85 | Bouncy Castle License (MIT style) |
| HikariCP (`com.zaxxer:HikariCP`) | 7.1.0 | Apache License 2.0 |
| Caffeine (`com.github.ben-manes.caffeine:caffeine`) | 3.2.4 | Apache License 2.0 |
| Gson (`com.google.code.gson:gson`) | 2.11.0 | Apache License 2.0 |
| Lettuce (`io.lettuce:lettuce-core`) | 7.6.0.RELEASE | Apache License 2.0 |
| Netty (`io.netty:netty-*`) | 4.2.13.Final | Apache License 2.0 |
| Project Reactor (`io.projectreactor:reactor-core`) | 3.6.6 | Apache License 2.0 |
| Reactive Streams (`org.reactivestreams:reactive-streams`) | 1.0.4 | MIT-0 |
| SLF4J API (`org.slf4j:slf4j-api`) | 2.0.17 | MIT License |
| JSpecify (`org.jspecify:jspecify`) | 1.0.0 | Apache License 2.0 |
| Error Prone Annotations (`com.google.errorprone:error_prone_annotations`) | 2.49.0 | Apache License 2.0 |
| Redis AuthX Core (`redis.clients.authentication:redis-authx-core`) | 0.1.1-beta2 | MIT License |
| **MySQL Connector/J** (`com.mysql:mysql-connector-j`) | 9.7.0 | **GPL v2 with Universal FOSS Exception 1.0** |

## A note on CodeverseAPI

CodeverseAPI is bundled deliberately unrelocated, unlike every other library
here. This plugin is the provider of those interfaces rather than a consumer
of them: consumer plugins declare the same coordinate as `compileOnly` and
resolve to this copy at runtime, which is what makes their
`CodeverseApiProvider` and this one the same class holding the same
registration. Relocating it would give every consumer a second set of
interfaces that are not the ones registered here.

## A note on MySQL Connector/J

MySQL Connector/J is the one dependency here that is not permissively
licensed. It is GPL v2, with the Universal FOSS Exception version 1.0.

The Universal FOSS Exception exists precisely so that GPL licensed Oracle
libraries can be combined with software under common open source licenses,
and the MIT License is one of the licenses it names. Distributing this MIT
licensed plugin with the connector bundled is therefore permitted, provided
the connector's own license and notices travel with it, which is why the
jar retains `META-INF/LICENSE` entries rather than stripping them.

If you would rather avoid a GPL component entirely, you have two options,
both supported without code changes:

**Use the MariaDB driver instead.** It speaks the MySQL protocol and works
against both MySQL and MariaDB. Replace the dependency in `build.gradle.kts`:

```kotlin
runtimeOnly("org.mariadb.jdbc:mariadb-java-client:3.5.9")
```

and set the driver in `config.json`:

```json
"driverClassName": "org.mariadb.jdbc.Driver"
```

adjusting `jdbcUrl` to begin `jdbc:mariadb://`.

**Ship no driver at all.** Remove the `runtimeOnly` line entirely and place
a driver jar of your choosing on the proxy yourself. This produces a much
smaller plugin jar and leaves the licensing decision to the operator.

## Apache License 2.0 attribution

Several bundled libraries are Apache 2.0 licensed, which requires that
attribution notices be preserved. The shaded jar keeps `META-INF/LICENSE`
and `META-INF/NOTICE` entries from its dependencies for this reason. If you
fork this project and adjust the shading configuration, do not exclude
those paths.
