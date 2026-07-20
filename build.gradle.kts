plugins {
    java
    id("com.gradleup.shadow") version "9.6.0"
}

group = "net.codeverse"
version = "0.1.0"

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly("com.velocitypowered:velocity-api:4.0.0")
    annotationProcessor("com.velocitypowered:velocity-api:4.0.0")
    compileOnly("net.luckperms:api:5.5")

    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("com.zaxxer:HikariCP:7.1.0")
    implementation("io.lettuce:lettuce-core:7.6.0.RELEASE")
    implementation("com.github.ben-manes.caffeine:caffeine:3.2.4")
    implementation("com.google.code.gson:gson:2.11.0")
    runtimeOnly("com.mysql:mysql-connector-j:9.7.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.release.set(25)
    options.compilerArgs.add("-Xlint:deprecation")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    // Service files must reach mergeServiceFiles() rather than being dropped
    // as duplicates on the way in. This matters most for
    // META-INF/services/java.sql.Driver: losing it is what produces a
    // "No suitable driver" failure at runtime despite the driver being
    // present in the jar.
    duplicatesStrategy = DuplicatesStrategy.INCLUDE

    archiveBaseName.set("CodeverseAuth")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())

    // Relocated so a different version of any of these shipped by another
    // plugin on the same proxy cannot collide with ours.
    relocate("org.bouncycastle", "net.codeverse.libs.bouncycastle")
    relocate("com.zaxxer.hikari", "net.codeverse.libs.hikari")
    relocate("io.lettuce", "net.codeverse.libs.lettuce")
    relocate("com.github.benmanes.caffeine", "net.codeverse.libs.caffeine")
    relocate("com.google.gson", "net.codeverse.libs.gson")

    mergeServiceFiles()

    // Deliberately no minimize(). Caffeine selects its cache implementation
    // reflectively by generated class name (SSMSW and siblings), and Lettuce
    // and the MySQL driver also resolve classes reflectively, so minimization
    // strips classes that are provably needed at runtime but invisible to
    // static analysis. The failure only appears once the plugin actually
    // runs, which makes the few megabytes saved a bad trade.
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
