plugins {
    kotlin("jvm") version "1.9.24"
}

// Pure JVM (17) by design: :core:proto must compile and run in desktop CI for
// Go↔Kotlin golden-vector interop (protocol/SPEC.md §5). Do not add Android
// dependencies here.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// Golden-vector tests land with the Step 1 interop milestone; the vector
// files are shared verbatim with the Go implementation.
dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
    // JSON parsing for protocol/vectors/*.json (test scope only).
    testImplementation("com.google.code.gson:gson:2.11.0")
}

tasks.test {
    useJUnitPlatform()
    // Per-test outcomes in CI logs: pinpoint hangs and failures at a glance.
    testLogging {
        events("passed", "failed", "skipped")
        showExceptions = true
        showStackTraces = true
    }
}
