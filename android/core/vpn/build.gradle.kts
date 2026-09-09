plugins {
    kotlin("jvm")
}

// Pure JVM by design: the packet engine must be unit-testable without a
// device or the Android SDK. The VpnService fd adapter lives in the app layer
// and plugs into PacketSource/PacketSink.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
    // JSON parsing for protocol/vectors/packets.json (test scope only).
    testImplementation("com.google.code.gson:gson:2.11.0")
}

tasks.test {
    useJUnitPlatform()
}
