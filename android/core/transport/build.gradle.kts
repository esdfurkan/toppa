plugins {
    kotlin("jvm")
}

// Pure JVM: transports hand raw Sockets to :core:tunnel; the SoftAP address
// discovery is behind ApAddressProvider (Android impl in the app layer).
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
