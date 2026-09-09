plugins {
    kotlin("jvm")
}

// Pure JVM: Android touchpoints (ConnectivityManager pinning, WifiManager AP
// address discovery) are isolated behind UpstreamProvider / ApAddressProvider
// interfaces and injected by the app layer.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":core:proto"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
