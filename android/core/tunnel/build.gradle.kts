plugins {
    kotlin("jvm")
}

// Pure JVM: phone-side orchestration (transport → handshake → mux → relay).
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":core:proto"))
    implementation(project(":core:relay"))
    implementation(project(":core:transport"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
