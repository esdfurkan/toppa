pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "toppa-android"

// Pure-JVM modules: build and test in desktop CI without the Android SDK.
// :core:proto must stay Android-free at all times (CI interop depends on it).
include(":core:proto")     // TLMP codec, Noise, SAS, mux session
include(":core:vpn")       // packet parser, TTL/HL rewrite, Shield-mode engine
include(":core:relay")     // stream→socket engine, resolver/DoH, loop guard
include(":core:transport") // transport servers (adb/loopback now, SoftAP/WFD later)
include(":core:tunnel")    // phone-side session orchestration

// Android-only modules: NOT included yet. They need the Android SDK + AGP
// and are compiled by the :app milestone (Step 5) and CI's emulator job.
// Their sources and build files are committed so the wiring is reviewable.
// include(":core:service")
// include(":app")
