// Root build for the Toppa Android project. Modules are pure JVM unless they
// explicitly opt into Android (e.g. :core:service) — that keeps the protocol
// and engine layers CI-testable without the Android SDK.
plugins {
    kotlin("jvm") version "1.9.24" apply false
}
