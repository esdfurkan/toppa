plugins {
    id("com.android.library") version "8.5.2"
    kotlin("android") version "1.9.24"
}

// Android-only module (foreground service). NOT included in settings.gradle
// yet — it requires the Android SDK + AGP and is compiled by the :app
// milestone (roadmap Step 5). Sources are committed so the lifecycle wiring
// is reviewable now.
android {
    namespace = "dev.toppa.service"
    compileSdk = 35
    defaultConfig {
        minSdk = 26
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":core:tunnel"))
}
