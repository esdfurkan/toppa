package dev.toppa.app

import android.app.Application
import dev.toppa.service.RelayForegroundService

/**
 * Application entry: injects the relay runtime factory into the foreground
 * service (the Hilt graph lands with the settings/dashboard milestones —
 * this manual injection point is the seam).
 */
class ToppaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        RelayForegroundService.runtimeFactory =
            RelayForegroundService.RuntimeFactory { context -> AppRuntime.createRelayRuntime(context) }
    }
}
