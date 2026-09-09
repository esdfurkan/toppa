package dev.toppa.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import dev.toppa.tunnel.RelayRuntime
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Foreground service hosting the relay stack (docs/ARCHITECTURE.md §2.4).
 * Owns the notification, the Wi-Fi/wake locks, and the START_STICKY
 * lifecycle (OS restart after process death → RelayRuntime cold-start
 * reconciliation re-binds the transport).
 *
 * Battery rules encoded here: locks are held only while the relay runs and
 * are released on stop; the notification is low-importance; the Wi-Fi lock
 * uses LOW_LATENCY on API 29+ for SoftAP/WFD throughput.
 *
 * DI: :app sets [runtimeFactory] at startup (Hilt once :app exists). The
 * app manifest must declare this service with a foregroundServiceType of
 * dataSync (specialUse fallback is documented in the architecture).
 */
class RelayForegroundService : Service() {

    /** Supplies the running relay stack; wired by :app, faked by tests. */
    interface RuntimeFactory {
        fun create(context: Context): RelayRuntime
    }

    companion object {
        const val ACTION_START = "dev.toppa.service.START"
        const val ACTION_STOP = "dev.toppa.service.STOP"

        @Volatile
        var runtimeFactory: RuntimeFactory? = null

        private const val CHANNEL_ID = "toppa_relay"
        private const val NOTIFICATION_ID = 1
    }

    private var runtime: RelayRuntime? = null
    private var executor: ExecutorService? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopRelay()
            stopSelf()
            return START_NOT_STICKY
        }
        startRelay()
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Foreground services survive task removal by design — keep relaying.
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        stopRelay()
        super.onDestroy()
    }

    private fun startRelay() {
        if (runtime != null) {
            return
        }
        val factory = runtimeFactory ?: run {
            stopSelf()
            return
        }
        startForeground(NOTIFICATION_ID, buildNotification("Toppa relay starting"))
        acquireLocks()
        val relayRuntime = factory.create(this)
        runtime = relayRuntime
        val pool = Executors.newSingleThreadExecutor { r -> Thread(r, "toppa-relay-worker") }
        executor = pool
        pool.submit {
            try {
                relayRuntime.runBlocking()
            } catch (e: InterruptedException) {
                // Service stopping; exit the worker.
            }
        }
        updateNotification("Toppa relay active")
    }

    private fun stopRelay() {
        runtime?.close()
        runtime = null
        executor?.let { pool ->
            pool.shutdown()
            runCatching { pool.awaitTermination(2, TimeUnit.SECONDS) }
        }
        executor = null
        releaseLocks()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    @Suppress("DEPRECATION") // WifiLock APIs are deprecated on 31+ but still the right tool here
    private fun acquireLocks() {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "toppa:relay").apply {
            setReferenceCounted(false)
            acquire()
        }
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val mode = if (Build.VERSION.SDK_INT >= 29) {
            WifiManager.WIFI_MODE_FULL_LOW_LATENCY
        } else {
            WifiManager.WIFI_MODE_FULL_HIGH_PERF
        }
        wifiLock = wifi.createWifiLock(mode, "toppa:wifi").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseLocks() {
        runCatching { wifiLock?.release() }
        runCatching { wakeLock?.release() }
        wifiLock = null
        wakeLock = null
    }

    private fun createChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Toppa relay", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun buildNotification(text: String): Notification {
        // Generic system icon until :app supplies the real one.
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Toppa")
            .setContentText(text)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
