package dev.toppa.app

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import dev.toppa.relay.DnsShield
import dev.toppa.relay.DohResolver
import dev.toppa.relay.Resolver
import dev.toppa.vpn.UdpDnsReply
import kotlin.concurrent.thread

/**
 * Shield-mode VpnService (docs/ARCHITECTURE.md §1.1 L1 — DNS shield): the TUN
 * routes ONLY the resolver address; DNS queries that arrive are answered
 * locally via DoH, so no plaintext DNS leaves the phone. This is a VPN in
 * service of DNS hardening only — it intentionally does not forward other
 * traffic (that is the relay's job for PC flows; phone apps already egress
 * with native TTL 64).
 */
class ToppaVpnService : VpnService() {

    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var running = false

    private val resolver: Resolver by lazy {
        DohResolver(listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"))
    }

    override fun onRevoke() {
        // The user (or the system) revoked VPN consent: clean teardown.
        stopShield()
    }

    override fun onDestroy() {
        stopShield()
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopShield()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startShield()
        }
        return START_STICKY
    }

    private fun startShield() {
        if (running) {
            return
        }
        // VpnService.prepare() is handled by the activity before starting us.
        tunnel = Builder()
            .setSession("Toppa DNS shield")
            .setMtu(1500)
            .addAddress(SHIELD_ADDRESS, 32)
            .addRoute(SHIELD_ADDRESS, 32) // only resolver-bound traffic reaches us
            .addDnsServer(SHIELD_ADDRESS)
            .establish() ?: run {
            stopSelf()
            return
        }
        running = true
        worker = thread(name = "toppa-shield") { shieldLoop() }
    }

    private fun stopShield() {
        running = false
        runCatching { tunnel?.close() }
        tunnel = null
    }

    private fun shieldLoop() {
        val fd = tunnel ?: return
        val input = ParcelFileDescriptor.AutoCloseInputStream(fd)
        val output = ParcelFileDescriptor.AutoCloseOutputStream(tunnel ?: return)
        val buffer = ByteArray(32 * 1024)
        while (running) {
            val n = try {
                input.read(buffer)
            } catch (e: Exception) {
                break
            }
            if (n <= 0) break
            val response = handleDnsPacket(buffer, n) ?: continue
            runCatching { output.write(response, 0, response.size) }
        }
    }

    /** Returns the wire reply packet for a DNS query datagram, or null to drop. */
    private fun handleDnsPacket(packet: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8 + 12) return null
        if (packet[9].toInt() != 17) return null // UDP only

        val udpPayload = length - ihl - 8
        val query = packet.copyOfRange(ihl + 8, length)
        if (!DnsShield.isQuery(query)) return null
        val name = DnsShield.queryName(query) ?: return null

        val addresses = try {
            resolver.resolve(name)
        } catch (e: Exception) {
            return null
        }
        val response = DnsShield.buildResponse(query, addresses)
        return UdpDnsReply.build(packet, length, response)
    }

    companion object {
        const val ACTION_START = "dev.toppa.app.SHIELD_START"
        const val ACTION_STOP = "dev.toppa.app.SHIELD_STOP"
        private const val SHIELD_ADDRESS = "10.112.0.1"

        /** Launch helper: runs the system consent flow, then starts the service. */
        fun prepareAndStart(activity: android.app.Activity, onReady: (Intent) -> Unit) {
            val intent = Intent(activity, ToppaVpnService::class.java).setAction(ACTION_START)
            val consent = VpnService.prepare(activity)
            if (consent == null) {
                onReady(intent)
            } else {
                // The activity result path lives in MainActivity's launcher.
                activity.startActivityForResult(consent, REQUEST_CONSENT)
            }
        }

        const val REQUEST_CONSENT = 47471
    }
}
