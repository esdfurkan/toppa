package dev.toppa.app

import android.content.Context
import dev.toppa.relay.UpstreamProvider
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Upstream selection with real cellular pinning (docs/ARCHITECTURE.md §1.3):
 * relay sockets bind to the ConnectivityManager-selected TRANSPORT_CELLULAR
 * network, so relay traffic can never fall out of the hotspot interface.
 * The loop guard lives in [connect].
 */
class AndroidUpstreamProvider(context: Context) : UpstreamProvider {

    override val networkId: String = "cellular"

    private val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
    @Volatile private var cellular: android.net.Network? = null

    private fun cellularNetwork(): android.net.Network? {
        cellular?.let { return it }
        val latch = CountDownLatch(1)
        var found: android.net.Network? = null
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
            .build()
        val callback = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                found = network
                latch.countDown()
            }
        }
        try {
            connectivity.requestNetwork(request, callback)
            latch.await(3, TimeUnit.SECONDS)
        } catch (e: Exception) {
            // fall through: found may be null
        } finally {
            runCatching { connectivity.unregisterNetworkCallback(callback) }
        }
        cellular = found
        return found
    }

    override fun connect(host: InetAddress, port: Int, transportId: String): UpstreamSocket {
        if (transportId == networkId) {
            throw dev.toppa.relay.LoopGuardViolation(
                "relay: upstream 'cellular' equals transport '$transportId' — refusing routing loop",
            )
        }
        val network = cellularNetwork()
            ?: throw dev.toppa.relay.UpstreamUnavailableException("relay: no cellular network available")
        val socket = network.socketFactory.createSocket()
        socket.connect(java.net.InetSocketAddress(host, port))
        return UpstreamSocket(socket)
    }
}

/**
 * Discovers the SoftAP interface address at runtime by scanning for a
 * private IPv4 on any non-cellular interface. Heuristic by necessity (the
 * clean tethering APIs are hidden) — `transport.hotspot_addr` in the shared
 * config is the deterministic override.
 */
class AndroidApAddressProvider : dev.toppa.transport.ApAddressProvider {
    override fun hotspotAddress(): InetAddress {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: throw IllegalStateException("no network interfaces")
        for (nif in interfaces.asSequence()) {
            if (nif.name.startsWith("rmnet") || nif.name.startsWith("ccmni")) {
                continue // cellular data interfaces
            }
            for (addr in nif.inetAddresses) {
                if (!addr.isLoopbackAddress && addr is java.net.Inet4Address && addr.isSiteLocalAddress) {
                    return addr
                }
            }
        }
        throw IllegalStateException("hotspot interface address not found; enable the hotspot or set transport.hotspot_addr")
    }
}
