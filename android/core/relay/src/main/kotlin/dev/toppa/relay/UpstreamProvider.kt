package dev.toppa.relay

import dev.toppa.proto.Target
import java.io.IOException
import java.net.InetAddress
import java.net.Socket

/** The upstream refused the association: relay-side failure (not a protocol error). */
class UpstreamUnavailableException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Thrown when an upstream would egress through the same network the transport
 * itself rides — the routing loop that SoftAP mode must never enter
 * (docs/ARCHITECTURE.md §1.3, "upstream pinning + loop guard").
 */
class LoopGuardViolation(message: String) : IOException(message)

/** A connected upstream socket owned by the relay. */
class UpstreamSocket(val socket: Socket)

/**
 * Selects and opens the upstream network path for relayed flows.
 *
 * Production implementation (app layer): `ConnectivityManager.requestNetwork`
 * with TRANSPORT_CELLULAR + per-socket `Network.bindSocket`, so relay traffic
 * can never fall out of the hotspot interface. The JVM default connects
 * directly and is what CI tests use.
 */
interface UpstreamProvider {
    /** Stable identity of the upstream network (loop-guard comparison key). */
    val networkId: String

    fun connect(host: InetAddress, port: Int, transportId: String): UpstreamSocket
}

/** Plain-socket upstream: JVM tests, and phones without per-network pinning. */
class DefaultUpstreamProvider(override val networkId: String) : UpstreamProvider {
    override fun connect(host: InetAddress, port: Int, transportId: String): UpstreamSocket {
        if (transportId == networkId) {
            throw LoopGuardViolation(
                "relay: upstream network '$networkId' equals transport '$transportId' — refusing routing loop",
            )
        }
        return try {
            UpstreamSocket(Socket(host, port))
        } catch (e: Exception) {
            throw UpstreamUnavailableException("relay: connect $host:$port failed", e)
        }
    }
}

/**
 * Relay tuning. Defaults mirror configs/defaults.json (`relay.*`) — the app
 * layer maps persisted config onto this; nothing operational is hardcoded in
 * the engine.
 */
data class RelayConfig(
    val maxStreams: Int = 256,
    val bufferBytes: Int = 256 * 1024,
    /** Resolve FQDN targets through [Resolver] instead of the system stack. */
    val resolveDomains: Boolean = true,
)

/** Name resolution strategy for FQDN targets (SPEC/architecture §1.5). */
interface Resolver {
    fun resolve(name: String): List<InetAddress>
}

/** Phone-system resolution: maximum traffic realism, least privacy. */
class SystemDnsResolver : Resolver {
    override fun resolve(name: String): List<InetAddress> = InetAddress.getAllByName(name).toList()
}
