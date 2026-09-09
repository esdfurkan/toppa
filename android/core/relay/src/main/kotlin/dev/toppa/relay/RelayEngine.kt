package dev.toppa.relay

import dev.toppa.proto.MuxSession
import dev.toppa.proto.MuxStream
import dev.toppa.proto.Tlmp
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * The phone-side relay engine: accepts TLMP streams from a session and
 * re-originates each one as a real socket on the upstream network
 * (docs/ARCHITECTURE.md §1.3). Every flow the PC tunnels through here
 * egresses with Android-native characteristics — TTL 64, Android TCP stack —
 * which is the core bypass property of the whole system.
 *
 * Per-connection upstream pinning: production callers inject an
 * [UpstreamProvider] bound to the cellular Network; the loop guard rejects
 * any upstream that equals the transport's network.
 */
class RelayEngine(
    private val upstream: UpstreamProvider,
    private val resolver: Resolver? = null,
    private val config: RelayConfig = RelayConfig(),
) {
    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "toppa-relay-flow").apply { isDaemon = true }
    }
    private val activeStreams = AtomicInteger(0)

    /** Serves streams until the session closes, then closes the session. */
    fun serveSession(session: MuxSession, transportId: String) {
        try {
            while (true) {
                val stream = session.accept() ?: break
                if (activeStreams.incrementAndGet() > config.maxStreams) {
                    activeStreams.decrementAndGet()
                    runCatching { stream.close() }
                    continue
                }
                executor.submit {
                    try {
                        handleStream(stream, transportId)
                    } finally {
                        activeStreams.decrementAndGet()
                    }
                }
            }
        } finally {
            session.close()
        }
    }

    private fun handleStream(stream: MuxStream, transportId: String) {
        var upstreamSocket: UpstreamSocket? = null
        try {
            upstreamSocket = connectUpstream(stream.target, transportId)
            val socket = upstreamSocket.socket
            socket.tcpNoDelay = true

            // Remote → client (sockets have no FIN message; close = RST for the client).
            val remoteToClient = thread(name = "toppa-up", isDaemon = true) {
                try {
                    val buf = ByteArray(config.bufferBytes)
                    while (true) {
                        val n = socket.getInputStream().read(buf)
                        if (n < 0) break
                        stream.write(buf, 0, n)
                    }
                    stream.close() // FIN toward the client
                } catch (e: Exception) {
                    runCatching { stream.close() }
                }
            }

            // Client → remote; half-close the socket when the client FINs.
            try {
                val buf = ByteArray(config.bufferBytes)
                while (true) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    socket.getOutputStream().write(buf, 0, n)
                }
                socket.getOutputStream().flush()
                runCatching { socket.shutdownOutput() }
            } catch (e: Exception) {
                runCatching { socket.close() }
            }
            remoteToClient.join()
        } catch (e: Exception) {
            runCatching { stream.close() }
            upstreamSocket?.socket?.close()
        } finally {
            runCatching { stream.close() }
        }
    }

    private fun connectUpstream(target: Target, transportId: String): UpstreamSocket {
        return when (target.atyp) {
            Tlmp.ATYP_FQDN -> {
                val host = String(target.address, Charsets.US_ASCII)
                val address = if (resolver != null && config.resolveDomains) {
                    resolver.resolve(host).firstOrNull()
                        ?: throw UpstreamUnavailableException("relay: no addresses for $host")
                } else {
                    InetAddress.getByName(host) // phone_system mode
                }
                upstream.connect(address, target.port, transportId)
            }
            Tlmp.ATYP_IPV4, Tlmp.ATYP_IPV6 ->
                upstream.connect(InetAddress.getByAddress(target.address), target.port, transportId)
            else -> throw IOException("relay: bad atyp ${target.atyp}")
        }
    }
}
