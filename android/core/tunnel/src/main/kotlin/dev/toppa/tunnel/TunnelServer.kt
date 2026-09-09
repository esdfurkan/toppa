package dev.toppa.tunnel

import dev.toppa.proto.MuxConfig
import dev.toppa.proto.crypto.Role
import dev.toppa.proto.crypto.TunnelHandshake
import dev.toppa.relay.RelayEngine
import dev.toppa.transport.TransportServer
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** The phone's Noise static identity (Keystore-wrapped storage lands in :app). */
interface RelayIdentity {
    val staticPrivate: ByteArray
    /** Pinned PC static key from pairing; null until first pairing completes. */
    val pinnedPeer: ByteArray?
}

/**
 * Phone-side session orchestration (roadmap Step 2): transport connection →
 * Noise_XX as responder → TLMP session → [RelayEngine]. Each accepted socket
 * is one PC connection; connection churn is handled per-connection, and the
 * mux's PING/PONG keepalive detects dead links.
 */
class TunnelServer(
    private val transport: TransportServer,
    private val identity: RelayIdentity,
    private val relay: RelayEngine,
    private val muxConfig: MuxConfig = MuxConfig(isInitiator = false),
    private val handshakeTimeoutMillis: Int = 5_000,
) {
    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "toppa-tunnel-worker").apply { isDaemon = true }
    }
    @Volatile private var started = false

    fun start() {
        check(!started) { "tunnel server already started" }
        started = true
        transport.start(::onConnection)
    }

    fun stop() {
        if (!started) {
            return
        }
        started = false
        transport.stop()
        executor.shutdown()
        executor.awaitTermination(2, TimeUnit.SECONDS)
    }

    private fun onConnection(socket: Socket) {
        executor.submit { handleConnection(socket) }
    }

    private fun handleConnection(socket: Socket) {
        try {
            socket.use {
                socket.soTimeout = handshakeTimeoutMillis
                val result = TunnelHandshake.handshake(
                    socket.getInputStream(),
                    socket.getOutputStream(),
                    Role.RESPONDER,
                    identity.staticPrivate,
                    identity.pinnedPeer,
                )
                // Handshake done; the mux keepalive governs liveness from here.
                socket.soTimeout = 0
                val session = MuxSession(result.channel, muxConfig.copy(isInitiator = false))
                relay.serveSession(session, transport.id)
            }
        } catch (e: Exception) {
            // Unpaired peer, pin mismatch, or transport death: drop quietly.
            runCatching { socket.close() }
        }
    }
}

/**
 * Blocking runtime handle for the foreground service: [runBlocking] parks the
 * service worker thread until [close] (service stop) tears the stack down.
 */
class RelayRuntime(private val server: TunnelServer) : AutoCloseable {
    private val stopped = CountDownLatch(1)

    fun runBlocking() {
        server.start()
        stopped.await()
    }

    override fun close() {
        runCatching { server.stop() }
        stopped.countDown()
    }
}
