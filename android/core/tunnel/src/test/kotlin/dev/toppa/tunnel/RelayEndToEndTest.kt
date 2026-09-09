package dev.toppa.tunnel

import com.sun.net.httpserver.HttpServer
import dev.toppa.proto.MuxConfig
import dev.toppa.proto.MuxSession
import dev.toppa.proto.Target
import dev.toppa.proto.Tlmp
import dev.toppa.proto.crypto.Role
import dev.toppa.proto.crypto.TunnelHandshake
import dev.toppa.proto.crypto.X25519
import dev.toppa.relay.DefaultUpstreamProvider
import dev.toppa.relay.RelayEngine
import dev.toppa.transport.TcpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The JVM analog of the Step 2 exit criterion "an external harness fetches
 * HTTP through the phone": a real HTTP server plays the internet, the full
 * phone-side stack (transport → Noise_XX responder → TLMP mux → relay engine
 * → upstream socket) runs in-process, and a Noise initiator client fetches a
 * page through all of it. The Go↔Kotlin interop job covers the crypto
 * cross-language; this test covers the relay plumbing.
 */
class RelayEndToEndTest {

    @Test
    fun `http request through the full phone-side stack`() {
        val body = "toppa relay e2e ok"
        val http = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        http.createContext("/toppa") { exchange ->
            val bytes = body.toByteArray()
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        http.start()

        val transport = TcpServer("loopback", InetAddress.getLoopbackAddress(), 0)
        val serverIdentity = X25519.generatePrivateKey()
        val tunnel = TunnelServer(
            transport = transport,
            identity = object : RelayIdentity {
                override val staticPrivate: ByteArray = serverIdentity
                override val pinnedPeer: ByteArray? = null
            },
            relay = RelayEngine(
                upstream = DefaultUpstreamProvider(networkId = "jvm-upstream"),
                resolver = null,
            ),
        )
        tunnel.start()
        val relayPort = transport.boundPort ?: fail("transport did not bind")

        try {
            Socket(InetAddress.getLoopbackAddress(), relayPort).use { socket ->
                socket.tcpNoDelay = true
                socket.soTimeout = 15_000
                val handshake = TunnelHandshake.handshake(
                    socket.getInputStream(),
                    socket.getOutputStream(),
                    Role.INITIATOR,
                    X25519.generatePrivateKey(),
                )
                MuxSession(handshake.channel, MuxConfig(isInitiator = true)).use { session ->
                    val target = Target(
                        network = Tlmp.NET_TCP,
                        atyp = Tlmp.ATYP_IPV4,
                        address = InetAddress.getByName("127.0.0.1").address,
                        port = http.address.port,
                    )
                    val stream = session.open(target)
                    stream.write("GET /toppa HTTP/1.1\r\nHost: toppa.test\r\nConnection: close\r\n\r\n".toByteArray())

                    val response = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    while (true) {
                        val n = stream.read(buf)
                        if (n < 0) break // relay FINs us when the HTTP server closes
                        response.write(buf, 0, n)
                    }
                    val text = response.toString("UTF-8")
                    assertTrue(text.startsWith("HTTP/1.1 200"), "expected HTTP 200, got: ${text.take(40)}")
                    assertTrue(text.contains(body), "expected relayed body, got: ${text.take(120)}")
                    stream.close()
                }
            }
        } finally {
            tunnel.stop()
            http.stop(0)
        }
    }
}
