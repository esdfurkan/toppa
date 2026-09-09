package dev.toppa.proto

import dev.toppa.proto.crypto.Role
import dev.toppa.proto.crypto.SecureChannel
import dev.toppa.proto.crypto.TunnelHandshake
import dev.toppa.proto.crypto.X25519
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Live Go↔Kotlin interop: Noise_XX handshake, AEAD records, and a TLMP echo
 * against `desktop/cmd/toppactl serve`. Skipped unless TOPPA_INTEROP_ADDR is
 * set — the protocol-interop CI job wires the Go responder up. This test is
 * the correctness gate for NoiseHandshake/X25519/ChaChaPoly on the Kotlin
 * side; Go is the reference implementation.
 */
class InteropTest {

    @Test
    @Timeout(60)
    fun `noise xx handshake and tlmp echo against go responder`() {
        val addr = System.getenv("TOPPA_INTEROP_ADDR")
        assumeTrue(addr != null, "TOPPA_INTEROP_ADDR not set; interop runs in the protocol-interop CI job")
        val host = addr.substringBeforeLast(':')
        val port = addr.substringAfterLast(':').toInt()

        Socket(host, port).use { socket ->
            socket.tcpNoDelay = true
            val identity = X25519.generatePrivateKey()
            val result = TunnelHandshake.handshake(
                socket.getInputStream(),
                socket.getOutputStream(),
                Role.INITIATOR,
                identity,
            )
            println("[interop] handshake ok · SAS=${result.sas} · peer=${result.peerStatic.size} bytes")
            println("[interop] confirm the responder console prints the same SAS: ${result.sas}")

            val mux = MiniMuxClient(result.channel)
            val target = Target(
                network = Tlmp.NET_TCP,
                atyp = Tlmp.ATYP_FQDN,
                address = "echo.toppa.test".toByteArray(Charsets.US_ASCII),
                port = 443,
            )
            val payload = ByteArray(64 * 1024) { (it * 31).toByte() }
            val echoed = mux.echoRoundTrip(target, payload)
            assertTrue(payload.contentEquals(echoed), "echo payload mismatch")
            println("[interop] TLMP echo round-trip ok (${payload.size} bytes)")
        }
    }
}

/**
 * Minimal TLMP client used only by the interop test: one stream, one
 * echo round trip, tolerant frame reading (WIN/PING/PONG/GOAWAY). The full
 * session implementation (flow control, concurrency, keepalives) lands with
 * :core:tunnel in Step 2.
 */
class MiniMuxClient(private val channel: SecureChannel) {

    private val channelInput: InputStream = object : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            val n = channel.read(one)
            return if (n <= 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (off == 0 && b.size == len) {
                return channel.read(b)
            }
            val tmp = ByteArray(len)
            val n = channel.read(tmp)
            if (n > 0) {
                System.arraycopy(tmp, 0, b, off, n)
            }
            return n
        }
    }

    fun echoRoundTrip(target: Target, payload: ByteArray): ByteArray {
        val streamId = 1 // initiator side: odd ids
        val syn = ByteArrayOutputStream().also {
            Tlmp.writeFrame(it, Flags.SYN, streamId, Tlmp.appendTarget(ByteArray(0), target))
        }.toByteArray()
        val data = ByteArrayOutputStream().also {
            Tlmp.writeFrame(it, Flags.DATA, streamId, payload)
        }.toByteArray()
        val fin = ByteArrayOutputStream().also {
            Tlmp.writeFrame(it, Flags.FIN, streamId, ByteArray(0))
        }.toByteArray()
        channel.write(syn)
        channel.write(data)
        channel.write(fin)

        val echoed = ByteArray(payload.size)
        var filled = 0
        var finSeen = false
        while (filled < payload.size) {
            val frame = Tlmp.readFrame(channelInput, MAX_FRAME_PAYLOAD)
            when {
                frame.flags and Flags.DATA != 0 -> {
                    val n = minOf(frame.payload.size, payload.size - filled)
                    if (n <= 0) {
                        fail("responder sent more echo data than expected")
                    }
                    System.arraycopy(frame.payload, 0, echoed, filled, n)
                    filled += n
                    channel.write(windowUpdate(streamId, frame.payload.size))
                }
                frame.flags and Flags.FIN != 0 -> finSeen = true
                frame.flags and Flags.PING != 0 -> channel.write(controlFrame(Flags.PONG, frame.payload))
                frame.flags and Flags.GOAWAY != 0 -> throw IOException("responder sent GOAWAY mid-echo")
                else -> { /* WIN on our stream: nothing to do for a small transfer */ }
            }
        }
        if (!finSeen) {
            // Tolerate a trailing FIN arriving after the last data frame.
            val trailing = Tlmp.readFrame(channelInput, MAX_FRAME_PAYLOAD)
            assertTrue(trailing.flags and Flags.FIN != 0, "expected FIN after echo, got flags=0x${trailing.flags.toString(16)}")
        }
        return echoed
    }

    private fun windowUpdate(streamId: Int, credit: Int): ByteArray {
        val creditBytes = ByteArray(4)
        creditBytes[0] = (credit ushr 24).toByte()
        creditBytes[1] = (credit ushr 16).toByte()
        creditBytes[2] = (credit ushr 8).toByte()
        creditBytes[3] = credit.toByte()
        return controlFrame(Flags.WIN, streamId, creditBytes)
    }

    private fun controlFrame(flags: Int, streamId: Int, payload: ByteArray): ByteArray =
        ByteArrayOutputStream().also { Tlmp.writeFrame(it, flags, streamId, payload) }.toByteArray()

    private fun controlFrame(flags: Int, payload: ByteArray): ByteArray =
        controlFrame(flags, 0, payload)

    companion object {
        // Matches the Go responder's configured max frame payload (defaults).
        const val MAX_FRAME_PAYLOAD = 65536
    }
}
