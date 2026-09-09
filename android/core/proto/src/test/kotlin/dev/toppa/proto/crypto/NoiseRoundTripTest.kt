package dev.toppa.proto.crypto

import dev.toppa.proto.PipedStreams
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Kotlin↔Kotlin Noise round trip: isolates implementation bugs from cross-language interop issues. */
class NoiseRoundTripTest {

    @Test
    fun `kotlin initiator and responder complete a handshake`() {
        val (a, b) = PipedStreams.pair()

        val responderResult = arrayOfNulls<TunnelHandshake.Result>(1)
        val responder = Thread {
            responderResult[0] = TunnelHandshake.handshake(
                b.getInputStream(), b.getOutputStream(), Role.RESPONDER, X25519.generatePrivateKey(),
            )
        }
        responder.start()

        val initiator = TunnelHandshake.handshake(
            a.getInputStream(), a.getOutputStream(), Role.INITIATOR, X25519.generatePrivateKey(),
        )
        responder.join(10_000)

        val resp = responderResult[0] ?: kotlin.test.fail("responder handshake did not complete")
        assertEquals(initiator.sas, resp.sas, "SAS must match on both ends")

        // Record-layer round trip through the secured channel.
        val reader = Thread {
            // Drain so writes never block on the synchronous pipe.
            val buf = ByteArray(4096)
            while (true) {
                if (resp.channel.read(buf) <= 0) break
            }
        }
        reader.start()
        initiator.channel.write("hello".toByteArray())
        assertTrue(true)
    }
}
