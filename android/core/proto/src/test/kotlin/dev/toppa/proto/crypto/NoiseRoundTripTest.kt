package dev.toppa.proto.crypto

import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals

/** Kotlin↔Kotlin Noise round trip: isolates implementation bugs from cross-language interop issues. */
class NoiseRoundTripTest {

    @Test
    fun `kotlin initiator and responder complete a handshake`() {
        // inA/outA belong to the initiator, inB/outB to the responder;
        // outA feeds inB and outB feeds inA.
        val inA = PipedInputStream()
        val outA = PipedOutputStream()
        val inB = PipedInputStream()
        val outB = PipedOutputStream()
        inA.connect(outB)
        inB.connect(outA)

        val responderResult = arrayOfNulls<TunnelHandshake.Result>(1)
        val responder = Thread {
            responderResult[0] = TunnelHandshake.handshake(
                inB, outB, Role.RESPONDER, X25519.generatePrivateKey(),
            )
        }
        responder.start()

        val initiator = TunnelHandshake.handshake(
            inA, outA, Role.INITIATOR, X25519.generatePrivateKey(),
        )
        responder.join(10_000)

        val resp = responderResult[0] ?: kotlin.test.fail("responder handshake did not complete")
        assertEquals(initiator.sas, resp.sas, "SAS must match on both ends")
    }
}
