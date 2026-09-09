package dev.toppa.proto.crypto

import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Kotlin↔Kotlin Noise round trip: isolates implementation bugs from
 * cross-language interop issues. Both roles run with hard deadlines so a
 * protocol stall fails instead of hanging CI.
 */
class NoiseRoundTripTest {

    @Test
    fun `kotlin initiator and responder complete a handshake`() {
        val inA = PipedInputStream()
        val outA = PipedOutputStream()
        val inB = PipedInputStream()
        val outB = PipedOutputStream()
        inA.connect(outB)
        inB.connect(outA)

        val responderResult = arrayOfNulls<TunnelHandshake.Result>(1)
        val initiatorResult = arrayOfNulls<TunnelHandshake.Result>(1)
        val errors = mutableListOf<Exception>()

        val responder = Thread {
            try {
                responderResult[0] = TunnelHandshake.handshake(
                    inB, outB, Role.RESPONDER, X25519.generatePrivateKey(),
                )
            } catch (e: Exception) {
                errors.add(e)
            }
        }
        val initiator = Thread {
            try {
                initiatorResult[0] = TunnelHandshake.handshake(
                    inA, outA, Role.INITIATOR, X25519.generatePrivateKey(),
                )
            } catch (e: Exception) {
                errors.add(e)
            }
        }
        responder.start()
        initiator.start()
        responder.join(15_000)
        initiator.join(15_000)

        assertTrue(!responder.isAlive || responderResult[0] != null, "responder handshake hung")
        assertTrue(!initiator.isAlive || initiatorResult[0] != null, "initiator handshake hung")
        assertEquals(0, errors.size, "handshake errors: $errors")

        val ini = initiatorResult[0] ?: fail("no initiator result")
        val resp = responderResult[0] ?: fail("no responder result")
        assertEquals(ini.sas, resp.sas, "SAS must match on both ends")
    }

    private fun fail(msg: String): Nothing = throw AssertionError(msg)
}
