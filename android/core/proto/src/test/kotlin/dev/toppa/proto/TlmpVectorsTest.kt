package dev.toppa.proto

import com.google.gson.Gson
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Consumes protocol/vectors/frames.json — the same file the Go
 * implementation is tested against (desktop/internal/mux/vectors_test.go).
 * Skipped when the repository root is not present (standalone module builds).
 */
class TlmpVectorsTest {

    private val vectorsDir = File("../../../protocol/vectors")
    private val gson = Gson()

    private fun vectorsFile(name: String): File {
        val file = vectorsDir.resolve(name)
        assumeTrue(file.exists(), "golden vectors not found at ${file.absolutePath}; full checkout required")
        return file
    }

    private fun hexToBytes(s: String): ByteArray =
        ByteArray(s.length / 2) { i -> ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte() }

    private fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `frame vectors round trip`() {
        val vectors = gson.fromJson(vectorsFile("frames.json").readText(), FramesVector::class.java)
        assertEquals("TLMP", vectors.protocol)
        for (case in vectors.cases) {
            val encoded = hexToBytes(case.encodedHex)
            val maxPayload = case.maxPayload.toInt()
            when (case.kind) {
                "valid" -> {
                    val frame = Tlmp.readFrame(ByteArrayInputStream(encoded), maxPayload)
                    assertEquals(case.version, 1, case.name)
                    assertEquals(case.flags, frame.flags, case.name)
                    assertEquals(case.streamId, frame.streamId, case.name)
                    assertEquals(case.payloadHex, bytesToHex(frame.payload), case.name)

                    val reencoded = ByteArrayOutputStream().also {
                        Tlmp.writeFrame(it, frame.flags, frame.streamId, frame.payload)
                    }.toByteArray()
                    assertTrue(encoded.contentEquals(reencoded), "${case.name}: re-encode mismatch")
                }
                "error" -> {
                    try {
                        Tlmp.readFrame(ByteArrayInputStream(encoded), maxPayload)
                        fail("${case.name}: expected rejection (${case.reason}) but frame decoded")
                    } catch (_: Exception) {
                        // Any exception is a rejection; reason classification is
                        // asserted on the Go side via error sentinels.
                    }
                }
                else -> fail("${case.name}: unknown kind ${case.kind}")
            }
        }
    }

    @Test
    fun `target vectors round trip`() {
        val vectors = gson.fromJson(vectorsFile("targets.json").readText(), TargetsVector::class.java)
        for (case in vectors.cases) {
            val encoded = hexToBytes(case.encodedHex)
            if (case.kind == "error") {
                try {
                    Tlmp.parseTarget(encoded)
                    fail("${case.name}: expected rejection but target parsed")
                } catch (_: Exception) {
                    continue
                }
            }
            val target = Tlmp.parseTarget(encoded)
            val network = when (case.network) {
                "tcp" -> Tlmp.NET_TCP
                "udp" -> Tlmp.NET_UDP
                else -> fail("${case.name}: bad network ${case.network}")
            }
            val (atyp, address) = when (case.atyp) {
                "ipv4" -> Pair(Tlmp.ATYP_IPV4, java.net.InetAddress.getByName(case.host).address)
                "ipv6" -> Pair(Tlmp.ATYP_IPV6, java.net.InetAddress.getByName(case.host).address)
                "fqdn" -> Pair(Tlmp.ATYP_FQDN, case.host.toByteArray(Charsets.US_ASCII))
                else -> fail("${case.name}: bad atyp ${case.atyp}")
            }
            assertEquals(network, target.network, case.name)
            assertEquals(atyp, target.atyp, case.name)
            assertEquals(case.port, target.port, case.name)
            assertTrue(address.contentEquals(target.address), "${case.name}: address mismatch")

            val reencoded = Tlmp.appendTarget(ByteArray(0), target)
            assertTrue(encoded.contentEquals(reencoded), "${case.name}: re-encode mismatch")
        }
    }
}

data class FramesVector(
    val protocol: String = "",
    val version: Int = 0,
    val cases: List<FrameCase> = emptyList(),
)

data class FrameCase(
    val name: String = "",
    val kind: String = "",
    val reason: String? = null,
    val maxPayload: Int = 65536,
    val version: Int = 1,
    val flags: Int = 0,
    val streamId: Int = 0,
    val payloadHex: String = "",
    val encodedHex: String = "",
)

data class TargetsVector(
    val protocol: String = "",
    val version: Int = 0,
    val cases: List<TargetCase> = emptyList(),
)

data class TargetCase(
    val name: String = "",
    val kind: String = "",
    val network: String = "",
    val atyp: String = "",
    val host: String = "",
    val port: Int = 0,
    val encodedHex: String = "",
)
