package dev.toppa.vpn

import com.google.gson.Gson
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

data class PacketsVector(
    val protocol: String = "",
    val version: Int = 0,
    val cases: List<PacketCase> = emptyList(),
)

data class PacketCase(
    val name: String = "",
    val kind: String = "",
    val ipVersion: Int? = null,
    val ttlOffset: Int = 0,
    val before: Int = 0,
    val after: Int = 0,
    val checksumOffset: Int? = null,
    val inputHex: String = "",
)

/**
 * Consumes protocol/vectors/packets.json plus in-code packet assertions.
 * These fixtures are the Step 2 "TTL manipulation" exit criterion: they pin
 * down that the rewriter changes ONLY the TTL/HopLimit byte (plus the IPv4
 * checksum) and that the resulting checksum validates.
 */
class PacketProcessorTest {

    private val processor = PacketProcessor()

    private fun hexToBytes(s: String): ByteArray =
        ByteArray(s.length / 2) { i ->
            ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte()
        }

    @Test
    fun `golden packet fixtures`() {
        val file = File("../../../protocol/vectors/packets.json")
        assumeTrue(file.exists(), "packet fixtures not found; full checkout required")
        val vectors = Gson().fromJson(file.readText(), PacketsVector::class.java)
        for (case in vectors.cases) {
            val packet = hexToBytes(case.inputHex)
            when (case.kind) {
                "rewrite" -> {
                    val result = processor.process(packet)
                    if (result !is PacketProcessor.Result.ForwardedRewritten) {
                        fail("${case.name}: expected rewrite, got $result")
                    }
                    assertEquals(case.after, packet[case.ttlOffset].toInt() and 0xFF, "${case.name}: TTL/HL value")
                    if (case.ipVersion == 4) {
                        val checksumOffset = case.checksumOffset
                            ?: fail("${case.name}: ipv4 fixture missing checksumOffset")
                        assertTrue(
                            Checksums.verify(packet, 0, 20, checksumOffset),
                            "${case.name}: rewritten checksum must validate",
                        )
                    }
                }
                "nochange" -> {
                    val original = packet.copyOf()
                    val result = processor.process(packet)
                    if (result !is PacketProcessor.Result.ForwardedUnchanged) {
                        fail("${case.name}: expected unchanged passthrough, got $result")
                    }
                    assertTrue(packet.contentEquals(original), "${case.name}: bytes must not change")
                }
                "drop" -> {
                    val result = processor.process(packet)
                    if (result !is PacketProcessor.Result.Dropped) {
                        fail("${case.name}: expected drop, got $result")
                    }
                }
                else -> fail("${case.name}: unknown kind ${case.kind}")
            }
        }
    }

    @Test
    fun `ipv4 tcp syn is normalized in place`() {
        val packet = hexToBytes(
            "45000028123440003f060000c0a801645db8d822c00001bb11223344000000005002ffff00000000",
        )
        val original = packet.copyOf()
        val result = processor.process(packet)
        assertTrue(result is PacketProcessor.Result.ForwardedRewritten, "ttl 63 must be rewritten to 64")
        assertEquals(64, packet[8].toInt() and 0xFF, "TTL forced to 64")
        assertTrue(Checksums.verify(packet, 0, 20, 10), "checksum must be recomputed and valid")
        // Everything except TTL (8) and checksum (10,11) must be untouched.
        for (i in packet.indices) {
            if (i != 8 && i != 10 && i != 11) {
                assertEquals(original[i], packet[i], "byte $i must not change")
            }
        }
    }

    @Test
    fun `ipv6 hop limit changes exactly one byte`() {
        val packet = hexToBytes(
            "600000000028067ffd00000000000000000000000000000120014860486000000000000000008888c00001bb11223344000000005002ffff00000000",
        )
        val original = packet.copyOf()
        val result = processor.process(packet)
        assertTrue(result is PacketProcessor.Result.ForwardedRewritten)
        assertEquals(64, packet[7].toInt() and 0xFF, "Hop Limit forced to 64")
        for (i in packet.indices) {
            if (i != 7) {
                assertEquals(original[i], packet[i], "ipv6 has no header checksum: byte $i must not change")
            }
        }
    }

    @Test
    fun `custom policy ttl is honored`() {
        val strict = PacketProcessor(PacketProcessor.Policy(ipv4Ttl = 65, ipv6HopLimit = 65))
        val packet = hexToBytes("4500001c0001000040110000c0a80164080808084d2a003500080000")
        val result = strict.process(packet)
        assertTrue(result is PacketProcessor.Result.ForwardedRewritten)
        assertEquals(65, packet[8].toInt() and 0xFF, "policy TTL (not hardcoded 64) must be applied")
    }

    @Test
    fun `fragmented and truncated packets are handled`() {
        // Fragment with no transport header: still normalized, never crashes.
        val fragment = hexToBytes("45000014000220017f110000c0a8016408080808")
        val fragmentResult = processor.process(fragment)
        assertTrue(fragmentResult is PacketProcessor.Result.ForwardedRewritten)
        assertEquals(64, fragment[8].toInt() and 0xFF)

        // Garbage: dropped, not thrown.
        assertTrue(processor.process(byteArrayOf(0x45, 0x00)) is PacketProcessor.Result.Dropped)
        assertTrue(processor.process(ByteArray(0)) is PacketProcessor.Result.Dropped)
        assertTrue(processor.process(hexToBytes("56000014")) is PacketProcessor.Result.Dropped)
    }
}
