package dev.toppa.relay

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

private fun hexToBytes(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte()
    }

private fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

class DnsWireTest {

    @Test
    fun `query wire format matches the golden bytes`() {
        val query = DnsWire.buildQuery(0x1234, "example.com", DnsWire.TYPE_A)
        assertEquals(
            "123401000001000000000000076578616d706c6503636f6d0000010001",
            bytesToHex(query),
        )
    }

    @Test
    fun `response parse handles compression pointers`() {
        // Header + question + one A answer whose name is a pointer (0xC00C).
        val response = hexToBytes(
            "123481800001000100000000" +
                "076578616d706c6503636f6d0000010001" +
                "c00c000100010000003c00045db8d822",
        )
        val addresses = DnsWire.parseResponse(response, "example.com")
        assertEquals(1, addresses.size)
        assertEquals("93.184.216.34", addresses.single().hostAddress)
    }

    @Test
    fun `non address records are skipped`() {
        // One CNAME-shaped answer (type 5, rdata "example" name bytes) then an A record.
        val response = hexToBytes(
            "123481800001000200000000" +
                "076578616d706c6503636f6d0000010001" +
                "c00c000500010000003c0004" + "c00c" + // CNAME pointing at itself, rdlen 4
                "c00c000100010000003c00045db8d822",
        )
        val addresses = DnsWire.parseResponse(response, "example.com")
        assertEquals(listOf("93.184.216.34"), addresses.map { it.hostAddress })
    }

    @Test
    fun `truncated messages throw instead of crashing`() {
        val truncated = hexToBytes("123481800001")
        assertFailsWith<IllegalArgumentException> {
            DnsWire.parseResponse(truncated, "example.com")
        }
    }
}

class LoopGuardTest {

    @Test
    fun `upstream equal to transport is refused`() {
        val provider = DefaultUpstreamProvider("hotspot-net")
        val violation = assertFailsWith<LoopGuardViolation> {
            provider.connect(
                InetAddress.getLoopbackAddress(),
                443,
                transportId = "hotspot-net",
            )
        }
        assertTrue(violation.message!!.contains("refusing routing loop"))
    }
}
