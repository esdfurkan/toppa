package dev.toppa.relay

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsShieldTest {

    private fun queryBytes(name: String): ByteArray {
        val q = DnsWire.buildQuery(0x4242, name, DnsWire.TYPE_A)
        return q
    }

    @Test
    fun `queries are recognized and names extracted`() {
        val q = queryBytes("example.com")
        assertTrue(DnsShield.isQuery(q))
        assertEquals("example.com", DnsShield.queryName(q))
    }

    @Test
    fun `responses are not queries`() {
        val q = queryBytes("example.com")
        q[2] = (q[2].toInt() or 0x80).toByte() // set QR
        assertTrue(!DnsShield.isQuery(q))
    }

    @Test
    fun `multi label and deep names`() {
        assertEquals("a.b.toppa.test", DnsShield.queryName(queryBytes("a.b.toppa.test")))
        assertNull(DnsShield.queryName(ByteArray(12)))
    }

    @Test
    fun `response echoes question and carries v4 answers`() {
        val q = queryBytes("example.com")
        val addresses = listOf(
            InetAddress.getByAddress(byteArrayOf(93, -72, -40, 34)), // 93.184.216.34
            InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946"), // v6: filtered
        )
        val response = DnsShield.buildResponse(q, addresses)

        assertEquals(0x42, response[0].toInt() and 0xFF)
        assertEquals(0x42, response[1].toInt() and 0xFF)
        assertTrue((response[2].toInt() and 0x80) != 0, "QR must be set")
        assertEquals(1, (response[4].toInt() and 0xFF) shl 8 or (response[5].toInt() and 0xFF))
        assertEquals(1, (response[6].toInt() and 0xFF) shl 8 or (response[7].toInt() and 0xFF))
        // Question echoed, then pointer answer: find 0xC00C after the question.
        val questionEnd = 12 + (1 + 7) + (1 + 3) + 1 + 4
        assertEquals(0xC0.toByte(), response[questionEnd])
        assertEquals(0x0C.toByte(), response[questionEnd + 1])
        // A record rdata at the very end.
        val rdata = response.copyOfRange(response.size - 4, response.size)
        assertTrue(rdata.contentEquals(byteArrayOf(93, -72, -40, 34)), "v4 rdata must be the answer")
    }
}
