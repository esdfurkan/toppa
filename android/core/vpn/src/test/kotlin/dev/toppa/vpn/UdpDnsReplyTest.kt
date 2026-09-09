package dev.toppa.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UdpDnsReplyTest {

    private val request = hexToBytes(
        // IPv4 (TTL 32, proto UDP) + UDP: 19778:53, len 8, cksum 0 — DNS payload 4 bytes.
        "4500001c0001000020110000c0a80164080808084d2a0035000c0000" + "1234010000010000",
    )

    private fun hexToBytes(s: String): ByteArray =
        ByteArray(s.length / 2) { i ->
            ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte()
        }

    @Test
    fun `reply swaps endpoints forces ttl and validates checksum`() {
        val dnsResponse = byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0)
        val reply = UdpDnsReply.build(request, request.size, dnsResponse)
            ?: fail("reply must be built")

        assertEquals(64, reply[8].toInt() and 0xFF, "TTL forced to 64")
        assertTrue(Checksums.verify(reply, 0, 20, 10), "ip checksum must validate")

        // Addresses swapped: source becomes 8.8.8.8, destination 192.168.1.100.
        assertEquals("8.8.8.8", java.net.InetAddress.getByAddress(reply.copyOfRange(12, 16)).hostAddress)
        assertEquals("192.168.1.100", java.net.InetAddress.getByAddress(reply.copyOfRange(16, 20)).hostAddress)

        // Ports swapped: reply source port 53, destination 19778 (0x4D2A).
        assertEquals(53, (reply[20].toInt() and 0xFF) shl 8 or (reply[21].toInt() and 0xFF))
        assertEquals(0x4D2A, (reply[22].toInt() and 0xFF) shl 8 or (reply[23].toInt() and 0xFF))

        // Payload carried through.
        assertEquals(request.size + 12 - 20 + 4 + 0, reply.size) // 28-20-8... structural: ihl(20)+8+12
        assertEquals(0x12.toByte(), reply[28])
    }

    @Test
    fun `non udp and short packets are rejected`() {
        assertNull(UdpDnsReply.build(ByteArray(10), 10, ByteArray(4)))
        val tcpPacket = request.copyOf().also { it[9] = 6 }
        assertNull(UdpDnsReply.build(tcpPacket, tcpPacket.size, ByteArray(4)))
    }
}
