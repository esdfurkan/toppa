package dev.toppa.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ChecksumsTest {

    @Test
    fun `rfc 1071 worked example`() {
        val data = byteArrayOf(
            0x00, 0x01, 0xF2.toByte(), 0x03, 0xF4.toByte(), 0xF5.toByte(), 0xF6.toByte(), 0xF7.toByte(),
        )
        assertEquals(0x220D, Checksums.internetChecksum(data))
    }

    @Test
    fun `verify accepts its own checksum`() {
        val data = byteArrayOf(
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0.toByte(), 0xA8.toByte(), 0x01, 0x64,
            0x5D.toByte(), 0xB8.toByte(), 0xD8.toByte(), 0x22,
        )
        data[10] = 0
        data[11] = 0
        val sum = Checksums.internetChecksum(data, 0, 20)
        data[10] = ((sum shr 8) and 0xFF).toByte()
        data[11] = (sum and 0xFF).toByte()
        assertTrue(Checksums.verify(data, 0, 20, 10), "checksum placed by the test must verify")
    }

    @Test
    fun `verify rejects a corrupt header`() {
        val data = byteArrayOf(
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x12, 0x34, 0xC0.toByte(), 0xA8.toByte(), 0x01, 0x64,
            0x5D.toByte(), 0xB8.toByte(), 0xD8.toByte(), 0x22,
        )
        assertTrue(!Checksums.verify(data, 0, 20, 10), "arbitrary checksum bytes must not verify")
    }

    @Test
    fun `odd length pads with zero`() {
        val even = byteArrayOf(0x00, 0x01, 0xF2.toByte(), 0x03)
        val odd = byteArrayOf(0x00, 0x01, 0xF2.toByte(), 0x03, 0xF4.toByte())
        val withPad = byteArrayOf(0x00, 0x01, 0xF2.toByte(), 0x03, 0xF4.toByte(), 0x00)
        // Padding the odd trailing byte with zero must not change the checksum.
        assertEquals(Checksums.internetChecksum(withPad), Checksums.internetChecksum(odd))
        assertEquals(Checksums.internetChecksum(even), Checksums.internetChecksum(even))
    }
}
