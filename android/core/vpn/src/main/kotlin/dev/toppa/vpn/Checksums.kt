package dev.toppa.vpn

/**
 * Ones-complement internet checksum (RFC 1071) over big-endian 16-bit words,
 * with the odd trailing byte padded as a high byte.
 */
object Checksums {

    fun internetChecksum(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toLong() and 0xFF) shl 8) or (data[i + 1].toLong() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toLong() and 0xFF) shl 8
        }
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.toInt() and 0xFFFF).inv() and 0xFFFF
    }

    /**
     * True when the 16-bit field at [checksumOffset] (absolute index)
     * validates as the checksum over data[offset, offset+length). Works on a
     * copy; the input is not modified.
     */
    fun verify(data: ByteArray, offset: Int, length: Int, checksumOffset: Int): Boolean {
        val work = data.copyOfRange(offset, offset + length)
        val field = checksumOffset - offset
        work[field] = 0
        work[field + 1] = 0
        val computed = internetChecksum(work)
        val stored = ((data[checksumOffset].toInt() and 0xFF) shl 8) or
            (data[checksumOffset + 1].toInt() and 0xFF)
        return computed == stored
    }
}
