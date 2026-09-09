package dev.toppa.relay

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress

/**
 * Minimal DNS wire codec (RFC 1035) — query build + A/AAAA answer parse with
 * compression-pointer handling. Just enough for DoH (RFC 8484) relayed
 * resolution; no zone transfer, no EDNS.
 */
object DnsWire {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    private const val CLASS_IN = 1

    /** Standard recursive query: one question, RD flag set. */
    fun buildQuery(id: Int, name: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(v: Int) {
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }
        u16(id and 0xFFFF)
        u16(0x0100) // RD=1
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(0) // NSCOUNT
        u16(0) // ARCOUNT
        for (label in name.split('.')) {
            require(label.isNotEmpty() && label.length <= 63) { "dns: bad label '$label'" }
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0) // root
        u16(type)
        u16(CLASS_IN)
        return out.toByteArray()
    }

    /** Extracts A/AAAA addresses from a response for [expectedName]. */
    fun parseResponse(message: ByteArray, expectedName: String): List<InetAddress> {
        require(message.size >= 12) { "dns: message truncated" }
        fun u16(pos: Int): Int =
            ((message[pos].toInt() and 0xFF) shl 8) or (message[pos + 1].toInt() and 0xFF)

        val questionCount = u16(4)
        val answerCount = u16(6)
        var pos = 12
        repeat(questionCount) {
            pos = skipName(message, pos)
            pos += 4 // qtype + qclass
        }
        val addresses = ArrayList<InetAddress>()
        repeat(answerCount) {
            if (pos >= message.size) {
                return addresses
            }
            pos = skipName(message, pos)
            if (pos + 10 > message.size) {
                return addresses
            }
            val type = u16(pos)
            pos += 2 // type
            pos += 2 // class
            pos += 4 // ttl
            val rdLength = u16(pos)
            pos += 2
            when {
                type == TYPE_A && rdLength == 4 && pos + 4 <= message.size ->
                    addresses.add(InetAddress.getByAddress(message.copyOfRange(pos, pos + 4)))
                type == TYPE_AAAA && rdLength == 16 && pos + 16 <= message.size ->
                    addresses.add(InetAddress.getByAddress(message.copyOfRange(pos, pos + 16)))
            }
            pos += rdLength
        }
        return addresses
    }

    /** Returns the position after a (possibly compressed) name. */
    private fun skipName(message: ByteArray, posIn: Int): Int {
        var pos = posIn
        var jumps = 0
        while (true) {
            if (pos >= message.size) {
                throw IOException("dns: name runs past end of message")
            }
            val len = message[pos].toInt() and 0xFF
            if (len == 0) {
                return pos + 1
            }
            if (len and 0xC0 == 0xC0) {
                if (pos + 1 >= message.size) {
                    throw IOException("dns: truncated compression pointer")
                }
                if (++jumps > 32) {
                    throw IOException("dns: compression pointer loop")
                }
                return pos + 2
            }
            pos += 1 + len
        }
    }
}
