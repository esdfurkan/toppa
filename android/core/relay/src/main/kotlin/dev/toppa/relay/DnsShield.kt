package dev.toppa.relay

import java.net.InetAddress

/**
 * DNS shield helpers for the phone's VpnService TUN (architecture §1.1 L1,
 * DNS-shield variant): recognize query datagrams, extract the question name,
 * and build an A-record response wire message. Pure JVM — unit tested.
 */
object DnsShield {

    /** True for a plausible DNS query (QR=0, at least one question). */
    fun isQuery(b: ByteArray): Boolean {
        if (b.size < 12) {
            return false
        }
        val qr = b[2].toInt() and 0x80
        val qd = ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
        return qr == 0 && qd >= 1
    }

    /** First question name (uncompressed, as stub resolvers emit); null if absent. */
    fun queryName(query: ByteArray): String? {
        if (query.size < 12) {
            return null
        }
        var pos = 12
        val sb = StringBuilder()
        while (true) {
            if (pos >= query.size) {
                return null
            }
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                break
            }
            if (len and 0xC0 != 0) {
                return null // question names are not compressed on the wire
            }
            if (pos + 1 + len > query.size) {
                return null
            }
            if (sb.isNotEmpty()) {
                sb.append('.')
            }
            sb.append(String(query, pos + 1, len, Charsets.US_ASCII))
            pos += 1 + len
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /**
     * Builds a NOERROR response for [query] with one A record per v4 address
     * in [addresses]. The question section is echoed verbatim and answers
     * use a single compression pointer to offset 12.
     */
    fun buildResponse(query: ByteArray, addresses: List<InetAddress>): ByteArray {
        val v4 = addresses.mapNotNull { a -> a.address.takeIf { it.size == 4 } }
        val questionEnd = questionEnd(query)
        val out = ByteArrayOutputStream(query.size + v4.size * 16)
        fun u16(v: Int) {
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }
        // Header
        if (query.size >= 2) {
            out.write(query, 0, 2) // transaction id
        } else {
            u16(0)
        }
        u16(0x8180) // QR + RD + RA, RCODE 0
        u16(1) // QDCOUNT
        u16(v4.size) // ANCOUNT
        u16(0)
        u16(0)
        // Question section, echoed.
        if (questionEnd > 12) {
            out.write(query, 12, questionEnd - 12)
        } else {
            out.write(0)
            u16(DnsWire.TYPE_A)
            u16(1)
        }
        // Answers: NAME = pointer to 12, TYPE A, CLASS IN, TTL 60, RDLENGTH 4.
        for (addr in v4) {
            out.write(0xC0)
            out.write(0x0C)
            u16(DnsWire.TYPE_A)
            u16(1)
            u16(60 shr 16 and 0xFFFF)
            u16(60 and 0xFFFF)
            u16(4)
            out.write(addr)
        }
        return out.toByteArray()
    }

    /** End offset of the question section (name + qtype + qclass). */
    private fun questionEnd(query: ByteArray): Int {
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                return pos + 1 + 4
            }
            pos += 1 + len
        }
        return -1
    }
}
