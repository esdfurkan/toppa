package dev.toppa.vpn

import java.net.InetAddress

/**
 * Builds the wire response packet for a captured IPv4/UDP DNS request:
 * swaps addresses and ports, forces TTL 64 (the shield's fingerprint rule),
 * recomputes the IPv4 header checksum, and leaves the UDP checksum at zero
 * (legal for IPv4). Used by the phone's DNS-shield VpnService loop.
 */
object UdpDnsReply {

    fun build(request: ByteArray, length: Int, dnsResponse: ByteArray): ByteArray? {
        if (length < 28) {
            return null
        }
        val ihl = (request[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) {
            return null
        }
        if (request[9].toInt() != 17) { // protocol must be UDP
            return null
        }
        val total = ihl + 8 + dnsResponse.size

        val out = ByteArray(total)
        // IPv4 header: copy, swap addresses, set length + TTL, fix checksum.
        System.arraycopy(request, 0, out, 0, ihl)
        for (i in 0 until 4) {
            out[12 + i] = request[16 + i]
            out[16 + i] = request[12 + i]
        }
        out[2] = ((total shr 8) and 0xFF).toByte()
        out[3] = (total and 0xFF).toByte()
        out[8] = 64
        out[10] = 0
        out[11] = 0
        val sum = Checksums.internetChecksum(out, 0, ihl)
        out[10] = ((sum shr 8) and 0xFF).toByte()
        out[11] = (sum and 0xFF).toByte()

        // UDP header: swap ports, set length, checksum 0.
        out[ihl] = request[ihl + 2]
        out[ihl + 1] = request[ihl + 3]
        out[ihl + 2] = request[ihl]
        out[ihl + 3] = request[ihl + 1]
        out[ihl + 4] = ((8 + dnsResponse.size) shr 8).toByte()
        out[ihl + 5] = (8 + dnsResponse.size).toByte()
        out[ihl + 6] = 0
        out[ihl + 7] = 0

        System.arraycopy(dnsResponse, 0, out, ihl + 8, dnsResponse.size)
        return out
    }
}
