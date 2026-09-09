package dev.toppa.vpn

/**
 * Policy-driven IP packet rewriter — the Shield-mode egress normalizer
 * (docs/ARCHITECTURE.md §1.1, layer L1). Mutates a packet in place:
 * forces IPv4 TTL / IPv6 Hop Limit to the policy value, recomputes the IPv4
 * header checksum when the header changed, and classifies non-IP frames as
 * dropped.
 *
 * Contracts (mirrored by protocol/vectors/packets.json):
 *  - Only the TTL/HL byte and (for IPv4) the checksum bytes ever change.
 *  - IPv6 has no header checksum; its packets change in exactly one byte.
 *  - A packet whose TTL/HL already matches is forwarded byte-identical.
 *  - Fragments (no transport header present) are still normalized: only the
 *    IP header is touched, so parsing never needs the L4 payload.
 */
class PacketProcessor(private val policy: Policy = Policy()) {

    data class Policy(val ipv4Ttl: Int = 64, val ipv6HopLimit: Int = 64)

    sealed class Result {
        object ForwardedUnchanged : Result()
        data class ForwardedRewritten(val changes: List<String>) : Result()
        data class Dropped(val reason: String) : Result()
    }

    fun process(packet: ByteArray, length: Int = packet.size): Result {
        if (length < 1) {
            return Result.Dropped("empty")
        }
        return when (val version = (packet[0].toInt() and 0xF0) shr 4) {
            4 -> processIpv4(packet, length)
            6 -> processIpv6(packet, length)
            else -> Result.Dropped("unsupported ip version $version")
        }
    }

    private fun processIpv4(packet: ByteArray, length: Int): Result {
        if (length < IPV4_HEADER_MIN) {
            return Result.Dropped("ipv4 header truncated")
        }
        val changes = ArrayList<String>(2)
        if ((packet[TTL_OFFSET].toInt() and 0xFF) != policy.ipv4Ttl) {
            packet[TTL_OFFSET] = policy.ipv4Ttl.toByte()
            changes.add("ttl=${policy.ipv4Ttl}")
        }
        if (changes.isNotEmpty()) {
            packet[CHECKSUM_OFFSET] = 0
            packet[CHECKSUM_OFFSET + 1] = 0
            val headerBytes = (packet[0].toInt() and 0x0F) * 4
            val headerEnd = minOf(headerBytes, length)
            val sum = Checksums.internetChecksum(packet, 0, headerEnd)
            packet[CHECKSUM_OFFSET] = ((sum shr 8) and 0xFF).toByte()
            packet[CHECKSUM_OFFSET + 1] = (sum and 0xFF).toByte()
            changes.add("checksum")
        }
        return if (changes.isEmpty()) {
            Result.ForwardedUnchanged
        } else {
            Result.ForwardedRewritten(changes)
        }
    }

    private fun processIpv6(packet: ByteArray, length: Int): Result {
        if (length < IPV6_HEADER_LEN) {
            return Result.Dropped("ipv6 header truncated")
        }
        if ((packet[HOP_LIMIT_OFFSET].toInt() and 0xFF) == policy.ipv6HopLimit) {
            return Result.ForwardedUnchanged
        }
        packet[HOP_LIMIT_OFFSET] = policy.ipv6HopLimit.toByte()
        return Result.ForwardedRewritten(listOf("hopLimit=${policy.ipv6HopLimit}"))
    }

    companion object {
        const val IPV4_HEADER_MIN = 20
        const val IPV6_HEADER_LEN = 40
        const val TTL_OFFSET = 8
        const val HOP_LIMIT_OFFSET = 7
        const val CHECKSUM_OFFSET = 10
    }
}
