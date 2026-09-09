package dev.toppa.proto

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress

/**
 * Frame flag bits — protocol/SPEC.md §4.2.
 */
object Flags {
    const val SYN: Int = 0x01
    const val FIN: Int = 0x02
    const val RST: Int = 0x04
    const val WIN: Int = 0x08
    const val DATA: Int = 0x10
    const val PING: Int = 0x20
    const val PONG: Int = 0x40
    const val GOAWAY: Int = 0x80

    /** GOAWAY/RST reason codes. */
    const val REASON_NORMAL: Int = 0
    const val REASON_PROTOCOL: Int = 1
    const val REASON_BUSY: Int = 2
}

/**
 * One decoded TLMP frame. [payload] is a private copy owned by the caller
 * (the codec allocates it per read; no pooling at this layer).
 */
class Frame(val flags: Int, val streamId: Int, val payload: ByteArray)

/**
 * Relayed-stream destination, mirroring the SOCKS5 address family set.
 * Domain targets are resolved on the phone (docs/ARCHITECTURE.md §1.5).
 */
class Target(
    val network: Int,
    val atyp: Int,
    val address: ByteArray,
    val port: Int,
) {
    override fun toString(): String {
        val host = when (atyp) {
            Tlmp.ATYP_IPV4, Tlmp.ATYP_IPV6 -> try {
                InetAddress.getByAddress(address).hostAddress
            } catch (e: Exception) {
                "<ip>"
            }
            else -> String(address, Charsets.US_ASCII)
        }
        val net = if (network == Tlmp.NET_UDP) "udp" else "tcp"
        return "$host:$port/$net"
    }
}

/**
 * TLMP v1 (Toppa Link Multiplexing Protocol) codec — Kotlin twin of the Go
 * implementation in desktop/internal/mux, both normative per
 * protocol/SPEC.md. This module is pure JVM on purpose: it must build and run
 * in desktop CI so Go↔Kotlin interop is testable without an emulator.
 */
object Tlmp {
    const val PROTOCOL_VERSION: Int = 1
    const val HEADER_SIZE: Int = 10

    const val NET_TCP: Int = 1
    const val NET_UDP: Int = 2

    const val ATYP_IPV4: Int = 1
    const val ATYP_FQDN: Int = 3
    const val ATYP_IPV6: Int = 4

    const val MAX_FQDN_LENGTH: Int = 255

    /** Encodes and writes one frame; flushes so keepalives stay prompt. */
    @Throws(IOException::class)
    fun writeFrame(out: OutputStream, flags: Int, streamId: Int, payload: ByteArray) {
        val header = ByteArray(HEADER_SIZE)
        header[0] = PROTOCOL_VERSION.toByte()
        header[1] = flags.toByte()
        putU32(header, 2, streamId)
        putU32(header, 6, payload.size)
        out.write(header)
        if (payload.isNotEmpty()) {
            out.write(payload)
        }
        out.flush()
    }

    /**
     * Reads exactly one frame. Rejects wrong versions, oversized payloads,
     * and any structural violation of SPEC §4.2 (all are fatal per spec).
     */
    @Throws(IOException::class)
    fun readFrame(inp: InputStream, maxPayload: Int): Frame {
        val header = readFully(inp, HEADER_SIZE)
        val version = header[0].toInt() and 0xFF
        if (version != PROTOCOL_VERSION) {
            throw IOException("tlmp: unsupported protocol version $version")
        }
        val flags = header[1].toInt() and 0xFF
        val streamId = getU32(header, 2)
        val length = getU32(header, 6)
        if (length > maxPayload) {
            throw IOException("tlmp: frame payload $length exceeds maximum $maxPayload")
        }
        val payload = if (length > 0) readFully(inp, length) else ByteArray(0)
        validate(flags, streamId, payload.size)
        return Frame(flags, streamId, payload)
    }

    /** Structural rules from SPEC §4.2, shared by read paths and vectors. */
    fun validate(flags: Int, streamId: Int, payloadLength: Int) {
        if (flags and Flags.SYN != 0 && flags and Flags.DATA != 0) {
            throw IOException("tlmp: SYN combined with DATA")
        }
        if (flags and (Flags.PING or Flags.PONG or Flags.GOAWAY) != 0 && streamId != 0) {
            throw IOException("tlmp: control frame carries stream id $streamId")
        }
        if (flags and Flags.WIN != 0 && payloadLength != 4) {
            throw IOException("tlmp: WIN payload must be exactly 4 bytes, got $payloadLength")
        }
        if (flags and Flags.RST != 0 && payloadLength != 1) {
            throw IOException("tlmp: RST payload must be exactly 1 byte, got $payloadLength")
        }
        if (flags and Flags.GOAWAY != 0 && payloadLength != 1) {
            throw IOException("tlmp: GOAWAY payload must be exactly 1 byte, got $payloadLength")
        }
        val known = Flags.SYN or Flags.FIN or Flags.RST or Flags.WIN or Flags.DATA or
            Flags.PING or Flags.PONG or Flags.GOAWAY
        val unknown = flags and known.inv()
        if (unknown != 0) {
            throw IOException("tlmp: unknown flag bits 0x%02x".format(unknown))
        }
    }

    /** Encodes [t] per SPEC §4.4 and appends it to [dst]. */
    fun appendTarget(dst: ByteArray, t: Target): ByteArray {
        var out = dst + byteArrayOf(t.network.toByte(), t.atyp.toByte())
        when (t.atyp) {
            ATYP_FQDN -> {
                require(t.address.isNotEmpty() && t.address.size <= MAX_FQDN_LENGTH) {
                    "tlmp: fqdn length ${t.address.size} out of (0,$MAX_FQDN_LENGTH]"
                }
                out += byteArrayOf(t.address.size.toByte())
                out += t.address
            }
            ATYP_IPV4, ATYP_IPV6 -> out += t.address
            else -> throw IOException("tlmp: bad atyp ${t.atyp}")
        }
        out += byteArrayOf((t.port shr 8).toByte(), t.port.toByte())
        return out
    }

    /** Decodes an address block; rejects truncation and bogus fields. */
    fun parseTarget(b: ByteArray): Target {
        if (b.size < 4) throw IOException("tlmp: truncated target header")
        val network = b[0].toInt() and 0xFF
        val atyp = b[1].toInt() and 0xFF
        if (network != NET_TCP && network != NET_UDP) {
            throw IOException("tlmp: bad network $network")
        }
        var off = 2
        val address: ByteArray
        when (atyp) {
            ATYP_IPV4 -> {
                if (b.size < off + 4 + 2) throw IOException("tlmp: short ipv4 target")
                address = b.copyOfRange(off, off + 4)
                off += 4
            }
            ATYP_IPV6 -> {
                if (b.size < off + 16 + 2) throw IOException("tlmp: short ipv6 target")
                address = b.copyOfRange(off, off + 16)
                off += 16
            }
            ATYP_FQDN -> {
                if (b.size < off + 1) throw IOException("tlmp: missing fqdn length")
                val n = b[off].toInt() and 0xFF
                if (n == 0 || b.size < off + 1 + n + 2) throw IOException("tlmp: bad fqdn target")
                address = b.copyOfRange(off + 1, off + 1 + n)
                off += 1 + n
            }
            else -> throw IOException("tlmp: bad atyp $atyp")
        }
        val port = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
        return Target(network, atyp, address, port)
    }

    fun readFully(inp: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(out, off, n - off)
            if (r < 0) throw EOFException("tlmp: unexpected EOF")
            off += r
        }
        return out
    }

    private fun putU32(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }

    private fun getU32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)
}
