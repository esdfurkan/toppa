package dev.toppa.proto

import java.security.MessageDigest

/**
 * Short Authentication String derivation — Kotlin mirror of
 * desktop/internal/tunnel (protocol/SPEC.md §2.4):
 *
 *   sas = %06d(BE_uint32(SHA-256("toppa-sas-v1" || handshake_hash)[0:4]) mod 1_000_000)
 *
 * Both ends display this during first pairing; a mismatch means MITM.
 */
object Sas {
    private const val DOMAIN = "toppa-sas-v1"

    fun shortAuthString(handshakeHash: ByteArray): String {
        require(handshakeHash.size == 32) { "sas: handshake hash must be 32 bytes" }
        val md = MessageDigest.getInstance("SHA-256")
        md.update(DOMAIN.toByteArray(Charsets.US_ASCII))
        md.update(handshakeHash)
        val sum = md.digest()
        var value = 0L
        for (i in 0 until 4) {
            value = (value shl 8) or (sum[i].toLong() and 0xFF)
        }
        return "%06d".format(value % 1_000_000)
    }
}
