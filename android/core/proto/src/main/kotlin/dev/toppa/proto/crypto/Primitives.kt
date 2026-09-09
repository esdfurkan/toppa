package dev.toppa.proto.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Internal hashing helpers shared by the Noise state machine and HKDF.

internal fun sha256(vararg chunks: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    for (chunk in chunks) {
        md.update(chunk)
    }
    return md.digest()
}

internal fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/**
 * RFC 5869 HKDF (HMAC-SHA256) in the two-output shape the Noise framework
 * uses for MixKey and Split.
 */
object Hkdf {
    fun derive2(chainingKey: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val tempKey = hmacSha256(chainingKey, ikm)
        val out1 = hmacSha256(tempKey, byteArrayOf(0x01))
        val out2 = hmacSha256(tempKey, out1 + byteArrayOf(0x02))
        return Pair(out1, out2)
    }
}

/**
 * ChaCha20-Poly1305 AEAD through the JCA provider. `encrypt` returns
 * ciphertext || 16-byte tag; `decrypt` throws on forgery. The JCA
 * ChaCha20-Poly1305 transform is available on JVM 11+ and Android API 28+;
 * for older Android targets plug a provider-backed implementation behind
 * this object — nothing else in the module touches JCA directly.
 */
object ChaChaPoly {
    private const val TRANSFORM = "ChaCha20-Poly1305/None/NoPadding"

    fun encrypt(key: ByteArray, nonce12: ByteArray, ad: ByteArray?, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
        if (ad != null && ad.isNotEmpty()) {
            cipher.updateAAD(ad)
        }
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce12: ByteArray, ad: ByteArray?, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
        if (ad != null && ad.isNotEmpty()) {
            cipher.updateAAD(ad)
        }
        return cipher.doFinal(ciphertext)
    }

    /** Noise nonce: 4 zero bytes followed by the 64-bit little-endian counter. */
    fun nonce12(counter: Long): ByteArray {
        val nonce = ByteArray(12)
        for (i in 0 until 8) {
            nonce[4 + i] = ((counter ushr (8 * i)) and 0xFFL).toByte()
        }
        return nonce
    }
}

/**
 * Raw X25519 (RFC 7748) implemented with BigInteger field arithmetic — no
 * platform crypto provider involved, so JVM CI and Android behave
 * identically, and correctness is pinned by the RFC 7748 §6.1 vectors in
 * X25519Test.
 *
 * Known limitation (documented, acceptable for v1): BigInteger arithmetic is
 * not constant-time. The static key signs no payloads — it only authenticates
 * the handshake — and session keys are per-connection; a constant-time
 * implementation (e.g. Tink) is the upgrade path if timing attacks on the
 * handshake ever land in the threat model.
 */
object X25519 {
    private val P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)
    private val BASE_POINT = ByteArray(32).also { it[0] = 9 } // u = 9

    /** 32 random bytes; clamped at use time per RFC 7748. */
    fun generatePrivateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val key = ByteArray(32)
        random.nextBytes(key)
        return clamp(key)
    }

    /** Public key of a raw private key: X25519(priv, base point). */
    fun publicFromPrivate(privRaw: ByteArray): ByteArray = dh(privRaw, BASE_POINT)

    /** Raw Diffie-Hellman: the 32-byte shared x-coordinate. */
    fun dh(privRaw: ByteArray, peerPubRaw: ByteArray): ByteArray {
        require(privRaw.size == 32 && peerPubRaw.size == 32) { "x25519: keys must be 32 bytes" }
        val scalar = decodeScalar(privRaw)
        val x1 = decodeU(peerPubRaw)

        // Montgomery ladder (RFC 7748 §5, 255-bit scalars after clamping).
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = false
        for (t in 254 downTo 0) {
            val kt = scalar.testBit(t)
            if (swap != kt) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = kt
            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            val daPlusCb = da.add(cb)
            val daMinusCb = da.subtract(cb)
            x3 = daPlusCb.multiply(daPlusCb).mod(P)
            z3 = x1.multiply(daMinusCb).multiply(daMinusCb).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }
        if (swap) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }
        val result = x2.multiply(z2.modPow(P.subtract(BigInteger.TWO), P)).mod(P)
        return to32LE(result)
    }

    private fun decodeScalar(raw: ByteArray): BigInteger {
        val k = raw.copyOf().also {
            it[0] = (it[0].toInt() and 248).toByte()
            it[31] = ((it[31].toInt() and 127) or 64).toByte()
        }
        return BigInteger(1, k.reversedArray())
    }

    private fun decodeU(raw: ByteArray): BigInteger {
        val u = raw.copyOf()
        u[31] = (u[31].toInt() and 127).toByte() // mask the high bit per RFC 7748
        return BigInteger(1, u.reversedArray())
    }

    private fun to32LE(value: BigInteger): ByteArray {
        val be = value.mod(P).toByteArray()
        val out = ByteArray(32)
        var i = be.size - 1
        var j = 0
        while (i >= 0 && j < 32) {
            out[j] = be[i]
            i--
            j++
        }
        return out
    }

    private fun clamp(key: ByteArray): ByteArray {
        key[0] = (key[0].toInt() and 248).toByte()
        key[31] = ((key[31].toInt() and 127) or 64).toByte()
        return key
    }
}
