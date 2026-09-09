package dev.toppa.proto.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NamedParameterSpec
import java.security.SecureRandom
import java.security.interfaces.XECPrivateKey
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
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
 * ChaCha20-Poly1305 AEAD through the JCA provider (JVM 11+). `encrypt`
 * returns ciphertext || 16-byte tag; `decrypt` throws on forgery.
 *
 * Android note: modern Android (API 28+) ships an equivalent provider; if a
 * target device does not, plug a BouncyCastle-backed implementation behind
 * this object — nothing else in the module may touch JCA directly.
 */
object ChaChaPoly {
    private const val TRANSFORM = "ChaCha20-Poly1305/None/NoPadding"

    fun encrypt(key: ByteArray, nonce12: ByteArray, ad: ByteArray?, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
        if (!ad.isNullOrEmpty()) {
            cipher.updateAAD(ad)
        }
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce12: ByteArray, ad: ByteArray?, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
        if (!ad.isNullOrEmpty()) {
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
 * Raw X25519 (RFC 7748) over the JCA XDH provider. Keys use the Noise
 * DH25519 wire encoding: raw 32-byte little-endian byte strings.
 */
object X25519 {
    private val BASE_POINT = ByteArray(32).also { it[0] = 9 } // u = 9

    fun generatePrivateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val generator = KeyPairGenerator.getInstance("XDH")
        generator.initialize(NamedParameterSpec.X25519, random)
        val keyPair = generator.generateKeyPair()
        val privateKey = keyPair.private as XECPrivateKey
        val scalar = privateKey.scalar.orElseThrow {
            IllegalStateException("x25519: provider returned a key without a scalar")
        }
        return bigIntegerTo32LE(scalar)
    }

    /** Public key of a raw private key: X25519(priv, base point). */
    fun publicFromPrivate(privRaw: ByteArray): ByteArray = dh(privRaw, BASE_POINT)

    /** Raw Diffie-Hellman: the 32-byte shared x-coordinate. */
    fun dh(privRaw: ByteArray, peerPubRaw: ByteArray): ByteArray {
        val agreement = KeyAgreement.getInstance("XDH")
        agreement.init(privateKey(privRaw))
        agreement.doPhase(publicKey(peerPubRaw), true)
        return agreement.generateSecret()
    }

    private fun privateKey(raw: ByteArray) =
        KeyFactory.getInstance("XDH").generatePrivate(
            XECPrivateKeySpec(NamedParameterSpec.X25519, rawToBigInteger(raw))
        )

    private fun publicKey(raw: ByteArray) =
        KeyFactory.getInstance("XDH").generatePublic(
            XECPublicKeySpec(NamedParameterSpec.X25519, rawToBigInteger(raw))
        )

    private fun rawToBigInteger(raw: ByteArray): BigInteger {
        require(raw.size == 32) { "x25519: raw key must be 32 bytes, got ${raw.size}" }
        return BigInteger(1, raw.reversedArray()) // little-endian raw -> big-endian integer
    }

    private fun bigIntegerTo32LE(value: BigInteger): ByteArray {
        val bigEndian = value.toByteArray() // may carry a leading zero sign byte
        val stripped = if (bigEndian.size > 32) bigEndian.copyOfRange(bigEndian.size - 32, bigEndian.size) else bigEndian
        val out = ByteArray(32)
        for (i in stripped.indices) {
            out[stripped.size - 1 - i] = stripped[i]
        }
        return out
    }
}
