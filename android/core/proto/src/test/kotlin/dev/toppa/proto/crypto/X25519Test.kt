package dev.toppa.proto.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * RFC 7748 §6.1 Diffie-Hellman test vectors — the authority for the pure
 * BigInteger X25519 implementation. If these pass, the ladder, scalar
 * decoding, clamping and encoding are all correct.
 */
class X25519Test {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { i ->
            ((Character.digit(s[2 * i], 16) shl 4) + Character.digit(s[2 * i + 1], 16)).toByte()
        }

    @Test
    fun `rfc 7748 section 6_1 public keys`() {
        val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

        val alicePub = X25519.publicFromPrivate(alicePriv)
        val bobPub = X25519.publicFromPrivate(bobPriv)

        assertEquals(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            alicePub.joinToString("") { "%02x".format(it) },
            "alice public key",
        )
        assertEquals(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            bobPub.joinToString("") { "%02x".format(it) },
            "bob public key",
        )
    }

    @Test
    fun `rfc 7748 section 6_1 shared secret`() {
        val alicePriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val alicePub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

        val shared1 = X25519.dh(alicePriv, bobPub)
        val shared2 = X25519.dh(bobPriv, alicePub)

        val expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(expected, shared1.joinToString("") { "%02x".format(it) }, "alice side")
        assertEquals(expected, shared2.joinToString("") { "%02x".format(it) }, "bob side")
    }

    @Test
    fun `generated keys produce matching shared secrets`() {
        val a = X25519.generatePrivateKey()
        val b = X25519.generatePrivateKey()
        val aPub = X25519.publicFromPrivate(a)
        val bPub = X25519.publicFromPrivate(b)
        assertTrue(
            X25519.dh(a, bPub).contentEquals(X25519.dh(b, aPub)),
            "both sides must derive the same shared secret",
        )
    }
}
