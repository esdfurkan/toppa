package dev.toppa.proto.crypto

import java.io.ByteArrayOutputStream
import javax.crypto.AEADBadTagException

/** Noise handshake role. The device that opened the transport connection initiates. */
enum class Role { INITIATOR, RESPONDER }

class NoiseException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Minimal Noise_XX_25519_ChaChaPoly_SHA256 state machine
 * (protocol/SPEC.md §2). Deliberately self-contained and auditable: only the
 * XX pattern and the payload rules Toppa needs are implemented.
 *
 * Reviewers: this file is validated by the Go↔Kotlin interop CI job
 * (Go is the reference implementation, via github.com/flynn/noise). Do not
 * add patterns or cipher suites here — changes go through an ADR and vector
 * updates on the Go side first.
 */
class NoiseHandshake(role: Role, staticPrivateRaw: ByteArray) {

    init {
        require(staticPrivateRaw.size == KEY_LEN) { "noise: static private key must be 32 bytes" }
    }

    private val role: Role = role
    private val staticPriv: ByteArray = staticPrivateRaw.copyOf()
    private val staticPub: ByteArray = X25519.publicFromPrivate(staticPrivateRaw)

    // Symmetric state (Noise framework §5.2).
    private var handshakeHash: ByteArray = sha256(PROTOCOL_NAME.toByteArray(Charsets.US_ASCII))
    private var chainingKey: ByteArray = handshakeHash.copyOf()
    private var key: ByteArray? = null
    private var nonce = 0L

    // Local ephemeral (generated lazily on this side's first write).
    private var ephemeralPriv: ByteArray? = null
    private var ephemeralPub: ByteArray? = null

    var remoteEphemeral: ByteArray? = null
        private set
    var remoteStatic: ByteArray? = null
        private set

    /** True after the third message has been processed; [split] is then valid. */
    var complete: Boolean = false
        private set

    private var step = 0

    fun writeMessage(payload: ByteArray): ByteArray {
        val writable = if (role == Role.INITIATOR) step == 0 || step == 2 else step == 1
        check(writable) { "noise: write not expected at step $step" }
        val out = ByteArrayOutputStream()
        if (role == Role.INITIATOR) {
            when (step) {
                0 -> { // -> e
                    generateEphemeral()
                    val pub = ephemeralPub!!
                    out.write(pub)
                    mixHash(pub)
                    out.write(encryptAndHash(payload))
                }
                2 -> { // -> s, se
                    val re = requireField(remoteEphemeral, "remote ephemeral")
                    out.write(encryptAndHash(staticPub))
                    mixKey(X25519.dh(staticPriv, re))
                    out.write(encryptAndHash(payload))
                }
                else -> throw IllegalStateException("unreachable")
            }
        } else {
            // <- e, ee, s, es
            generateEphemeral()
            val pub = ephemeralPub!!
            out.write(pub)
            mixHash(pub)
            val re = requireField(remoteEphemeral, "remote ephemeral")
            mixKey(X25519.dh(requireField(ephemeralPriv, "ephemeral"), re)) // ee
            out.write(encryptAndHash(staticPub))                            // s
            // es: DH(responder static, initiator ephemeral) — per the Noise
            // rule, es is always DH(initiator ephemeral, responder static).
            mixKey(X25519.dh(staticPriv, re))
            out.write(encryptAndHash(payload))
        }
        step++
        if (step == 3) {
            complete = true
        }
        return out.toByteArray()
    }

    fun readMessage(message: ByteArray): ByteArray {
        val plaintext: ByteArray
        if (role == Role.INITIATOR) {
            check(step == 1) { "noise: initiator cannot read at step $step" }
            require(message.size >= 2 * KEY_LEN + TAG_LEN) { "noise: message 2 truncated" }
            val re = message.copyOfRange(0, KEY_LEN) // <- e
            mixHash(re)
            remoteEphemeral = re
            mixKey(X25519.dh(requireField(ephemeralPriv, "ephemeral"), re))                        // ee
            val rs = decryptAndHash(message.copyOfRange(KEY_LEN, KEY_LEN + KEY_LEN + TAG_LEN))      // s
            remoteStatic = rs
            mixKey(X25519.dh(requireField(ephemeralPriv, "ephemeral"), rs))                         // es
            plaintext = decryptAndHash(message.copyOfRange(2 * KEY_LEN + TAG_LEN, message.size))
        } else {
            when (step) {
                0 -> { // -> e
                    require(message.size >= KEY_LEN) { "noise: message 1 truncated" }
                    val re = message.copyOfRange(0, KEY_LEN)
                    mixHash(re)
                    remoteEphemeral = re
                    plaintext = decryptAndHash(message.copyOfRange(KEY_LEN, message.size))
                }
                2 -> { // -> s, se
                    require(message.size >= KEY_LEN + TAG_LEN) { "noise: message 3 truncated" }
                    val rs = decryptAndHash(message.copyOfRange(0, KEY_LEN + TAG_LEN)) // s
                    remoteStatic = rs
                    val re = requireField(remoteEphemeral, "remote ephemeral")
                    mixKey(X25519.dh(staticPriv, re))                                  // se
                    plaintext = decryptAndHash(message.copyOfRange(KEY_LEN + TAG_LEN, message.size))
                }
                else -> throw IllegalStateException("noise: responder cannot read at step $step")
            }
        }
        step++
        return plaintext
    }

    /**
     * Derives the two transport keys (Noise Split). First key encrypts
     * initiator→responder, second responder→initiator.
     */
    fun split(): Pair<ByteArray, ByteArray> {
        check(complete) { "noise: handshake not complete" }
        return Hkdf.derive2(chainingKey, ByteArray(0))
    }

    /** The Noise handshake hash (ChannelBinding); input to the SAS (SPEC §2.4). */
    fun handshakeHash(): ByteArray = handshakeHash.copyOf()

    private fun generateEphemeral() {
        ephemeralPriv = X25519.generatePrivateKey()
        ephemeralPub = X25519.publicFromPrivate(ephemeralPriv!!)
    }

    private fun mixHash(data: ByteArray) {
        handshakeHash = sha256(handshakeHash, data)
    }

    private fun mixKey(dhOutput: ByteArray) {
        val (newChain, tempKey) = Hkdf.derive2(chainingKey, dhOutput)
        chainingKey = newChain
        key = tempKey
        nonce = 0
    }

    private fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val k = key
        return if (k == null) {
            mixHash(plaintext)
            plaintext
        } else {
            val ciphertext = ChaChaPoly.encrypt(k, ChaChaPoly.nonce12(nonce), handshakeHash, plaintext)
            mixHash(ciphertext)
            nonce++
            ciphertext
        }
    }

    private fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val k = key ?: run {
            mixHash(ciphertext)
            return ciphertext
        }
        val plaintext = try {
            ChaChaPoly.decrypt(k, ChaChaPoly.nonce12(nonce), handshakeHash, ciphertext)
        } catch (e: AEADBadTagException) {
            throw NoiseException("noise: handshake decryption failed", e)
        }
        mixHash(ciphertext)
        nonce++
        return plaintext
    }

    private fun requireField(value: ByteArray?, name: String): ByteArray =
        value ?: throw IllegalStateException("noise: $name missing")

    companion object {
        // Exactly 32 bytes, so the initial handshake hash needs no padding.
        const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"
        const val KEY_LEN = 32
        const val TAG_LEN = 16
    }
}
