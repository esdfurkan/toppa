package dev.toppa.proto.crypto

import dev.toppa.proto.Sas
import dev.toppa.proto.Tlmp
import java.io.InputStream
import java.io.OutputStream

/**
 * The Toppa tunnel handshake (protocol/SPEC.md §2–3): Noise_XX with peer
 * static keys carried inside the encrypted handshake payloads, SAS display
 * for first pairing (TOFU + pinning), then the AEAD record layer.
 * Kotlin mirror of desktop/internal/tunnel/handshake.go.
 */
object TunnelHandshake {

    class Result(
        /** Encrypted channel ready for TLMP frames. */
        val channel: SecureChannel,
        /** 6-digit code to display and compare with the peer during first pairing. */
        val sas: String,
        /** Remote static public key; pin it after SAS confirmation. */
        val peerStatic: ByteArray,
    )

    fun handshake(
        input: InputStream,
        output: OutputStream,
        role: Role,
        staticPrivate: ByteArray,
        pinnedPeer: ByteArray? = null,
    ): Result {
        val handshake = NoiseHandshake(role, staticPrivate)
        val myPublic = X25519.publicFromPrivate(staticPrivate)

        fun send(message: ByteArray) {
            val header = byteArrayOf((message.size shr 8).toByte(), message.size.toByte())
            output.write(header)
            output.write(message)
            output.flush()
        }

        fun receive(): ByteArray {
            val header = Tlmp.readFully(input, 2)
            val size = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (size == 0) {
                throw NoiseException("noise: empty handshake message")
            }
            return Tlmp.readFully(input, size)
        }

        val peer: ByteArray = when (role) {
            Role.INITIATOR -> {
                send(handshake.writeMessage(ByteArray(0)))       // -> e
                val responderStatic = handshake.readMessage(receive()) // <- e, ee, s, es
                send(handshake.writeMessage(myPublic))           // -> s, se (payload = our static)
                responderStatic
            }
            Role.RESPONDER -> {
                handshake.readMessage(receive())                 // -> e
                send(handshake.writeMessage(myPublic))           // <- e, ee, s, es (payload = our static)
                handshake.readMessage(receive())                 // -> s, se
            }
        }

        if (peer.size != 32) {
            throw NoiseException("noise: peer static payload is ${peer.size} bytes, want 32")
        }
        if (pinnedPeer != null && !constantTimeEquals(peer, pinnedPeer)) {
            throw NoiseException("noise: pinned peer key does not match remote")
        }

        val (initiatorToResponder, responderToInitiator) = handshake.split()
        val (readKey, writeKey) = when (role) {
            Role.INITIATOR -> Pair(responderToInitiator, initiatorToResponder)
            Role.RESPONDER -> Pair(initiatorToResponder, responderToInitiator)
        }
        return Result(
            SecureChannel(input, output, readKey, writeKey),
            Sas.shortAuthString(handshake.handshakeHash()),
            peer.copyOf(),
        )
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) {
            return false
        }
        var v = 0
        for (i in a.indices) {
            v = v or (a[i].toInt() xor b[i].toInt())
        }
        return v == 0
    }
}
