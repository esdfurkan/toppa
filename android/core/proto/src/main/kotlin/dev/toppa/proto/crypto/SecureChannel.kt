package dev.toppa.proto.crypto

import dev.toppa.proto.ByteStream
import dev.toppa.proto.Tlmp
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * AEAD record layer (protocol/SPEC.md §3): each record is a 3-byte
 * big-endian ciphertext length followed by a ChaCha20-Poly1305 ciphertext.
 * Per-direction nonce counters start at 0 and increment once per record
 * (SPEC §2.5) — Kotlin mirror of desktop/internal/tunnel/secure.go.
 */
class SecureChannel(
    private val input: InputStream,
    private val output: OutputStream,
    private val readKey: ByteArray,
    private val writeKey: ByteArray,
) : ByteStream {
    init {
        require(readKey.size == 32 && writeKey.size == 32) { "toppa: transport keys must be 32 bytes" }
    }

    private var readNonce = 0L
    private var writeNonce = 0L
    private var pending: ByteArray = ByteArray(0)

    /** Encrypts [b] into one or more records and flushes. */
    @Throws(IOException::class)
    fun write(b: ByteArray) {
        var offset = 0
        while (offset < b.size) {
            val chunk = minOf(b.size - offset, MAX_RECORD_PLAINTEXT)
            val ciphertext = ChaChaPoly.encrypt(
                writeKey,
                ChaChaPoly.nonce12(writeNonce++),
                null,
                b.copyOfRange(offset, offset + chunk),
            )
            val header = byteArrayOf(
                (ciphertext.size shr 16).toByte(),
                (ciphertext.size shr 8).toByte(),
                ciphertext.size.toByte(),
            )
            output.write(header)
            output.write(ciphertext)
            offset += chunk
        }
        output.flush()
    }

    /**
     * Decrypts the next record (or drains a partially consumed one) into
     * [p]; returns the number of bytes copied.
     */
    @Throws(IOException::class)
    fun read(p: ByteArray): Int {
        if (pending.isNotEmpty()) {
            val n = minOf(p.size, pending.size)
            System.arraycopy(pending, 0, p, 0, n)
            pending = pending.copyOfRange(n, pending.size)
            return n
        }
        if (p.isEmpty()) {
            return 0
        }
        val header = Tlmp.readFully(input, RECORD_HEADER_LEN)
        val size = ((header[0].toInt() and 0xFF) shl 16) or
            ((header[1].toInt() and 0xFF) shl 8) or
            (header[2].toInt() and 0xFF)
        if (size < TAG_LEN || size > MAX_RECORD_PLAINTEXT + TAG_LEN) {
            throw IOException("toppa: record size $size out of range")
        }
        val ciphertext = Tlmp.readFully(input, size)
        val plaintext = try {
            ChaChaPoly.decrypt(readKey, ChaChaPoly.nonce12(readNonce), null, ciphertext)
        } catch (e: Exception) {
            throw IOException("toppa: record authentication failed", e)
        }
        readNonce++
        val n = minOf(p.size, plaintext.size)
        System.arraycopy(plaintext, 0, p, 0, n)
        if (n < plaintext.size) {
            pending = plaintext.copyOfRange(n, plaintext.size)
        }
        return n
    }

    /** ByteStream: -1 at EOF, otherwise bytes copied into b[off, off+len). */
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) {
            return 0
        }
        if (off == 0 && len == b.size) {
            return try {
                read(b)
            } catch (e: EOFException) {
                -1
            }
        }
        val tmp = ByteArray(len)
        val n = try {
            read(tmp)
        } catch (e: EOFException) {
            return -1
        }
        if (n > 0) {
            System.arraycopy(tmp, 0, b, off, n)
        }
        return n
    }

    /** ByteStream: writes all of b[off, off+len). */
    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off == 0 && len == b.size) {
            write(b)
        } else {
            write(b.copyOfRange(off, off + len))
        }
    }

    override fun close() {
        input.close()
        output.close()
    }

    companion object {
        const val MAX_RECORD_PLAINTEXT = 256 * 1024
        const val TAG_LEN = 16
        private const val RECORD_HEADER_LEN = 3
    }
}
