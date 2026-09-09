package dev.toppa.proto

import java.io.Closeable
import java.io.InputStream

/**
 * Ordered, reliable byte stream — the abstraction the mux rides. In
 * production this is [dev.toppa.proto.crypto.SecureChannel]; tests use pipes.
 */
interface ByteStream : Closeable {
    /** Reads up to [len] bytes into b[off, off+len); returns count, or -1 at EOF. */
    fun read(b: ByteArray, off: Int = 0, len: Int = b.size - off): Int

    /** Writes all of b[off, off+len), blocking; throws on failure. */
    fun write(b: ByteArray, off: Int = 0, len: Int = b.size - off)
}

/** InputStream view over a [ByteStream], for the TLMP codec. */
class ByteStreamInput(private val stream: ByteStream) : InputStream() {
    override fun read(): Int {
        val one = ByteArray(1)
        val n = stream.read(one, 0, 1)
        return if (n < 0) -1 else one[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int =
        if (len == 0) 0 else stream.read(b, off, len)
}
