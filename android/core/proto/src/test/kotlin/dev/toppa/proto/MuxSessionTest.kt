package dev.toppa.proto

import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** In-memory ByteStream pair for mux tests (the JVM analog of Go's net.Pipe). */
object PipedStreams {
    fun pair(): Pair<ByteStream, ByteStream> {
        val aIn = PipedInputStream()
        val aOut = PipedOutputStream()
        val bIn = PipedInputStream()
        val bOut = PipedOutputStream()
        aIn.connect(bOut) // B's writes arrive at A
        bIn.connect(aOut) // A's writes arrive at B
        fun stream(input: PipedInputStream, output: PipedOutputStream): ByteStream = object : ByteStream {
            override fun read(b: ByteArray, off: Int, len: Int): Int =
                if (len == 0) 0 else input.read(b, off, len)

            override fun write(b: ByteArray, off: Int, len: Int) {
                output.write(b, off, len)
            }

            override fun close() {
                runCatching { input.close() }
                runCatching { output.close() }
            }
        }
        return stream(aIn, aOut) to stream(bIn, bOut)
    }
}

/** Kotlin mirror of desktop/internal/mux/mux_test.go. */
class MuxSessionTest {

    private fun pair(tune: (MuxConfig) -> MuxConfig = { it }): Pair<MuxSession, MuxSession> {
        val (a, b) = PipedStreams.pair()
        val clientCfg = tune(MuxConfig(isInitiator = true, maxFramePayload = 4096, initialWindow = 64 * 1024))
        val serverCfg = tune(MuxConfig(isInitiator = false, maxFramePayload = 4096, initialWindow = 64 * 1024))
        return MuxSession(a, clientCfg) to MuxSession(b, serverCfg)
    }

    private fun echoServer(session: MuxSession) {
        thread(isDaemon = true) {
            while (true) {
                val stream = session.accept() ?: return@thread
                thread(isDaemon = true) {
                    try {
                        val buf = ByteArray(8192)
                        while (true) {
                            val n = stream.read(buf)
                            if (n < 0) break
                            stream.write(buf, 0, n)
                        }
                        stream.close()
                    } catch (e: Exception) {
                        runCatching { stream.close() }
                    }
                }
            }
        }
    }

    private fun pattern(seed: Int, size: Int): ByteArray =
        ByteArray(size) { i -> ((seed + i * 31) and 0xFF).toByte() }

    private fun readFully(stream: MuxStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val read = stream.read(out, filled, n - filled)
            if (read < 0) fail("stream EOF after $filled/$n bytes")
            filled += read
        }
        return out
    }

    private fun target(name: String, port: Int): Target = Target(
        network = Tlmp.NET_TCP,
        atyp = Tlmp.ATYP_FQDN,
        address = name.toByteArray(Charsets.US_ASCII),
        port = port,
    )

    @Test
    fun `echo stream round trip`() {
        val (client, server) = pair()
        echoServer(server)

        val stream = client.open(target("echo.toppa.test", 443))
        val payload = pattern(1, 256 * 1024)

        val writer = thread(isDaemon = true) {
            stream.write(payload)
            stream.close()
        }

        val echoed = readFully(stream, payload.size)
        assertTrue(payload.contentEquals(echoed), "echo payload mismatch")
        writer.join(5_000)
        stream.close()
    }

    @Test
    fun `concurrent streams stay independent`() {
        val (client, server) = pair()
        echoServer(server)

        val threads = (1..8).map { seed ->
            thread {
                val stream = client.open(target("fan.toppa.test", seed))
                val payload = pattern(seed, 32 * 1024)
                thread {
                    stream.write(payload)
                    stream.close()
                }
                val echoed = readFully(stream, payload.size)
                assertTrue(payload.contentEquals(echoed), "stream $seed payload mismatch")
                stream.close()
            }
        }
        threads.forEach { it.join(10_000) }
        threads.forEach { assertTrue(!it.isAlive, "a stream worker hung") }
    }

    @Test
    fun `flow control forces window round trips`() {
        val (client, server) = pair { cfg ->
            cfg.copy(initialWindow = 16 * 1024, maxFramePayload = 4096)
        }
        echoServer(server)

        val stream = client.open(target("bulk.toppa.test", 9))
        val payload = pattern(9, 1024 * 1024)
        val writer = thread(isDaemon = true) {
            stream.write(payload)
            stream.close()
        }
        val echoed = readFully(stream, payload.size)
        assertTrue(payload.contentEquals(echoed), "bulk payload mismatch (window enforcement broken)")
        writer.join(15_000)
    }

    @Test
    fun `half close drains then eof`() {
        val (client, server) = pair()
        thread(isDaemon = true) {
            val stream = server.accept() ?: return@thread
            stream.write(byteArrayOf(0x78)) // 'x'
            stream.close() // FIN: nothing more from this side
        }

        val stream = client.open(target("fin.toppa.test", 7))
        val one = ByteArray(1)
        assertEquals(1, stream.read(one), "expected the 'x' byte")
        assertEquals(-1, stream.read(one), "expected EOF after FIN")
    }

    @Test
    fun `session close wakes stream readers`() {
        val (client, server) = pair()
        val stream = client.open(target("hang.toppa.test", 1))
        thread(isDaemon = true) {
            Thread.sleep(50)
            server.close()
        }
        val started = System.currentTimeMillis()
        try {
            stream.read(ByteArray(16))
            fail("expected SessionClosedException")
        } catch (e: SessionClosedException) {
            // woke up as required
        }
        assertTrue(System.currentTimeMillis() - started < 5_000, "reader wake-up took too long")
    }

    @Test
    fun `accept returns null after close`() {
        val (client, server) = pair()
        client.close()
        // Allow the server's read loop to observe the dead pipe.
        var tries = 0
        while (tries++ < 100) {
            val stream = server.accept()
            if (stream == null) {
                assertNull(stream)
                return
            }
            Thread.sleep(10)
        }
        fail("accept did not return null after remote close")
    }
}
