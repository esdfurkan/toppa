package dev.toppa.proto

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

class MuxConfig(
    val maxFramePayload: Int = 64 * 1024,
    val initialWindow: Int = 256 * 1024,
    val keepAliveMillis: Long = 0,
    val pingTimeoutMillis: Long = 45_000,
    val acceptQueueDepth: Int = 64,
    val isInitiator: Boolean,
)

class TlmpProtocolException(message: String) : IOException(message)
class StreamResetException : IOException("tlmp: stream reset by remote")
class SessionClosedException : IOException("tlmp: session closed")

/** Growable ring buffer for stream receive queues. Not thread-safe: callers lock. */
internal class ByteBufferQueue(initialCapacity: Int = 4096) {
    private var buf = ByteArray(if (initialCapacity < 16) 16 else initialCapacity)
    private var head = 0
    private var tail = 0

    val size: Int get() = (tail - head + buf.size) % buf.size

    fun push(src: ByteArray, off: Int, len: Int) {
        ensureCapacity(len)
        if (head <= tail) {
            val first = minOf(len, buf.size - tail)
            System.arraycopy(src, off, buf, tail, first)
            System.arraycopy(src, off + first, buf, 0, len - first)
        } else {
            System.arraycopy(src, off, buf, tail, len)
        }
        tail = (tail + len) % buf.size
    }

    fun drain(dst: ByteArray, off: Int, len: Int): Int {
        val n = minOf(len, size)
        if (head + n <= buf.size) {
            System.arraycopy(buf, head, dst, off, n)
        } else {
            val first = buf.size - head
            System.arraycopy(buf, head, dst, off, first)
            System.arraycopy(buf, 0, dst, off + first, n - first)
        }
        head = (head + n) % buf.size
        return n
    }

    private fun ensureCapacity(extra: Int) {
        if (size + extra <= buf.size) {
            return
        }
        var newCap = buf.size
        while (newCap < size + extra) {
            newCap *= 2
        }
        val grown = ByteArray(newCap)
        val n = size
        val tmp = ByteArray(n)
        drain(tmp, 0, n)
        System.arraycopy(tmp, 0, grown, 0, n)
        buf = grown
        head = 0
        tail = n
    }
}

/**
 * One multiplexed channel — Kotlin mirror of desktop/internal/mux/stream.go.
 * Reads drain buffered data then return -1 after the remote FIN; [close]
 * half-closes the write side (FIN).
 */
class MuxStream internal constructor(
    val id: Int,
    val target: Target,
    private val session: MuxSession,
    initialWindow: Long,
) : AutoCloseable {
    private val lock = ReentrantLock()
    private val condition = lock.newCondition()
    private val buffer = ByteBufferQueue()
    private var sendWindow = initialWindow
    private var recvUnacked = 0L
    private var finReceived = false
    private var finSent = false
    private var reset = false
    private var sessionClosed = false

    fun read(p: ByteArray, off: Int = 0, len: Int = p.size - off): Int {
        if (len == 0) {
            return 0
        }
        val n: Int
        var credit = 0L
        lock.withLock {
            while (buffer.size == 0) {
                when {
                    reset -> throw StreamResetException()
                    finReceived -> return -1
                    sessionClosed -> throw SessionClosedException()
                }
                condition.await()
            }
            n = buffer.drain(p, off, len)
            credit = recvUnacked + n
            recvUnacked = 0
        }
        if (credit > 0) {
            session.writeWindowUpdate(id, credit)
        }
        return n
    }

    fun write(b: ByteArray, off: Int = 0, len: Int = b.size - off) {
        var sent = 0
        while (sent < len) {
            var chunk = 0
            lock.withLock {
                while (sendWindow == 0L) {
                    when {
                        reset -> throw StreamResetException()
                        sessionClosed -> throw SessionClosedException()
                        finSent -> throw IOException("tlmp: write on half-closed stream")
                    }
                    condition.await()
                }
                if (reset) {
                    throw StreamResetException()
                }
                chunk = minOf((len - sent).toLong(), sendWindow, session.config.maxFramePayload.toLong()).toInt()
                sendWindow -= chunk
            }
            session.writeDataFrame(id, b, off + sent, chunk)
            sent += chunk
        }
    }

    override fun close() {
        val remove: Boolean
        lock.withLock {
            if (finSent) {
                return
            }
            finSent = true
            remove = finReceived
            condition.signalAll()
        }
        if (remove) {
            session.removeStream(id)
        }
        session.writeFin(id)
    }

    internal fun pushData(payload: ByteArray) {
        lock.withLock {
            if (buffer.size + payload.size > session.config.initialWindow) {
                throw TlmpProtocolException("tlmp: receive window exceeded on stream $id")
            }
            if (payload.isNotEmpty()) {
                buffer.push(payload, 0, payload.size)
            }
            condition.signalAll()
        }
    }

    internal fun remoteClosed() {
        var both = false
        lock.withLock {
            finReceived = true
            both = finSent
            condition.signalAll()
        }
        if (both) {
            session.removeStream(id)
        }
    }

    internal fun addSendWindow(credit: Long) {
        lock.withLock {
            sendWindow += credit
            condition.signalAll()
        }
    }

    internal fun sessionClosedNow() {
        lock.withLock {
            sessionClosed = true
            condition.signalAll()
        }
    }

    internal fun remoteReset() {
        lock.withLock {
            reset = true
            condition.signalAll()
        }
    }
}

/**
 * TLMP session — Kotlin mirror of desktop/internal/mux/session.go: stream
 * multiplexing with window-credit flow control, PING/PONG keepalive, and
 * GOAWAY teardown (protocol/SPEC.md §4). Ends must use mirrored
 * [MuxConfig.isInitiator] values.
 */
class MuxSession(
    private val conn: ByteStream,
    val config: MuxConfig,
) : AutoCloseable {
    private val streams = ConcurrentHashMap<Int, MuxStream>()
    private val nextId = AtomicInteger(if (config.isInitiator) 1 else 2)
    private val acceptQueue = LinkedBlockingQueue<MuxStream>(config.acceptQueueDepth)
    private val closed = AtomicBoolean(false)
    private val writeLock = Any()
    @Volatile private var lastRecvMillis = System.currentTimeMillis()

    private val reader = thread(name = "tlmp-reader", isDaemon = true) { readLoop() }
    private val keepAlive = if (config.keepAliveMillis > 0) {
        thread(name = "tlmp-keepalive", isDaemon = true) { keepAliveLoop() }
    } else {
        null
    }

    fun open(target: Target): MuxStream {
        if (closed.get()) {
            throw SessionClosedException()
        }
        val id = nextId.getAndAdd(2)
        val stream = MuxStream(id, target, this, config.initialWindow.toLong())
        streams[id] = stream
        try {
            writeFrame(Flags.SYN, id, Tlmp.appendTarget(ByteArray(0), target))
        } catch (e: Exception) {
            streams.remove(id)
            throw e
        }
        return stream
    }

    /** Next inbound stream, or null once the session has closed. */
    fun accept(): MuxStream? {
        while (true) {
            val stream = acceptQueue.poll(50, TimeUnit.MILLISECONDS)
            if (stream != null) {
                return stream
            }
            if (closed.get()) {
                return null
            }
        }
    }

    override fun close() {
        teardown(sendGoaway = true, Flags.REASON_NORMAL)
    }

    internal fun isClosed(): Boolean = closed.get()

    internal fun writeFrame(flags: Int, streamId: Int, payload: ByteArray) {
        if (closed.get()) {
            throw SessionClosedException()
        }
        val bytes = encodeFrame(flags, streamId, payload)
        synchronized(writeLock) {
            conn.write(bytes, 0, bytes.size)
        }
    }

    internal fun writeDataFrame(streamId: Int, b: ByteArray, off: Int, len: Int) {
        val payload = if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len)
        writeFrame(Flags.DATA, streamId, payload)
    }

    internal fun writeWindowUpdate(streamId: Int, credit: Long) {
        val payload = ByteArray(4)
        for (i in 0 until 4) {
            payload[i] = ((credit ushr (8 * (3 - i))) and 0xFFL).toByte()
        }
        runCatching { writeFrame(Flags.WIN, streamId, payload) }
    }

    internal fun writeFin(streamId: Int) {
        runCatching { writeFrame(Flags.FIN, streamId, ByteArray(0)) }
    }

    internal fun removeStream(streamId: Int) {
        streams.remove(streamId)
    }

    internal fun resetStream(streamId: Int) {
        streams.remove(streamId)?.remoteReset()
    }

    private fun readLoop() {
        val input = ByteStreamInput(conn)
        while (true) {
            val frame = try {
                Tlmp.readFrame(input, config.maxFramePayload)
            } catch (e: Exception) {
                teardown(false, Flags.REASON_NORMAL)
                return
            }
            lastRecvMillis = System.currentTimeMillis()
            try {
                handleFrame(frame)
            } catch (e: TlmpProtocolException) {
                teardown(true, Flags.REASON_PROTOCOL)
                return
            } catch (e: Exception) {
                teardown(false, Flags.REASON_NORMAL)
                return
            }
        }
    }

    private fun handleFrame(frame: Frame) {
        when {
            frame.flags and Flags.SYN != 0 -> {
                val target = try {
                    Tlmp.parseTarget(frame.payload)
                } catch (e: Exception) {
                    runCatching { writeFrame(Flags.RST, frame.streamId, byteArrayOf(Flags.REASON_PROTOCOL.toByte())) }
                    return
                }
                val stream = MuxStream(frame.streamId, target, this, config.initialWindow.toLong())
                if (streams.putIfAbsent(frame.streamId, stream) != null) {
                    runCatching { writeFrame(Flags.RST, frame.streamId, byteArrayOf(Flags.REASON_BUSY.toByte())) }
                    return
                }
                if (!acceptQueue.offer(stream)) {
                    resetStream(frame.streamId)
                    runCatching { writeFrame(Flags.RST, frame.streamId, byteArrayOf(Flags.REASON_BUSY.toByte())) }
                }
            }
            frame.flags and Flags.DATA != 0 -> {
                val stream = streams[frame.streamId]
                if (stream == null) {
                    runCatching { writeFrame(Flags.RST, frame.streamId, byteArrayOf(Flags.REASON_BUSY.toByte())) }
                    return
                }
                stream.pushData(frame.payload) // window violation is fatal to the session
            }
            frame.flags and Flags.FIN != 0 -> streams[frame.streamId]?.remoteClosed()
            frame.flags and Flags.RST != 0 -> resetStream(frame.streamId)
            frame.flags and Flags.WIN != 0 -> {
                if (frame.payload.size == 4) {
                    var credit = 0L
                    for (b in frame.payload) {
                        credit = (credit shl 8) or (b.toLong() and 0xFF)
                    }
                    streams[frame.streamId]?.addSendWindow(credit)
                }
            }
            frame.flags and Flags.PING != 0 -> writeFrame(Flags.PONG, 0, frame.payload)
            frame.flags and Flags.PONG != 0 -> Unit
            frame.flags and Flags.GOAWAY != 0 -> throw SessionClosedException()
            else -> throw TlmpProtocolException("tlmp: unhandled frame flags 0x${frame.flags.toString(16)}")
        }
    }

    private fun keepAliveLoop() {
        try {
            while (!closed.get()) {
                Thread.sleep(config.keepAliveMillis)
                val idle = System.currentTimeMillis() - lastRecvMillis
                if (idle > config.pingTimeoutMillis) {
                    teardown(false, Flags.REASON_NORMAL)
                    return
                }
                val nonce = ByteArray(8)
                for (i in nonce.indices) {
                    nonce[i] = (System.nanoTime() ushr (8 * (i % 8))).toByte()
                }
                writeFrame(Flags.PING, 0, nonce)
            }
        } catch (e: InterruptedException) {
            // Session closed; exiting.
        } catch (e: Exception) {
            teardown(sendGoaway = false, Flags.REASON_NORMAL)
        }
    }

    private fun teardown(sendGoaway: Boolean, reason: Int) {
        if (!closed.compareAndSet(false, true)) {
            return
        }
        if (sendGoaway) {
            runCatching {
                val bytes = encodeFrame(Flags.GOAWAY, 0, byteArrayOf(reason.toByte()))
                synchronized(writeLock) {
                    conn.write(bytes, 0, bytes.size)
                }
            }
        }
        runCatching { conn.close() }
        for (stream in streams.values) {
            stream.sessionClosedNow()
        }
        streams.clear()
    }

    private fun encodeFrame(flags: Int, streamId: Int, payload: ByteArray): ByteArray =
        ByteArrayOutputStream(payload.size + Tlmp.HEADER_SIZE).also {
            Tlmp.writeFrame(it, flags, streamId, payload)
        }.toByteArray()
}
