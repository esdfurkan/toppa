package dev.toppa.vpn

import kotlin.concurrent.thread

/** Reads one packet into the buffer; returns its length, or -1 at EOF. */
fun interface PacketSource {
    fun read(into: ByteArray): Int
}

/** Writes one packet of [length] bytes. */
fun interface PacketSink {
    fun write(packet: ByteArray, length: Int)
}

/**
 * The Shield-mode read/process/write loop: reads packets from the TUN
 * (PacketSource over the VpnService fd), normalizes them, and writes them
 * back for reinjection. Android-free: the app layer supplies the fd adapters.
 */
class VpnPacketLoop(
    private val source: PacketSource,
    private val sink: PacketSink,
    private val processor: PacketProcessor = PacketProcessor(),
    private val mtu: Int = 1500,
) {
    class Stats {
        @Volatile var packetsIn: Long = 0
            private set
        @Volatile var forwarded: Long = 0
            private set
        @Volatile var rewritten: Long = 0
            private set
        @Volatile var dropped: Long = 0
            private set

        internal fun countIn() { packetsIn++ }
        internal fun countForwarded(rewrittenPacket: Boolean) {
            forwarded++
            if (rewrittenPacket) rewritten++
        }
        internal fun countDropped() { dropped++ }
    }

    val stats = Stats()
    @Volatile private var running = false
    private var worker: Thread? = null

    fun start() {
        check(!running) { "vpn packet loop already running" }
        running = true
        worker = thread(name = "toppa-vpn", isDaemon = true) { runLoop() }
    }

    /**
     * Requests the loop to stop. The final unblocking happens when the
     * underlying TUN fd is closed (the VpnService teardown path).
     */
    fun stop() {
        running = false
        worker?.join(2_000)
    }

    private fun runLoop() {
        val buffer = ByteArray(mtu)
        while (running) {
            val n = try {
                source.read(buffer)
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                break
            }
            if (n <= 0) {
                break
            }
            stats.countIn()
            when (val result = processor.process(buffer, n)) {
                is PacketProcessor.Result.Dropped -> stats.countDropped()
                is PacketProcessor.Result.ForwardedRewritten -> {
                    sink.write(buffer, n)
                    stats.countForwarded(rewrittenPacket = true)
                }
                PacketProcessor.Result.ForwardedUnchanged -> {
                    sink.write(buffer, n)
                    stats.countForwarded(rewrittenPacket = false)
                }
            }
        }
    }
}
