package dev.toppa.transport

import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * A link transport's phone-side listener. The PC connects over the link
 * (adb forward, SoftAP Wi-Fi, Wi-Fi Direct) and every accepted [Socket] is
 * handed to :core:tunnel for the Noise handshake.
 */
interface TransportServer {
    /** Stable transport identity ("usb", "hotspot", "wfd"); loop-guard key. */
    val id: String

    /** Port actually bound (relevant when constructed with an ephemeral port). */
    val boundPort: Int?

    fun start(onConnection: (Socket) -> Unit)

    fun stop()
}

/**
 * TCP listener shared by the USB and SoftAP transports. Bind addresses are
 * always discovered/narrow (loopback for adb, the AP interface address for
 * SoftAP) — never 0.0.0.0.
 */
open class TcpServer(
    override val id: String,
    private val bindAddress: InetAddress,
    private val requestedPort: Int,
) : TransportServer {
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    @Volatile private var handler: ((Socket) -> Unit)? = null

    override val boundPort: Int?
        get() = serverSocket?.localPort

    override fun start(onConnection: (Socket) -> Unit) {
        check(serverSocket == null) { "transport $id already started" }
        handler = onConnection
        val socket = ServerSocket(requestedPort, BACKLOG, bindAddress)
        serverSocket = socket
        acceptThread = thread(name = "toppa-accept-$id", isDaemon = true) {
            while (!socket.isClosed) {
                val client = try {
                    socket.accept()
                } catch (e: Exception) {
                    return@thread
                }
                handler?.invoke(client)
            }
        }
    }

    override fun stop() {
        runCatching { serverSocket?.close() }
        acceptThread?.join(1_000)
    }

    private companion object {
        const val BACKLOG = 64
    }
}

/**
 * USB transport. The PC runs `adb forward tcp:<hostport> tcp:<our port>`, so
 * adbd connects to us from the device's loopback — the carrier never sees
 * this link at all, which is why USB is the default transport.
 */
class AdbForwardServer(requestedPort: Int) : TransportServer by TcpServer(
    id = "usb",
    bindAddress = InetAddress.getLoopbackAddress(),
    requestedPort = requestedPort,
)

/** Supplies the hotspot (SoftAP) interface address at runtime. */
fun interface ApAddressProvider {
    fun hotspotAddress(): InetAddress
}

/**
 * Wi-Fi SoftAP transport. The AP interface address is discovered at runtime
 * via [ApAddressProvider] — historically 192.168.43.x / 192.168.49.x on some
 * builds, and hardcoding that is exactly the kind of assumption that breaks
 * across OEMs.
 */
class SoftApServer(
    private val requestedPort: Int,
    private val apAddress: ApAddressProvider,
) : TransportServer {
    override val id: String = "hotspot"
    private var delegate: TcpServer? = null

    override val boundPort: Int?
        get() = delegate?.boundPort

    override fun start(onConnection: (Socket) -> Unit) {
        check(delegate == null) { "transport $id already started" }
        val server = TcpServer(id, apAddress.hotspotAddress(), requestedPort)
        delegate = server
        server.start(onConnection)
    }

    override fun stop() {
        delegate?.stop()
    }
}
