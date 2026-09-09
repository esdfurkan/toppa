package dev.toppa.app

import android.content.Context
import dev.toppa.proto.crypto.X25519
import dev.toppa.relay.DohResolver
import dev.toppa.relay.RelayEngine
import dev.toppa.relay.RelayConfig
import dev.toppa.transport.AdbForwardServer
import dev.toppa.transport.SoftApServer
import dev.toppa.tunnel.RelayIdentity
import dev.toppa.tunnel.RelayRuntime
import dev.toppa.tunnel.TunnelServer
import java.io.File

/**
 * Assembles the phone-side stack for the foreground service.
 *
 * Config: Step 2 uses the shared defaults (configs/defaults.json values,
 * mirrored here until the DataStore-backed :core:config lands with the
 * settings UI). Keys: plain files under filesDir for v1 — Keystore wrapping
 * is the documented app-milestone upgrade.
 */
object AppRuntime {

    // Mirrors configs/defaults.json (kept in one place on this side).
    private const val LISTEN_PORT = 47471
    private const val MAX_FRAME_PAYLOAD = 64 * 1024
    private const val INITIAL_WINDOW = 256 * 1024
    private const val KEEPALIVE_SECS = 15
    private val DOH_SERVERS = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")

    fun createRelayRuntime(context: Context): RelayRuntime {
        val identity = FileIdentity(context)
        val relay = RelayEngine(
            upstream = AndroidUpstreamProvider(context),
            resolver = DohResolver(DOH_SERVERS),
            config = RelayConfig(),
        )
        val transport = AdbForwardServer(LISTEN_PORT)
        // SoftAP transport (secondary): enabled when the hotspot is on.
        val hotspot = SoftApServer(LISTEN_PORT + 1, AndroidApAddressProvider())
        // The TunnelServer takes ONE transport; transport arbitration by
        // priority is the TransportManager milestone. USB (adb) is v1's
        // default; the SoftAP server is exposed for contributors/tests.
        val server = TunnelServer(
            transport = transport,
            identity = identity,
            relay = relay,
            muxConfig = dev.toppa.proto.MuxConfig(
                maxFramePayload = MAX_FRAME_PAYLOAD,
                initialWindow = INITIAL_WINDOW,
                keepAliveMillis = KEEPALIVE_SECS * 1000L,
                isInitiator = false,
            ),
        )
        return RelayRuntime(server)
    }
}

/**
 * File-backed Noise identity (X25519), generated on first use. The private
 * key file is app-private storage; Keystore/StrongBox wrapping is the
 * documented next step — do not back this directory up.
 */
class FileIdentity(context: Context) : RelayIdentity {
    private val dir = File(context.filesDir, "keys").apply { mkdirs() }
    private val privFile = File(dir, "identity.priv")

    private val privateKey: ByteArray by lazy {
        if (privFile.exists()) {
            privFile.readBytes()
        } else {
            val key = X25519.generatePrivateKey()
            privFile.writeBytes(key)
            key
        }
    }

    override val staticPrivate: ByteArray
        get() = privateKey.copyOf()

    override val pinnedPeer: ByteArray?
        get() = null // TOFU pinning lands with the pairing milestone
}
