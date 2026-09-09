package dev.toppa.relay

import java.io.IOException
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection

/**
 * DNS-over-HTTPS resolver (RFC 8484, application/dns-message POST), built on
 * HttpsURLConnection so it runs on both the JVM (CI) and Android.
 *
 * Bootstrap strategy: the DoH server URL's host is resolved once via the
 * system stack and the request is then sent to the literal IP, so queries
 * for *other* domains never touch plaintext DNS. Resolver choice per
 * transport comes from the shared config (`dns.*`).
 */
class DohResolver(
    serverUrls: List<String>,
    private val timeoutMillis: Int = 3_000,
) : Resolver {
    init {
        require(serverUrls.isNotEmpty()) { "doh: at least one server URL required" }
    }

    private val serverUrls = serverUrls.toList()
    private val queryId = AtomicInteger(1)

    override fun resolve(name: String): List<InetAddress> {
        var lastError: Exception? = null
        for (url in serverUrls) {
            try {
                return resolveVia(url, name)
            } catch (e: Exception) {
                lastError = e
            }
        }
        throw IOException("doh: all resolvers failed for $name", lastError)
    }

    private fun resolveVia(serverUrl: String, name: String): List<InetAddress> {
        val url = bootstrapUrl(serverUrl)
        val query = DnsWire.buildQuery(queryId.getAndIncrement() and 0xFFFF, name, DnsWire.TYPE_A)

        val connection = (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = timeoutMillis
            readTimeout = timeoutMillis
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/dns-message")
            setRequestProperty("Accept", "application/dns-message")
            setFixedLengthStreamingMode(query.size)
        }
        try {
            connection.outputStream.use { it.write(query) }
            val code = connection.responseCode
            val body = (if (code in 200..299) connection.inputStream else connection.errorStream)
                ?.use { it.readBytes() } ?: ByteArray(0)
            if (code != 200) {
                throw IOException("doh: HTTP $code from $serverUrl")
            }
            val addresses = DnsWire.parseResponse(body, name)
            if (addresses.isEmpty()) {
                throw IOException("doh: no A records for $name")
            }
            return addresses
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Swaps the DoH hostname for its bootstrap IP (system DNS, once per
     * call) so the DNS query itself never depends on plaintext DNS.
     */
    private fun bootstrapUrl(serverUrl: String): URL {
        val uri = URI(serverUrl)
        require(uri.scheme == "https") { "doh: server must be https ($serverUrl)" }
        val host = uri.host ?: throw IOException("doh: server URL has no host: $serverUrl")
        if (host.all { it.isDigit() || it == '.' }) {
            return URL(serverUrl) // already a literal IP
        }
        val ip = InetAddress.getAllByName(host).first()
        val literal = if (ip.address.size == 4) ip.hostAddress else "[${ip.hostAddress}]"
        val port = if (uri.port == -1) 443 else uri.port
        return URL("https", literal, port, uri.path ?: "/dns-query")
    }
}
