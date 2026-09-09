package dev.toppa.vpn

/**
 * Command builder for the optional ROOT-ONLY classic-hotspot NAT clamp
 * (docs/ARCHITECTURE.md §1.1, layer L2) — for users who must run legacy L3
 * tethering (game consoles) on a rooted phone.
 *
 * This object only *generates* commands; execution requires an explicit
 * RootShell supplied by the caller. Nothing here runs implicitly, and the
 * core relay path never depends on it.
 */
object RootNatClamp {

    fun addCommands(ipv4Ttl: Int, ipv6HopLimit: Int, clampMss: Boolean): List<String> = buildList {
        add("iptables -t mangle -A POSTROUTING -j TTL --ttl-set $ipv4Ttl")
        add("ip6tables -t mangle -A POSTROUTING -j HL --hl-set $ipv6HopLimit")
        if (clampMss) {
            add("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
        }
    }

    /** Inverts [addCommands] output for teardown. */
    fun removeCommands(commands: List<String>): List<String> =
        commands.map { it.replace(" -A ", " -D ") }
}
