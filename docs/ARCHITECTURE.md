# Toppa — Cross-Platform Tether-Obfuscation Suite

## Architectural Specification v0.1

> Project name: **Toppa** (renamed from the original `umbra` codename on 2026-09-09; the whole tree — module path, Kotlin package, protocol name TLMP, CLI — uses it consistently). The GitHub namespace `github.com/esdfurkan/toppa` remains a placeholder until the repository is published under its final org/user.

---

## 0. Goal Confirmation, Scope, and Honest Constraints

### 0.1 What we are building

Two **first-party** devices cooperate:

- **Android phone** — owns the metered cellular uplink. Runs a Kotlin app that terminates an encrypted multiplexed tunnel and **re-originates** every flow from its own socket layer onto the cellular radio.
- **Windows PC** — consumes connectivity. Runs a Go daemon that captures system traffic at L3 via a Wintun adapter, converts it to L5 flows in a user-space TCP/IP stack, and relays it to the phone over a short-range transport (USB/ADB, Wi-Fi SoftAP, Wi-Fi Direct later).

The product goal: PC-originated traffic becomes indistinguishable from ordinary phone traffic at the carrier, defeating tethering detection (TTL fingerprinting, OS fingerprinting, DNS patterns), avoiding tethering-specific data caps, and removing tethering headers from the visible path — combining PdaNet+-style socket redirection and PairVPN-style P2P encrypted tunneling in a modular, contributor-friendly, fully config-driven open-source codebase.

### 0.2 The load-bearing architectural theorem

> **A carrier can only fingerprint what crosses the cellular interface. If no IP packet that originated on the PC ever egresses the phone's radio — if every flow is re-originated by a socket owned by our Android app — then Windows TTL=128, Windows TCP options/window signatures, SMB/UPnP chatter, and PC DNS behavior never reach the carrier, and TTL normalization becomes satisfied by construction.**

Therefore the system is designed as a **user-space relay, not a router**. Classic NAT-based tethering (L3 forwarding inside the phone) is explicitly *not* the primary mode; it is supported only as an optional, root-only legacy module (§1.1, Layer L2). Every design decision follows from this theorem.

### 0.3 Responsibility, legality, and non-guarantees

- Running this tool may breach the user's carrier Terms of Service. The project ships for education/research on **the user's own devices**; users are responsible for compliance with their contracts and local law (`README.md`, `docs/legal.md`).
- **Detection is reduced, not eliminated.** Residual carrier signals remain: e2e TLS SNI/ALPN sets visible on phone-origin flows (we will not MITM user TLS), aggregate flow counts/ports, volume, and timing. `docs/THREAT-MODEL.md` enumerates these explicitly.
- **Non-root Android cannot rewrite TTL of L3-forwarded packets.** VpnService's TUN does not reliably capture tethered-client traffic on current Android, and the API offers no guarantee. This is a platform fact — hence the L5-relay architecture.
- Distribution note: the battery-optimization exemption flow is restricted on Google Play; GitHub Releases and F-Droid are the primary channels.

---

## 1. PHASE 1 — Carrier Detection Bypass & Obfuscation Techniques

### 1.1 TTL (Time to Live) & Hop Limit Normalization

**Detection mechanics.** A carrier rule of the form `inbound_ttl < 64 → tethered` exploits that Windows initializes IPv4 TTL at 128 and IPv6 Hop Limit at 128, while Android/Linux uses 64. In classic hotspot NAT the phone decrements the client packet (128 → 127), so the carrier sees 127 where it expects 64.

**Where the leak exists** — by transport mode:

| Mode | Forwarding path | TTL leak possible? |
|---|---|---|
| Classic hotspot NAT (no app) | phone L3-forwards | **Yes** (127 vs 64) |
| Toppa over USB (adb forward) | no IP forwarding, relay at L5 | No — PC TTL never crosses the radio |
| Toppa over Wi-Fi SoftAP | no IP forwarding, relay at L5 | No |
| Toppa over Wi-Fi Direct | no IP forwarding, relay at L5 | No |

**Defense-in-depth layers implemented in Toppa:**

- **L0 — Structural (default, all modes):** L5 re-origination. Every egress packet is emitted by the Android kernel on behalf of our app with Android's native TTL/HL = 64. Nothing to rewrite.
- **L1 — Shield mode (`:core:vpn`, opt-in, corrected 2026-09-09):** a VpnService TUN is a single pipe — reads are app *egress*, writes are app *ingress* — so "rewrite TTL and re-inject" is architecturally impossible without a phone-side netstack. What Shield mode honestly provides today: **DNS shield** (the TUN routes only the resolver address; queries are answered via DoH, killing plaintext DNS) and a **kill-switch drop mode**. The `:core:vpn` packet engine (TTL/HL forcing + checksums, `protocol/vectors/packets.json`) is the reusable component for an *experimental root-forwarded-capture* mode (root `ip-rule` steering forwarded traffic into the TUN with protected egress) — flagged as a contributor extension, not a shipped path.
- **L2 — Root NAT clamp (optional legacy module, disabled by default):** for users who must run classic hotspot NAT (game consoles): root-only iptables mangle rules — `TTL --ttl-set 64`, IPv6 `HL --hl-set 64`, plus `TCPMSS --clamp-mss-to-pmtu`. Shipped as a clearly flagged `root-hotspot` extension module; never a core dependency.

**ICMP policy:** the PC's ICMP is not forwarded (traceroute fingerprints). The netstack answers echo for adapter-local addresses; internet-bound ping is unsupported in v1 (documented), with TCP-based reachability checks provided instead.

**IPv6 parity:** v1 tunnel is IPv4-only internally. To prevent an IPv6 SLAAC leak around the tunnel, Wintun claims a `::/0` route that blackholes into the tunnel (netstack returns unreachable), controlled by `ipv6.blackhole=true`. Native IPv6 is a v2 item; the packet parser treats v6 headers as first-class so contributors can extend it.

### 1.2 P2P Encrypted Tunneling (PairVPN-style)

Although the PC↔phone link is short-range (USB/Wi-Fi) and the carrier never sees it, the tunnel is encrypted and mutually authenticated for: protection from other clients on the hotspot network, a uniform security model across transports, and protection when links are reused in untrusted environments.

**Cryptographic design:**

- **Handshake:** Noise_XX for initial pairing (no pre-shared keys needed), hardened with a Short Authentication String — both screens display a 6-digit code derived from the handshake transcript hash; the user confirms once. Session resume uses Noise_IK semantics via pinned peer static keys.
- **Keys:** Noise static keypairs generated at first run. Phone: private key wrapped by Android Keystore (StrongBox where available). PC: DPAPI wrapping planned for the Step 3 packaging milestone; v1 stores with restrictive file permissions.
- **Cipher:** ChaCha20-Poly1305 AEAD with caller-managed, monotonically increasing per-direction nonce counters and replay rejection.

**Link multiplexing — custom "TLMP" (Toppa Link Multiplexing Protocol):** rather than depending on yamux (weak Kotlin parity, dependency-drift risk), we define a small strict spec: fixed-size frame header (version, flags, stream id, length) + window-credit flow control, carrying three channel types — relay streams, UDP datagram associations, and control messages (PING/PONG/GOAWAY). Spec, golden vectors, and fuzz targets live in `/protocol`; Go and Kotlin are independent implementations validated against the vectors.

**Transports carrying the tunnel** (pluggable behind one interface; priority is config, not code):

| Transport | Carrier visibility | Realistic throughput | Setup friction | Status |
|---|---|---|---|---|
| USB via `adb forward` | none (no radio use at all) | ~100–300 Mbps (ADB overhead-bound on USB 2.0) | USB debugging + adb binary | v1 default |
| Wi-Fi SoftAP hotspot | none (Wi-Fi is local) | Wi-Fi bound (50–300 Mbps) | user enables hotspot; some carrier/OEM builds run entitlement checks (documented, not circumvented) | v1 |
| Wi-Fi Direct (P2P) | none | medium | Windows WFD pairing is complex from Go (WinRT); user-pair-once then auto-reconnect | v1.x experimental |
| Bluetooth PAN | none | ~1–2 Mbps | poor UX | out of scope |

ADB specifics (direction matters): we use **`adb forward tcp:<hostport> tcp:<phoneport>`** — the PC connects to its own loopback and adbd completes the connection to our listener on the phone. Traffic rides the USB bus; there is *no carrier-visible artifact of tethering whatsoever* in this mode, which is why it is the default. Phone-side listeners bind loopback or the P2P interface only — never all interfaces.

**Battery note:** USB mode is also the battery-friendliest (no simultaneous Wi-Fi + cellular radio co-existence cost), reinforcing its default status.

### 1.3 Local Proxy / Socket Redirection (PdaNet-style)

**The PC-side chain** (all in-process; no external SOCKS port exposed by default):

```
apps (TCP/UDP/DNS)
   │  L3 packets
   ▼
Wintun adapter (MTU = config, default 1380)  — routes 0/0 + ::/0 blackhole
   │  L3 frames
   ▼
netstack (gVisor)  — L3→L5 conversion, MSS clamp, local ICMP answers
   │  per-flow Dial / UDP assoc
   ▼
Relay core — HeaderSanitizer (plain HTTP UA rewrite), pacing profile
   │  TLMP streams / datagrams
   ▼
Noise AEAD record layer
   │  encrypted frames
   ▼
Transport (adb forward │ SoftAP │ WFD)        ← carrier never sees this link
                                               ▼
                        Phone: transport listener → TLMP mux → Noise responder
                                               ▼
                        Relay engine: stream → real socket
                          ├─ TCP connect (native Android TTL 64)
                          ├─ UDP assoc with endpoint-independent mapping (full-cone-like)
                          └─ DNS: DoH upstream + cache
                                               ▼
                                   Cellular radio → carrier sees phone-shaped traffic
```

Key mechanics:

- **No L3 anywhere past Wintun.** The netstack terminates TCP/UDP so Windows-flavored headers never exist beyond the local adapter.
- **UDP relay** with endpoint-independent mapping on the phone (one local port per association) for NAT-friendliness (games, WebRTC). v1 rides the encrypted TCP transport (head-of-line accepted, documented); QUIC transport is a v2 candidate.
- **Optional LAN exposure:** an authenticated SOCKS5/HTTP listener bound to the P2P interface lets a tablet/second device reuse the tunnel ("tablet mode"), explicitly opt-in via config.
- **Android upstream pinning (critical):** phone relay sockets bind to the network selected via `ConnectivityManager.requestNetwork(INTERNET + TRANSPORT_CELLULAR)` and per-socket `Network.bindSocket()`. This prevents the relay's own traffic from looping back out the hotspot interface, plus a **loop guard** that refuses an upstream whose network equals the transport's network.
- **ADB/dev-mode constraint** is documented for the USB transport; SoftAP exists as the no-dev-mode fallback.

### 1.4 DPI & Fingerprint Obfuscation

**Surface analysis — what the carrier can actually observe** in our architecture:

| Carrier-observable signal | Classic NAT tethering | Toppa (L5 relay) | Mitigation status |
|---|---|---|---|
| TTL/HL < expected | leaked (127) | eliminated by re-origination | structural (L0) |
| PC TCP options / window / MSS signature | leaked | eliminated — flows are Android sockets | structural (L0) |
| Plaintext DNS of PC domains | leaked | eliminated (tunneled DNS + DoH) | §1.5 |
| HTTP User-Agent "Windows NT …" | leaked (payload) | **still visible** in plaintext HTTP payload even when relayed | relay-level `HeaderSanitizer` rewrites headers before tunneling; HTTPS hides UA from the carrier |
| e2e TLS SNI/ALPN set (e.g., Steam/Windows Update on a "phone") | visible | visible (phone-origin) | **cannot** be mitigated without MITM — accepted residual risk, documented in threat model |
| Flow count / port diversity / volume / burst timing | flagged | visible (phone-origin) | configurable pacing profile + concurrency caps; honest about limited efficacy |

**Module set (all config-gated, default profile `none` or `light`):**

- `obfuscation.pacing` — smoothing of PC-like bursts at the relay (small jitter buffers, concurrency caps) so aggregate phone behavior stays organic. Bounded, measurable, off by default.
- `obfuscation.padding` — TLMP frame padding profiles for the tunnel link (protects hotspot-local observers, future-proofs direct-cellular modes).
- `obfuscation.tls` — for flows **we** terminate (DoH to resolvers, future remote-relay mode): uTLS-style ClientHello shaping and SNI splitting. We do **not** terminate user TLS.
- `HeaderSanitizer` — plain-HTTP `User-Agent`/OS header rewrite (Windows → Android UA) at the PC relay, with an explicit "plain HTTP is sanitized; HTTPS UA is invisible to the carrier" contract.
- Root legacy module (§1.1 L2) additionally clamps MSS for classic-NAT users.

### 1.5 Secure DNS Routing

**Leak paths enumerated:** adapter DNS on non-tunnel interfaces; Windows parallel queries ("Smart Multi-Homed Name Resolution") to physical adapters; LLMNR/mDNS multicast; DoH bootstrap chicken-and-egg; IPv6 DNS; on-link DNS (the hotspot's dnsmasq resolving PC's stray queries out the cellular interface).

**Architecture:**

- **PC local resolver** owns DNS: the Wintun adapter's DNS points at the tunnel resolver address.
- **Physical-adapter DNS rewrite:** on connect, the daemon rewrites all physical adapters' DNS servers to the tunnel resolver (journaled, rolled back on disconnect/crash-recovery). This deterministically kills parallel-query leaks rather than fighting Windows heuristics.
- **Resolution modes** (config `dns.mode`, default `phone_doh`):
  - `phone_doh` — queries ride a TLMP DNS channel; the phone resolves via DoH, bootstrap servers pinned by IP, cache with TTL respect, ECS stripped, system-DNS fallback behind an explicit toggle. Carrier sees only DoH TLS from the phone.
  - `pc_doh` — PC performs DoH itself through the tunnel; zero DNS activity on the phone radio.
  - `phone_system` — phone uses the system resolver (maximum traffic realism, least privacy) — for users optimizing purely against carrier heuristics.
- **Kill-switch interaction:** with fail-closed routing (§3), even queries that bypass our resolver die in the blackhole route — no plaintext DNS can exit via the physical path.
- **Android side:** DoH sockets are `protect()`-ed in Shield mode; per-transport DoH provider preference supported.

---

## 2. PHASE 2 — Android System Architecture (Kotlin)

### 2.1 Module map (Gradle multi-module, feature/core split for PR-friendliness)

| Module | Responsibility |
|---|---|
| `:app` | Single-activity Compose shell, navigation, DI wiring (Hilt) |
| `:core:proto` | TLMP codec, Noise wrapper, wire types (pure JVM — runs in CI interop tests) |
| `:core:tunnel` | Session lifecycle, reconnect/backoff, keepalives, key store (Keystore-wrapped) |
| `:core:relay` | Stream→socket engine, UDP associations, upstream network pinning + loop guard, DoH resolver |
| `:core:transport` | `TransportServer` interface; `AdbForwardServer`, `SoftApServer`, `WifiDirectServer` (experimental), `LoopbackServer` (tests) |
| `:core:vpn` | VpnService TUN engine: IP/v6 packet parser, TTL/HL rewrite, checksum fix, Shield mode, root NAT clamp hooks |
| `:core:service` | Foreground service orchestration, wake/wifi locks, notification, lifecycle |
| `:core:config` | DataStore-backed config, JSON-schema-validated, shared schema with desktop |
| `:feature:pairing` | QR / SAS-code pairing UX |
| `:feature:dashboard` | Status, throughput, transport picker, battery, logs |

### 2.2 VpnService integration (`:core:vpn`)

- `VpnService.Builder` with `addAddress`/`addRoute`/`setMtu`/`addDnsServer`, `establish()` → `ParcelFileDescriptor`; packet I/O on a dedicated thread with pooled buffers.
- **Packet parser** as a standalone, unit-testable component: IPv4/IPv6 header read/write, TTL/HL forcing, checksum recomputation (header + pseudo-header for TCP/UDP), driven by pcap **fixture files** in CI — this is where "Android Packet Interception & TTL Manipulation" (roadmap Step 2) is implemented and verified without a device.
- `protect()` applied to all relay, DoH, and transport-adjacent sockets to prevent routing loops.
- Honest scoping (restated): this module's runtime value is Shield-mode hardening and (root) NAT clamp hooks. It is **not** load-bearing for the core bypass path, and the docs say so.

### 2.3 Dynamic connection handling

- `TransportManager` arbitrates transports by configured priority with health probes (RTT/jitter), seamless handover: new transport authenticated and warmed *before* the old one is torn down; in-flight TLMP streams drain; UI announces the switch.
- Transport reachability discovery: ADB presence detection (PC-side responsibility), SoftAP interface enumeration via `WifiManager`/`ConnectivityManager` (bind listeners to the AP interface address — discovered at runtime, **never hardcoded**, e.g. the historical 192.168.43.x/49.x defaults), WFD group owner address from `WifiP2pManager.requestConnectionInfo`.

### 2.4 Background resilience

- **Foreground service** with `dataSync` type (`specialUse` fallback and Play-policy documentation), `START_STICKY`, `onTaskRemoved` handling, WorkManager supervision job for restart, and `onRevoke` (VPN revoked) → clean teardown.
- **Locks:** `WifiLock` (`WIFI_MODE_FULL_HIGH_PERF`, `WIFI_MODE_FULL_LOW_LATENCY` on API 29+) held only while the SoftAP/WFD transport is active; partial wake lock held only while non-idle streams exist — battery is a design constraint, not an afterthought.
- **Battery-optimization bypass:** guided `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` flow with `isIgnoringBatteryOptimizations` checks, plus per-OEM autostart hints (MIUI/HyperOS, EMUI, ColorOS kill background services aggressively — documented in-app).
- Process-death recovery: all state (keys, config, session stats) persisted via DataStore + encrypted preferences; cold-start reconciliation resumes listening.

---

## 3. PHASE 3 — Windows System Architecture (Go)

### 3.1 Module map

| Package | Responsibility |
|---|---|
| `cmd/toppasvc` | Elevated service: owns adapter, routes, tunnel (v1 may run as elevated console for development) |
| `cmd/toppa` | Fyne tray/GUI (talks to the service via named-pipe JSON control API) |
| `cmd/toppactl` | CLI: pairing, status, config, diagnostics |
| `internal/adapter` | Wintun adapter lifecycle (create/open/delete, session rx/tx rings) behind a `TunDevice` interface |
| `internal/sysroute` | `RouteManager`: addresses, routes (0/0, ::/0 blackhole), DNS rewrite of *all* adapters, physical-interface pinning of tunnel sockets |
| `internal/netstack` | gVisor netstack wiring: `TunDevice` ↔ L3↔L5, per-flow handlers, MSS advertisement, ICMP-local |
| `internal/relay` | Dialer/UDP-associator toward the tunnel; HeaderSanitizer; pacing |
| `internal/mux` + `internal/keys` | TLMP codec; Noise sessions; key storage |
| `internal/transport` | `Transport` interface; `adb`, `wlan` (SoftAP), `wfd` (experimental), `loopback` (tests) |
| `internal/resolver` | Local DNS listener, modes (§1.5), cache, bootstrap |
| `internal/obfuscation` | Pacing/padding/TLS-shaping profiles (registry pattern) |
| `internal/failsafe` | Mutation journal, rollback, kill-switch policy, reconcile-on-start |
| `internal/config` | JSON config, schema-validated, shared schema with Android |
| `internal/api` | Named-pipe control API for UI/CLI |

### 3.2 Wintun adapter & route management

- Adapter creation/deletion via `golang.zx2c4.com/wintun` (admin required; `wintun.dll` shipped by the installer — redistribution terms verified during the packaging milestone); address/MTU/route/DNS mutation behind `RouteManager` so the LUID-level implementation (winipcfg-style IP helper APIs) is swappable and testable.
- **Route strategy: overlay, never delete.** Wintun gets `0.0.0.0/0` at a lower metric than the physical default; physical routes stay intact for instant rollback. A `::/0` blackhole route (config) closes the IPv6 leak.
- **Tunnel socket egress pinning (the Go equivalent of Android `protect()`):** Windows' weak-host model means binding a source IP does *not* pin the egress interface; tunnel transport sockets set `IP_UNICAST_IF` to the physical interface LUID, otherwise the tunnel routes into its own Wintun (classic routing loop).

### 3.3 tun2socks layer

- gVisor (`gvisor.dev/gvisor/pkg/tcpip`) as the default user-space stack, wrapped behind a `PacketEngine` interface (contributors can substitute lwIP or a custom engine without touching adapters/relay).
- Per-flow handlers map netstack TCP endpoints → relay `Dialer`; UDP endpoints → UDP associations; MSS advertised to Windows flows = min(Wintun MTU − headers, tunnel capability negotiated in the handshake) so PMTU blackholes are impossible by construction.
- Wintun MTU default 1380 (accounts for outer TCP/IP + AEAD + TLMP framing); the phone advertises its max inner payload in the handshake — the PC adapts. No hardcoded sizes; all in config.

### 3.4 Network state management & fail-safe

- **Mutation journal:** every stateful change (routes, DNS, adapter creation, proxy settings) is appended to a journal under ProgramData *before* being applied. Sources of rollback: graceful stop, service control handler, next-start reconciliation (crash recovery), optional boot-time scheduled task for hard-crash leftovers.
- **Kill-switch (fail-closed) is the default:** if the phone link drops, traffic continues into Wintun and dies there — it does **not** fall back to the physical NIC. Rationale: fail-open would leak raw Windows TTL=128 traffic across the carrier — the exact fingerprint we exist to prevent. Fail-open is a config option, off by default, with a loud UI warning.
- **System proxy mode** (optional alternative to TUN mode): set WinINET proxy to our local HTTP listener; same journal/rollback guarantees. Default off; TUN mode is primary.
- Crash-fuzz tests in CI: kill -9 the daemon mid-connection, restart, assert journal reconciliation returns the system to baseline.

---

## 4. PHASE 4 — Dependency-Linked Roadmap

| Step | Name | Depends on | Deliverables | Exit criteria (Definition of Done) |
|---|---|---|---|---|
| 0 | Repo bootstrap | — | Monorepo skeleton, CI, license, CONTRIBUTING/DCO, docs incl. this spec, protocol/config schemas | CI green on skeleton; docs reviewed |
| 1 | Core IPC & encrypted handshake | 0 | Protocol spec freeze (`/protocol`): TLMP + Noise; golden vectors; Go + Kotlin implementations; loopback **interop CI harness** | PC CLI ↔ Android module complete handshake + echo over loopback; AEAD/mux throughput benchmark report |
| 2 | Android packet interception & TTL manipulation + relay | 1 | `:core:proto/tunnel/relay/transport(adb)/service`; TUN parser w/ TTL/HL rewrite vs pcap fixtures; foreground service; upstream pinning + loop guard | `adb forward` transport live; external harness fetches HTTP through the phone; TTL-rewrite unit tests green; service survives task removal |
| 3 | Go Wintun virtual interface & route management | 1 | `internal/adapter/sysroute/netstack/failsafe`; route overlay strategy; `IP_UNICAST_IF` pinning; kill-switch; journal + crash-recovery tests | PC-wide traffic flows e2e through phone; kill -9 → restart reconciles cleanly; DNS/IPv6 leak checks pass locally |
| 4 | DPI / SNI obfuscation & DNS activation | 3 | DoH modes, physical-DNS rewrite, HeaderSanitizer, padding/pacing profiles, MSS clamp negotiation, UDP relay hardening, WFD transport (experimental) | Leak-test scripts (`scripts/e2e`) pass; Wireshark audit document; UDP (QUIC/DNS/game) flows verified |
| 5 | Native UI integration & system E2E | 2,3,4 | Compose app completion, QR/SAS pairing UX, Fyne tray + service split, transport auto-switch, packaging (installer w/ wintun.dll, APK signing), benchmark matrix | E2E matrix green on reference hardware; rollback/kill-switch UX verified; v1.0 tagged |

Each step lands as a reviewable increment with its own milestone; no step depends on unfinished behavior of a later step.

---

## 5. Repository Directory Structure

```
toppa/
├── .github/
│   ├── workflows/            # desktop.yml, android-proto.yml, protocol-interop.yml, release.yml
│   ├── ISSUE_TEMPLATE/ · CODEOWNERS · pull_request_template.md
├── android/                  # Gradle multi-module Kotlin project
│   ├── app/
│   ├── core/
│   │   ├── proto/            # TLMP codec + Noise wrapper (pure JVM — CI interop)
│   │   ├── tunnel/ · relay/ · transport/ · vpn/ · service/ · config/ · common/
│   ├── feature/
│   │   ├── pairing/ · dashboard/ · settings/ · logs/
│   ├── gradle/libs.versions.toml
│   └── build.gradle.kts · settings.gradle.kts
├── desktop/                  # Go module (go.mod at this root)
│   ├── cmd/
│   │   ├── toppasvc/ · toppa/ · toppactl/
│   ├── internal/
│   │   ├── adapter/ · sysroute/ · netstack/ · relay/ · resolver/
│   │   ├── mux/ · keys/ · tunnel/ · transport/{adb,wlan,wfd,loopback}/
│   │   ├── obfuscation/ · failsafe/ · config/ · api/
│   ├── ui/fyne/
│   └── Makefile
├── protocol/
│   ├── SPEC.md               # TLMP + handshake normative spec
│   ├── vectors/              # golden vectors (handshake, framing, checksum fixtures)
│   └── schemas/config.schema.json   # single source of truth for both platforms
├── configs/                  # defaults.json, profiles (light/paranoid), examples
├── docs/
│   ├── ARCHITECTURE.md · PROTOCOL.md · THREAT-MODEL.md · LEGAL.md
│   ├── transports/{usb,wifi-hotspot,wifi-direct}.md
│   └── contrib/…             # PR guides per extension point
├── scripts/                  # e2e leak tests, pcap audit helpers, dev bootstrap
├── CONTRIBUTING.md · SECURITY.md · README.md · LICENSE · PROGRESS.MD
```

**Extension points for open-source contributors** (each is an interface + config registration — new PR categories map 1:1 to these): `Transport`/`TransportServer` implementations, `PacketEngine` stacks, obfuscation profiles, DNS resolver providers, UI themes.

---

## 6. Cross-Cutting Standards

- **Configuration (no hardcoded values):** single JSON Schema consumed by both platforms; JSON today (YAML adapter later) on desktop, DataStore+validation on Android; defaults shipped in `configs/defaults.json`, overridable per-profile and by env vars on desktop. Key surface: `tunnel.mtu=1380`, `tunnel.keepalive_secs=15`, `tunnel.handshake_timeout_ms=5000`, `transport.priority=[usb,hotspot,wfd]`, `relay.max_streams`, `relay.buffer_kb`, `dns.mode=phone_doh`, `dns.doh_servers[]`+`dns.bootstrap_ips[]`, `log.level`.
- **Clean architecture:** UI layers (Compose, Fyne) depend only on control-plane APIs; core networking has zero UI imports; OS specifics confined to `adapter`/`sysroute`/`transport`/`vpn` packages behind interfaces; dependency injection on both platforms (Hilt; explicit constructor wiring in Go).
- **Testing strategy:** unit (checksums, framing, TTL rewrite vs pcap fixtures) → golden-vector interop (Go↔Kotlin on CI loopback) → integration (loopback transports, kill -9 recovery) → E2E hardware matrix; fuzzing for the mux/parser.
- **Documentation:** godoc/KDoc expectations in CONTRIBUTING; package READMEs state invariants; ADRs (`docs/adr/`) for decisions like "custom mux over yamux" and "fail-closed default".

## 7. Decision Log

| Decision | Choice | Rationale |
|---|---|---|
| Architecture | L5 relay, not NAT router | Eliminates TTL/OS fingerprint structurally; non-root constraint |
| License | Apache-2.0 | Permissive + patent grant |
| Mux | Custom TLMP + vectors | Cross-language parity and long-term maintenance |
| User-space stack (Step 3) | gVisor netstack | Proven (tun2socks v2/sing-box class), Go-native; behind interface |
| Default transport | USB (adb forward) | Zero carrier artifacts, best battery, most reliable |
| Routing (Step 3) | Overlay + fail-closed kill-switch | Instant rollback; fail-open leaks the exact fingerprint we hide |
| Tunnel scope v1 | IPv4-only + ::/0 blackhole | Contain scope; native v6 is v2 |
| Handshake | Noise_XX + payload-carried statics + SAS | No trusted third party; MITM-safe pairing via visual SAS; pinning enables IK-style resume |
| min SDK / Go | 26 / 1.27 | FGS types, WifiLock latency modes / current toolchain |
| Distribution | GitHub Releases + F-Droid primary | Battery-exemption UX restricted on Play |
