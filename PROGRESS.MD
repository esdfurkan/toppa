# PROGRESS

Toppa — cross-platform tether-obfuscation suite (Android Kotlin + Windows Go).
This file is the living work tracker: update it at the end of every session.

**Last updated:** 2026-09-09 (session 3, final)
**Status:** ALL FIVE ROADMAP STEPS ARE CODE-COMPLETE. Nothing is verified by a
compiler yet (maintainer mandate: code only). First compile/test pass is the
single remaining gate, and expected fallout is tracked below.

---

## Roadmap status

| Step | Name | Status |
|---|---|---|
| 0 | Repo bootstrap | ✅ done |
| 1 | Core IPC & encrypted handshake | 🟡 code complete |
| 2 | Android packet interception, TTL manipulation & relay | 🟡 code complete |
| 3 | Go Wintun virtual interface & route management | 🟡 code complete |
| 4 | DPI / SNI obfuscation & DNS activation | 🟡 code complete |
| 5 | Native UI integration & system E2E | 🟡 code complete (on-device E2E needs hardware) |

The project is **feature-frozen at v0.1 scope** until the verification pass.

---

## What exists, by layer

### Desktop (Go, `desktop/`)

| Package | Contents |
|---|---|
| `internal/mux` | TLMP v1 codec, session/streams (flow control, keepalive, GOAWAY), padding hook (`PingPayload`) |
| `internal/tunnel` | Noise_XX handshake (flynn/noise), AEAD records, SAS, pinning |
| `internal/keys` | identity + pinned peers (JSON, 0600; DPAPI wrapping = packaging TODO) |
| `internal/config` | strict JSON config incl. Step 3/4 sections (`netstack`, `obfuscation`, `api`, `daemon`) |
| `internal/adapter` | TunDevice interface, Wintun session impl, in-memory loopback pair for tests |
| `internal/failsafe` | write-ahead mutation journal; reverse-order rollback; crash-reconcile |
| `internal/sysroute` | RouteManager: overlay 0/0 route, ::/0 blackhole, DNS rewrite incl. physical adapters; netsh configurer behind `NetConfigurer` |
| `internal/relay` | StreamConn (net.Conn over mux), TunnelDialer, HeaderSanitizer (plain-HTTP UA/forwarded rewrite), Pacer |
| `internal/resolver` | tunnel-IP UDP listener (TC→TCP fallback), DoH-through-tunnel upstream |
| `internal/netstack` | gVisor engine: Wintun↔L5, TCP forwarder→dialer, UDP/53 interception, ICMP-local, v6 blackhole; MSS by construction from MTU |
| `internal/transport` | ADB (usb), WLAN (hotspot), Loopback transports |
| `internal/daemon` | full lifecycle: reconcile → connect → online (routes+resolver+padding) → teardown → backoff reconnect; fail-closed kill-switch |
| `internal/obfuscation` | padding profiles (none/light/paranoid) over the PING channel |
| `internal/api` | loopback control API (/status, /reconnect) |
| `cmd/toppasvc` | elevated service entry |
| `cmd/toppactl` | pairing/status CLI |
| `cmd/vectorgen` | golden-vector generator |
| `cmd/toppa` | Fyne dashboard (status + reconnect; fyne dep resolved at packaging) |

### Android (Kotlin, `android/`)

| Module | Contents |
|---|---|
| `:core:proto` | TLMP codec, Noise_XX (JCA), SAS, full mux session port |
| `:core:vpn` | checksums, PacketProcessor (TTL/HL rewrite), UdpDnsReply, VpnPacketLoop, RootNatClamp |
| `:core:relay` | RelayEngine (cellular-pinned sockets), DnsWire, DohResolver (HttpsURLConnection — Android-safe), DnsShield, loop guard |
| `:core:transport` | TransportServer, AdbForwardServer, SoftApServer (runtime AP discovery) |
| `:core:tunnel` | TunnelServer, RelayIdentity, RelayRuntime |
| `:core:service` | RelayForegroundService (dataSync FGS, locks, START_STICKY) — committed, not in settings until SDK |
| `:app` | Compose dashboard, RelayForegroundService wiring, ToppaVpnService (DNS shield), AndroidUpstreamProvider (real cellular pinning), FileIdentity — committed, not in settings until SDK |

### Shared

| Path | Contents |
|---|---|
| `protocol/SPEC.md` | normative TLMP v1 + handshake spec |
| `protocol/vectors/` | frames, targets, sas, packets fixtures + README |
| `protocol/schemas/config.schema.json` | full shared config surface (Steps 3–4 sections included) |
| `configs/defaults.json` | mirror of Go defaults (dns.mode=pc_doh is the wired v1 mode) |
| `docs/` | architecture (L1 semantics corrected), benchmarks (pending numbers) |
| `.github/workflows/` | desktop, android-proto, protocol-interop, release |
| `scripts/` | e2e leak checks (PowerShell), Windows packaging script |

---

## Verification ledger (honest state)

| Area | Compiled/tested? | Notes |
|---|---|---|
| Go non-test code (steps 1–2 scope) | ✅ build+vet PASS (session 1) | pre-Step-3 snapshot |
| Go tests | ⏸ never run | incl. journal, sysroute, sanitizer, wire |
| Go Step 3–5 code (adapter/sysroute/netstack/daemon/…) | ⏸ written only | `go mod tidy` needed (wintun, gvisor, fyne) |
| gVisor link endpoint | ⏸ written only | API drift likely; see note in engine.go — pin + adjust symbols, logic stands |
| Kotlin (steps 1–4 scope) | ⏸ written only | needs Gradle + `gradle :core:*:test` |
| Kotlin :app/:core:service | ⏸ written only | needs Android SDK + AGP |
| Golden vectors | ✅ hex/ASCII validated | SAS values computed via sha256sum |
| Live Go↔Kotlin interop | ⏸ pending | `protocol-interop.yml` ready |
| On-device E2E (adb + cellular) | ⏸ pending | needs :app build + hardware |

## First-compile playbook (the single gate before v0.1)

```bash
# 1. Desktop: resolve deps, then build/test everything
cd desktop && go mod tidy          # network: flynn/noise, wintun, gvisor
go build ./... && go vet ./... && go test ./...

# 2. Fix expected fallout (in likelihood order):
#    - internal/netstack: gVisor symbol renames (LinkEndpoint/WritePackets/PacketBuffer)
#    - daemon/config: minor drift from strict-JSON additions
#    - tests: timing-sensitive pipe tests if any

# 3. Android pure-JVM modules (needs Gradle install)
cd android && gradle :core:proto:test :core:vpn:test :core:relay:test :core:tunnel:test

# 4. Interop (also runs in CI on push)
cd desktop && go run ./cmd/toppactl serve -listen 127.0.0.1:47471
cd android && TOPPA_INTEROP_ADDR=127.0.0.1:47471 gradle :core:proto:test --tests "*Interop*"

# 5. Benchmarks → docs/benchmarks.md
cd desktop && go test ./internal/mux ./internal/tunnel -bench . -benchmem

# 6. Packaging + on-device E2E (hardware)
powershell -File scripts/package/windows.ps1
scripts/e2e/leak-checks.ps1
```

## Design decisions & corrections worth remembering

- **L5 relay, not NAT** — carrier fingerprinting dies structurally (TTL, TCP options, DNS).
- **L1 Shield-mode semantics corrected (s3)** — VpnService TUN is a single pipe;
  rewrite-and-reinject is impossible without a phone netstack. Shield v1 = DNS shield
  (DoH over the TUN) + drop-mode kill switch; the packet engine serves the experimental
  root-forwarded-capture extension. ARCHITECTURE.md §1.1 updated.
- **dns.mode=pc_doh is the wired v1 mode** (DoH through the tunnel; TC→TCP trick via the
  netstack); phone_doh needs the phone-side DoH bridge (documented leftover).
- **Fail-closed kill-switch**: crash leaves routes in place deliberately; reconcile on
  next start undoes them. Fail-open would leak TTL=128 — the fingerprint we exist to hide.
- **UDP beyond DNS is out of v1** (SPEC §6): the datagram channel is a future milestone.
- **Custom TLMP mux + hand-rolled Kotlin Noise**: cross-language parity over dependency
  risk; interop CI is the correctness gate.
- **Placeholders**: module path `github.com/esdfurkan/toppa` (404s until the repo is
  published); `toppa` codename renameable with a one-pass sweep.

## Known leftovers (tracked, non-blocking for v0.1)

- Keystore/StrongBox wrapping of the phone identity; DPAPI wrapping on desktop (packaging).
- Named-pipe + gRPC control API (loopback HTTP shipped first).
- Wi-Fi Direct transport (experimental), QUIC transport (v2), native IPv6 through the
  tunnel (v2), phone-side DoH bridge (`phone_doh` mode), SOCKS "tablet mode" listener.
- installer (Inno Setup) consuming `scripts/package/windows.ps1` output; code signing.
- TransportManager (intra-session transport failover with warm handover) — currently the
  daemon reconnects on the priority list instead.

## Toolchain notes (this machine)

- Go 1.27 installed (`C:\Program Files\Go\bin\go.exe`); JDK 21 present.
- Gradle / Android SDK / adb / fyne deps: not installed — hence the code-only ledger.
