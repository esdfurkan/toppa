# Toppa

Cross-platform, open-source tether-obfuscation suite: an **Android (Kotlin)** client and a
**Windows (Go)** desktop client that cooperate so that all PC traffic egresses the phone as
ordinary, phone-originated traffic — defeating TTL/OS fingerprint tethering detection and
tethering-specific data caps.

**Status: pre-alpha — Step 1 of 5 (core IPC & encrypted handshake).**
Live status: [PROGRESS.MD](PROGRESS.MD) · Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
Protocol: [protocol/SPEC.md](protocol/SPEC.md)

## How it works, in one paragraph

A carrier can only fingerprint what crosses the cellular interface. Toppa therefore never
forwards IP packets from the PC across the phone's radio. The Windows client captures system
traffic at L3 with a Wintun adapter, converts it to L5 flows in a user-space TCP/IP stack
(gVisor netstack), and relays every flow through an encrypted, multiplexed tunnel
(Noise_XX/IK + ChaCha20-Poly1305 + custom TLMP framing) to the Android client, which
re-originates each flow from its own sockets. The PC↔phone link rides USB (`adb forward`),
Wi-Fi SoftAP, or Wi-Fi Direct — none of which the carrier can observe. TTL normalization,
MSS clamping, and DNS-over-HTTPS harden the residual surface.

## Repository layout

| Path | Contents |
|---|---|
| `android/` | Gradle multi-module Kotlin app (`:app`, `:core:*`, `:feature:*`) |
| `desktop/` | Go module: service daemon, CLI, (later) Fyne UI, Wintun adapter, netstack |
| `protocol/` | Normative wire spec, golden vectors, shared JSON config schema |
| `configs/` | Default configuration files mirroring code defaults |
| `docs/` | Architecture, threat model, transport guides, ADRs |

## Building & testing (desktop, current scope)

Requires Go 1.27+.

```bash
cd desktop
go build ./...
go test -race ./...
```

Step-1 loopback smoke test (two terminals):

```bash
cd desktop
go run ./cmd/toppactl serve -listen 127.0.0.1:47471   # terminal 1 (responder + echo)
go run ./cmd/toppactl ping  -addr 127.0.0.1:47471     # terminal 2 (initiator)
```

Both consoles print a 6-digit SAS — confirm they match, then `ping` measures encrypted
round-trips over the multiplexer. Keys land in `~/.toppa/desktop/` (pinning is TOFU after
visual SAS confirmation).

## Legal & responsible use

Toppa operates only between devices you own. Using it may violate your carrier's terms of
service; you are responsible for compliance with your contracts and local law. This project
is published for education and research. Detection is *reduced, not eliminated* — the threat
model (`docs/THREAT-MODEL.md`, in progress) enumerates residual signals honestly.

## License

Apache-2.0 — see [LICENSE](LICENSE).
