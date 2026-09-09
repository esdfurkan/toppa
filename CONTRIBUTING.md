# Contributing to Toppa

Thanks for helping build Toppa. The codebase is structured so that most contributions are
additive: implement an interface, register it in config, open a PR.

## Ground rules

1. **No operational hardcoding.** Ports, buffer sizes, keepalive intervals, MTUs, feature
   toggles live in `internal/config` (Go) / `core:config` (Kotlin) with defaults mirrored in
   `configs/defaults.json` and validated by `protocol/schemas/config.schema.json`.
2. **Tests for behavior changes.** `go test -race ./...` must pass; pure-JVM protocol code
   must stay Android-independent so it can run in CI interop tests.
3. **Document invariants.** Every package's doc comment states what it owns and what must
   not leak across boundaries (UI ⇄ core ⇄ OS drivers).
4. **No crypto redesigns without an ADR.** Changes to the handshake/record layer require
   `docs/adr/NNN-*.md` rationale and golden-vector updates in `protocol/vectors/`.
5. Apache-2.0 licensing; sign off commits (`git commit -s`) for DCO traceability.

## Extension points (what to PR)

| You want to add | Implement | Register via |
|---|---|---|
| A link transport (BLE, QUIC, …) | `internal/transport.Transport` (Go) / `TransportServer` (Kotlin) | `transport.priority` config list |
| A user-space packet engine | `internal/netstack.PacketEngine` (Go) | `netstack.engine` config key (Step 3) |
| An obfuscation profile | `internal/obfuscation.Profile` | `obfuscation.profile` config key (Step 4) |
| A DNS resolver provider | `internal/resolver.Provider` | `dns.*` config keys (Step 4) |
| UI themes / dashboards | platform UI layer only — no core imports | — |

## Development setup

- **Desktop:** Go 1.27+ (`winget install GoLang.Go` or https://go.dev/dl/).
  `cd desktop && go build ./... && go test -race ./...`
- **Android:** JDK 21, Gradle (wrapper landing with the first Android milestone),
  Android Studio for `:app` work. `:core:proto` is pure JVM and builds without the SDK.

## Review checklist (maintainers)

- Config-driven? Schema updated? Defaults mirrored in `configs/defaults.json`?
- Failure paths: does cleanup/rollback survive `kill -9` (desktop) / process death (Android)?
- No new third-party dependency without justification in the PR description.
