# Golden Vectors

Shared test vectors consumed by **both** implementations:

| File | Covers | Consumers |
|---|---|---|
| `frames.json` | TLMP v1 frame encode/decode + all structural rejection rules (SPEC §4) | `desktop/internal/mux/vectors_test.go`, `android :core:proto TlmpVectorsTest.kt` |
| `targets.json` | Address-block encode/decode + rejections (SPEC §4.4) | same two tests |
| `sas.json` | Short Authentication String derivation (SPEC §2.4) | `desktop/internal/tunnel/sas_test.go`, `android :core:proto SasTest.kt` |

Rules:

1. Vectors are **normative**: if an implementation disagrees with a vector, the
   implementation (or the spec, via ADR) is wrong.
2. Adding wire features requires adding vectors in the same PR.
3. `desktop/cmd/vectorgen` regenerates all three files after a spec change
   (`cd desktop && go run ./cmd/vectorgen -out ../protocol/vectors`). The SAS
   values are computed from the domain constant + fixed handshake hashes and
   are the source of truth; frame/target cases are derived from the mux types.
4. Tests skip gracefully when the vectors directory is absent (standalone
   module checkouts), but CI always runs from a full checkout.

Cross-language **live** interop (real Noise_XX handshake + TLMP echo between
the Go and Kotlin implementations) is covered by
`.github/workflows/protocol-interop.yml` — vectors validate the codecs, the
interop job validates the cryptography.
