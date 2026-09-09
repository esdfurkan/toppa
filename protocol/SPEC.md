# Toppa Wire Protocol Specification v1

Status: **normative** for Step 1. Both implementations (Go `desktop/internal/{tunnel,mux}`,
Kotlin `android/core/proto`) must satisfy this document and the golden vectors in
`protocol/vectors/`. Changes require an ADR and a spec version bump.

## 1. Layering

```
transport (any ordered, reliable byte stream: TCP over USB/SoftAP/WFD)
  └── handshake framing (this section, handshake only)
        └── Noise_XX handshake
  └── record layer (post-handshake): AEAD framing
        └── TLMP v1 frames (multiplexing, flow control, control channel)
              └── channels: relay streams (TCP/UDP targets), session control
```

## 2. Handshake

### 2.1 Cipher suite and pattern

- Noise **XX** pattern, Curve25519, ChaChaPoly, SHA256
  (`noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly)` semantics).
- Roles: the device that *opened the transport connection* is the Noise **initiator**
  (`pc → phone`: PC initiates; loopback tests: role is explicit).

### 2.2 Handshake framing

Handshake messages use a 2-byte big-endian length prefix, then the Noise message bytes.
Maximum handshake message size: 65535 bytes. No padding.

### 2.3 Payload rules (key continuity without extra API surface)

| Message | Noise operations | Payload |
|---|---|---|
| 1 (`→`) | `e` | empty |
| 2 (`←`) | `e, ee, s, es` | initiator-bound: responder static public key (32 bytes, raw) |
| 3 (`→`) | `s, se` | responder-bound: initiator static public key (32 bytes, raw) |

Payloads are encrypted by the Noise handshake state machine. Each side compares the
received payload with its **pinned peer key** when one exists; any mismatch aborts the
connection (`ErrPeerMismatch`). When no pin exists (first pairing), the payload is stored
after the user confirms the SAS (TOFU with visual verification).

### 2.4 Short Authentication String (SAS)

```
sas = zero-padded(6, big_endian_u32(SHA-256("toppa-sas-v1" || handshake_hash)[0:4]) mod 1_000_000)
```

`handshake_hash` is the Noise handshake hash after message 3. Both ends MUST display the
SAS during first pairing; a mismatch indicates a man-in-the-middle.

### 2.5 Post-handshake keying

The two `CipherState`s returned by the final handshake message are used directly:

- `cs0` encrypts **initiator → responder**, `cs1` encrypts **responder → initiator**.
- Nonces follow the standard Noise construction: 12-byte nonce = 4 zero bytes ‖ 64-bit
  little-endian counter, one counter per direction, starting at 0 and incremented by 1 per
  record. Implementations delegate this to the Noise library's CipherState (which owns the
  per-direction counter); counters never reset or repeat within a session.

## 3. Record layer (post-handshake framing)

```
record = length(u24 BE) || ChaCha20-Poly1305(key_dir, nonce_dir, plaintext)
```

- `length` counts ciphertext bytes (plaintext + 16-byte AEAD tag).
- Maximum plaintext per record: configuration `tunnel.max_frame_payload` rounded up to a
  negotiated value in the handshake channel (v1: static default 262144; MUST be ≥ the
  TLMP max frame payload).
- A record may carry a partial TLMP frame; framing is a stream, not a datagram layer.

## 4. TLMP v1 (Toppa Link Multiplexing Protocol)

### 4.1 Frame header (10 bytes, big-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `version` — MUST be 1 |
| 1 | 1 | `flags` — bitmask, see below |
| 2 | 4 | `stream_id` |
| 6 | 4 | `length` — payload size in bytes, MUST ≤ max frame payload |

### 4.2 Flags

| Bit | Name | Meaning | stream_id | payload |
|---|---|---|---|---|
| 0x01 | `SYN` | open a stream; payload = address block | required | address block |
| 0x02 | `FIN` | sender will send no more data on the stream | required | empty |
| 0x04 | `RST` | abort the stream | required | 1 byte reason |
| 0x08 | `WIN` | WINDOW_UPDATE: extend peer's send window | required | 4-byte BE credit |
| 0x10 | `DATA` | stream payload | required | data |
| 0x20 | `PING` | keepalive probe | MUST be 0 | opaque (echoed verbatim) |
| 0x40 | `PONG` | keepalive reply | MUST be 0 | PING payload |
| 0x80 | `GOAWAY` | session teardown | MUST be 0 | 1 byte reason |

Validation rules: version mismatch → fatal. Oversized frames → fatal. Control frames with
nonzero `stream_id`, `WIN` payload ≠ 4 bytes, `RST`/`GOAWAY` payload ≠ 1 byte → fatal.
Fatal violations: send `GOAWAY(reason=1)` and close the transport.

### 4.3 Stream ids

Initiator allocates odd ids (1, 3, …), responder even (2, 4, …). Duplicate inbound `SYN`
for a live id → `RST(reason=2)`.

### 4.4 Address block (`SYN` payload)

```
network : u8   (1 = TCP, 2 = UDP)
atyp    : u8   (1 = IPv4, 3 = FQDN, 4 = IPv6)
address : atyp-dependent:
            IPv4  → 4 raw bytes
            IPv6  → 16 raw bytes
            FQDN  → length(u8, ≤255) || bytes (no trailing dot, lowercase recommended)
port    : u16 BE
```

### 4.5 Flow control

- Each stream has a receive window (initial size = configuration, default 256 KiB),
  implicitly granted at `SYN` acceptance.
- Senders MUST NOT have more than the granted window unacknowledged. Receivers return
  credit with `WIN` as the application consumes data.
- Exceeding the granted receive window is a fatal protocol violation.
- `SYN` frames carrying targets are not flow-controlled; `DATA` is.

### 4.6 Lifecycle semantics

- `FIN` half-closes; the receiving side drains buffered data, then observes EOF.
- Both directions FIN → stream is retired (id may not be reused within a session).
- `RST` discards stream state immediately; readers get `ErrStreamReset`, writers fail.
- `GOAWAY(reason)`: 0 = normal, 1 = protocol error, 2 = busy, 3 = shutdown. After sending,
  the session closes the transport.
- Keepalive: sender emits `PING` with an 8-byte nonce every `keepalive_secs` (config);
  receiver echoes `PONG`. If no inbound frame of any kind is observed for
  `ping_timeout` (default 45 s), the session is considered dead and torn down.

## 5. Golden vectors

`protocol/vectors/*.json` (Step 1 exit) will contain: frame encode/decode cases (including
rejection cases), address-block cases, SAS test vectors for fixed handshake hashes. Both
implementations must consume the same files.

## 6. Out of scope for v1 (explicit non-goals)

- Stream-level compression, encryption variants, padding (Step 4 adds padding profiles as
  optional *record-layer* transforms that must not alter this spec's frame semantics).
- Congestion control inside TLMP (the transport's TCP provides it).
- Zero-RTT resume (Noise IK pattern upgrade is a v2 candidate).
