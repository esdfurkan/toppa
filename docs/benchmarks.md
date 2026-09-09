# Benchmarks

Step 1 exit criterion includes an AEAD/multiplexer throughput report. The
benchmark code is committed; results are filled in by actually running it
(desktop-class and phone-class hardware both matter — record both).

## Commands

```bash
cd desktop

# Multiplexer: TLMP framing + window-credit flow control over an in-memory pipe
go test ./internal/mux -bench BenchmarkStreamRoundTrip -benchmem -count=5

# Tunnel: Noise_XX handshake cost (per new connection)
go test ./internal/tunnel -bench BenchmarkHandshake -benchmem -count=5

# Tunnel: ChaCha20-Poly1305 record layer throughput (64 KiB records)
go test ./internal/tunnel -bench BenchmarkSecureThroughput -benchmem -count=5
```

`-count=5` + `benchstat` (optional) gives stable numbers; a single run is
enough for a quick sanity check.

## Results

| Machine | Date | Benchmark | ops/s | MiB/s | B/op | allocs/op |
|---|---|---|---|---|---|---|
| _(pending first run)_ | | `BenchmarkStreamRoundTrip` | | | | |
| _(pending first run)_ | | `BenchmarkHandshake` | | | | |
| _(pending first run)_ | | `BenchmarkSecureThroughput` | | | | |

## Reading the numbers

- **SecureThroughput** bounds the tunnel's usable bandwidth; it must stay well
  above the weakest transport (USB 2.0 ADB ≈ 25–40 MB/s effective) so the
  tunnel is never the bottleneck.
- **Handshake** cost is paid once per connection; anything under ~10 ms is
  invisible behind transport latency.
- **StreamRoundTrip** minus SecureThroughput ≈ multiplexer overhead; a large
  gap points at flow-control stalls (window sizing in `configs/defaults.json`).
