# Raven Benchmarks

This report covers Raven's curated, server-oriented benchmark suite. It measures
single-stream library work using in-memory readers, writers, and DNS resolvers;
it does not measure network, filesystem, TLS, or external DNS latency.

## Reference environment

- Date: 2026-07-20
- CPU: Intel Core Ultra 9 185H
- OS: Linux 7.1.2-1-default, amd64
- Go: go1.26.4
- Execution: one benchmark package at a time and one logical CPU per benchmark

Five samples were collected for each benchmark. The tables report the median
sample; an additional seven-sample run was used for DKIM verification after its
original samples were interrupted by host scheduling.

```sh
go test -p=1 ./client ./server ./mail ./dkim ./arc ./spf ./dmarc \
  -run '^$' -bench '^BenchmarkDisplay' -benchmem \
  -benchtime=2s -count=5 -cpu=1
```

## Headline results

| Workload | Time/op | Throughput | B/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| SMTP DATA receive, 1 MiB | 204,962 ns | 5,116 MB/s | 4,352 | 4 |
| SMTP DATA send, 1 MiB | 986,628 ns | 1,063 MB/s | 0 | 0 |
| SMTP BDAT receive, 1 MiB / 64 KiB chunks | 90,557 ns | 11,579 MB/s | 48,449 | 148 |
| SMTP BDAT send, 1 MiB / 64 KiB chunks | 22,863 ns | 45,862 MB/s | 4,176 | 167 |
| Streaming MIME walk, 1 MiB | 159,454 ns | 6,576 MB/s | 8,008 | 48 |
| DKIM RSA-2048 `SignReader`, 1 MiB | 2,153,837 ns | 487 MB/s | 18,033 | 168 |
| DKIM RSA-2048 `VerifyReader`, 1 MiB | 1,862,156 ns | 563 MB/s | 3,169,775 | 214 |
| ARC RSA-2048 `SealReader`, 1 MiB | 3,138,031 ns | 334 MB/s | 28,472 | 227 |
| ARC RSA-2048 `VerifyReader`, 1 MiB | 1,655,230 ns | 634 MB/s | 42,944 | 277 |
| SPF pass with include | 3,727 ns | — | 2,928 | 67 |
| DMARC aligned pass | 1,610 ns | — | 864 | 15 |

The very high BDAT throughput reflects an in-memory protocol peer and should be
read as encoding/parsing overhead, not achievable network throughput.

## Large-message scaling

| Workload | Size | Time/op | Throughput | B/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| SMTP DATA send | 1 MiB | 986,628 ns | 1,063 MB/s | 0 | 0 |
| SMTP DATA send | 16 MiB | 16,206,489 ns | 1,035 MB/s | 559 | 0 |
| SMTP DATA receive | 1 MiB | 204,962 ns | 5,116 MB/s | 4,352 | 4 |
| SMTP DATA receive | 16 MiB | 4,475,065 ns | 3,749 MB/s | 4,368 | 4 |
| Streaming MIME walk | 1 MiB | 159,454 ns | 6,576 MB/s | 8,008 | 48 |
| Streaming MIME walk | 16 MiB | 2,658,418 ns | 6,311 MB/s | 8,017 | 48 |
| DKIM relaxed body hash | 1 MiB | 1,382,201 ns | 759 MB/s | 4,402 | 6 |
| DKIM relaxed body hash | 16 MiB | 23,060,794 ns | 728 MB/s | 4,402 | 6 |
| ARC relaxed body hash | 1 MiB | 1,562,383 ns | 671 MB/s | 4,402 | 6 |
| ARC relaxed body hash | 16 MiB | 25,831,111 ns | 650 MB/s | 4,402 | 6 |

The small non-zero byte counts reported with zero allocations for pooled DATA
send buffers are amortized `sync.Pool` replenishment; allocation counts are
rounded by Go's benchmark reporter. DATA receive, MIME traversal, and DKIM/ARC
body hashing retain constant allocation counts as message size grows.

## Workloads and interpretation

- DATA uses legal short SMTP lines and includes dot-prefixed content. Receive
  benchmarks validate and unstuff the wire representation; send benchmarks
  perform streaming dot stuffing.
- BDAT processes a complete RFC 5322 message in 64 KiB chunks. Per-chunk command
  formatting and response parsing are included, so allocations scale with the
  number of chunks rather than individual message lines.
- MIME walks a deterministic multipart message with text and attachment parts,
  draining leaf bodies without constructing an eager MIME tree.
- DKIM and ARC use the public seekable-reader APIs with RSA-2048, relaxed body
  canonicalization, fixed message content, in-memory DNS records, and setup keys
  generated outside the timed region.
- SPF follows an `include` to a passing `ip4` mechanism. DMARC evaluates aligned
  SPF and DKIM pass results. Both use in-memory resolvers.

Existing parser, generated MessagePack, and deprecated eager compatibility
benchmarks remain useful for maintainers but are intentionally excluded from
the displayed suite.

## Parallel scaling

The parallel suite gives each worker its own reader and connection-style state,
while immutable messages, verification keys, and in-memory DNS records are
shared. `testing.B.RunParallel` keeps one worker active per `GOMAXPROCS` slot.

```sh
go test -p=1 ./client ./server ./mail ./dkim ./arc \
  -run '^$' -bench '^BenchmarkScale' -benchmem \
  -benchtime=1s -count=3 -cpu=1,2,4,8,16,22
```

The table reports median aggregate throughput. Scheduler-disturbed server
16/22-worker and ARC 22-worker samples were repeated seven times in isolation.

| Workers | DATA receive | DATA send | MIME walk | DKIM verify | ARC verify |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5.97 GB/s | 1.10 GB/s | 6.55 GB/s | 572 MB/s | 617 MB/s |
| 2 | 11.5 GB/s | 2.17 GB/s | 12.8 GB/s | 1.05 GB/s | 1.27 GB/s |
| 4 | 21.3 GB/s | 4.09 GB/s | 23.9 GB/s | 1.73 GB/s | 2.43 GB/s |
| 8 | 34.1 GB/s | 6.65 GB/s | 39.6 GB/s | 2.68 GB/s | 4.12 GB/s |
| 16 | 49.5 GB/s | 9.22 GB/s | 50.3 GB/s | 3.86 GB/s | 5.36 GB/s |
| 22 | 47.0 GB/s | 8.69 GB/s | 44.2 GB/s | 4.31 GB/s | 5.42 GB/s |

Relative to one worker, peak aggregate scaling was approximately 8.3x for DATA
receive, 8.4x for DATA send, 7.7x for MIME traversal, 7.5x for DKIM verification,
and 8.8x for ARC verification. The decline from 16 to 22 workers in transport
and MIME is consistent with saturation on this heterogeneous CPU and shared
memory bandwidth rather than a Raven-wide lock: DKIM and ARC still improve at
22 workers, and per-operation allocation counts remain unchanged.

These results support parallel connection handling at the protocol layer, but
they do not include TCP, TLS, disk-backed spooling, external DNS, backend queue
contention, or idle/slow-client resource usage. DKIM verification remains the
notable memory-pressure path at about 3.17 MiB allocated per 1 MiB message; its
22-worker run reached 4.31 GB/s while retaining 213 allocations per operation.
