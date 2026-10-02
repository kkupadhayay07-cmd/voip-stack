# fuzz

cargo-fuzz targets for the VoIP stack's wire-format parsers. These run under
**libFuzzer on nightly**; on stable CI the equivalent deterministic corpus
lives in each crate's `tests/fuzz_smoke.rs` (see below).

## Targets

| Target                | API under test                             | Property                          |
|-----------------------|--------------------------------------------|-----------------------------------|
| `parse_sip_message`   | `sip_core::parse_message` / `parse_stream` | returns `Result`, never panics    |
| `parse_sdp`           | `sdp::parse`                               | returns `Result`, never panics    |
| `parse_rtp`           | `rtp::RtpPacket::parse`                    | returns `Result`, never panics    |
| `parse_dtmf`          | `rtp::dtmf::parse_event`                   | returns `Result`, never panics    |
| `parse_sctp_packet`   | `sctp::wire::parse_packet`                 | returns `Result`, never panics    |
| `parse_dcep`          | `sctp::dcep::parse`                        | returns `Result`, never panics    |
| `parse_dns_response`  | `rfc3263::wire::parse_response`            | returns `Result`, never panics    |

All parser crates are `#![forbid(unsafe_code)]` (sip-core, sdp) or keep their
`unsafe` confined to codec FFI outside the parse path (rtp), so the fuzz
property reduces to "no panic".

## Running (nightly required)

```sh
cd fuzz
cargo +nightly fuzz run parse_sip_message
cargo +nightly fuzz run parse_sdp
cargo +nightly fuzz run parse_rtp
cargo +nightly fuzz run parse_dtmf
cargo +nightly fuzz run parse_sctp_packet
cargo +nightly fuzz run parse_dcep
cargo +nightly fuzz run parse_dns_response
```

Useful flags:

* `-max_len=65536` — SIP messages are capped at 64 KiB (`MAX_MESSAGE`).
* `-max_total_time=60` — quick local session.
* Corpus artifacts land in `fuzz/corpus/<target>/`, crashes in
  `fuzz/artifacts/<target>/`. Commit interesting crashers to the
  `tests/fuzz_smoke.rs` corpora in the corresponding crate so they run on
  stable CI too.

## Stable smoke corpus (CI)

The same public parser APIs are exercised on every PR by handcrafted
malformed-input corpora (truncated headers, overflow lengths, invalid UTF-8,
zero-length payloads, huge declared counts, version-byte fuzz):

```sh
cargo test -p sip-core --test fuzz_smoke
cargo test -p sdp     --test fuzz_smoke
cargo test -p rtp     --test fuzz_smoke
```

## Layout notes

`fuzz/Cargo.toml` is its own workspace root (empty `[workspace]` table) — the
cargo-fuzz convention. It is **not** a member of the repository workspace, so
`cargo test --workspace` / `cargo clippy --workspace` at the repo root are
never affected by libfuzzer or nightly-only deps.
