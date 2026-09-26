# Security Notes

Status: `cargo audit` exit 0 — **no vulnerabilities** (RUSTSEC advisories with
severity `vulnerable`) in the dependency graph as of this writing. One
**unmaintained-crate warning** remains, documented below.

Scanned: 124 locked dependencies (Cargo.lock), advisory database 1271 advisories.
Reproduce with:

```
cargo install cargo-audit --locked
cargo audit
```

---

## RUSTSEC-2026-0150 — `audiopus_sys` is unmaintained

| Field        | Value |
|--------------|-------|
| Crate        | `audiopus_sys` 0.2.2 |
| Severity     | **Unmaintained** (informational; not a vulnerability) |
| ID / URL     | [RUSTSEC-2026-0150](https://rustsec.org/advisories/RUSTSEC-2026-0150) |
| Dependency path | `b2bua → codecs → opus 0.3.1 → audiopus_sys 0.2.2` |
| Remediation attempted | `cargo update` — no-op (0 packages re-locked); 0.2.2 is the newest published release, so no compatible update exists |

### What the crate is

`audiopus_sys` is the `-sys` binding layer used by our `opus = "0.3"` wrapper.
It links the **system** libopus (`pkg-config`, verified 1.5.2) and exposes the
C API to Rust. Our code never touches `audiopus_sys` directly — all Opus use
goes through the safe `opus` crate wrapper (`crates/codecs/src/opus.rs`).

### Is it exploitable here?

No known exploit path. Specifically:

1. **Unmaintained ≠ vulnerable.** No CVE is attached to this advisory. The
   risk model is "future bugs in the binding crate will not be patched
   upstream," not "known bug present today."
2. **Attack surface is minimal.** The crate is a thin `extern "C"` declaration
   layer. All audio processing happens inside the system libopus (a separate,
   actively maintained C project); the Rust binding code is a few hundred
   lines of declarations with no parsers, allocators, or network I/O of its own.
3. **Untrusted input never reaches unsafe FFI marshalling directly.** Decoder
   input sizes are framed by our RTP payload handling (fixed samples-per-frame
   per codec), and malformed packets are rejected by the `rtp` parser before
   `decode_frame` is invoked.
4. **Build-time failure mode, not runtime.** If libopus ever changes ABI in an
   incompatible way, the result is a link/build error, not a silent
   vulnerability.

### Planned remediation (Phase 2+, requires a dependency decision)

Options, in order of preference — all require either a major version change of
`opus` (blocked by the current "no dependency major-version changes" rule) or a
workspace-internal replacement, so they are deferred to a planned release:

1. **Vendor our own `libopus-sys`** inside the workspace (a ~100-line `-sys`
   crate against the same pkg-config system libopus), dropping `opus` +
   `audiopus_sys` entirely. Lowest long-term risk; small, auditable surface.
2. **Switch to a maintained binding** (`audiopus` 1.x/2.x or an actively
   maintained `opus-sys` fork) — a major dependency change, to be scheduled
   with the usual review.
3. **Track upstream**: re-run `cargo audit` in CI (already wired in
   `.github/workflows/ci.yml`, job `audit`); if the advisory is withdrawn or a
   successor crate adopted by the `opus` wrapper appears, revisit.

Until one of these lands, the finding is **accepted risk** for Phase 1:
documented, monitored by CI, with no known vulnerability behind it.
