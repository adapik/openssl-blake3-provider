# Changelog

## 0.1.0 (unreleased)

First version: digest (`BLAKE3`, XOF, squeeze, dup), MAC (`KEYED-BLAKE3`), KDF (`BLAKE3-KDF`).

* Vendored upstream BLAKE3 C **1.8.7** (tag `1.8.7`, commit `f3149ec5bb5449af877ba20377a11008ff499fa2`).
* Spec reference: C2SP `BLAKE3.md` at commit `625d8db08a0f196540e40f0a2256332275492f78`; official `test_vectors.json` from the same upstream tag.
* OpenSSL used for development/testing: **3.5.9** and **4.0.3** (both built from the official tarballs).

### What was verified (all on Linux x86_64, AMD Ryzen 5 7500F, gcc; see "Known limitations" for what was not)

* One module binary, compiled against the 3.5.9 headers, loads and passes the full suite under OpenSSL 3.5.9 **and** 4.0.3
  (`ctest`: 35 tests per OpenSSL version; the four NEON ones are skipped on x86).
* Backends exercised on this machine: portable, SSE2, SSE4.1, AVX2, AVX-512 (via `BLAKE3_PROV_FORCE_IMPL`), intrinsics and `.S` builds. The `.S` build is the default on Linux/BSD x86_64 (measurably faster, see bench).
  NEON: **not exercised** (no aarch64 hardware or emulator available here).
* Spec appendix traces (all 7 round states of hash("IETF"), all 32 chunk blocks and the parent of the keyed example), 35 official vectors
  (digest one-shot/incremental/FinalXOF/squeeze 1+7+64+59, MAC, KDF), ~400k boundary/split/dup/XOF/error checks against an independent in-tree reference.
* Cross-implementation: 10,000 seeded random cases (length 0..256 KiB, all three modes, random key/context/output length 1..1000) against
  `b3sum` 1.8.7, python `blake3` 1.0.10, upstream Rust `reference_impl`, Go `lukechampine.com/blake3` v1.4.1: 0 mismatches. 500 of them
  against the pure-Python oracle written from the C2SP pseudocode: 0 mismatches. 300 more through the `openssl` CLI: 0 mismatches.
* 4 GiB + 4097 byte stream through `openssl dgst` equals `b3sum`. (The chunk counter's high 32-bit word is only reached after 4 TiB; that path was not exercised.)
* ASan + UBSan + LSan clean on the whole suite; TSan clean on the 16-thread test (run with ASLR off: `setarch -R`).
* Mutation check: a deliberately broken provider (squeeze offset not advanced) is caught by the vector, incremental and fuzz tests.
* Compile-only check (zig cc 0.16, not run, not linked) of the provider and vendored sources for aarch64-linux-gnu (incl. NEON), aarch64-macos,
  x86_64-macos and x86_64-windows-gnu: compiles without errors or warnings in `-Wall`. This is *not* a test of behaviour on those targets.
* Benchmarks (`bench/RESULTS.md`, release OpenSSL 3.5.9): 0 of 80 cells >= 16 KiB are below 95% of the stock upstream C library on the same backend;
  64 KiB AVX2 is 2.5x SHA-256 with SHA-NI (asm) / 1.6x (intrinsics). EVP per-call overhead at 64 B is lower than SHA-256's (7-10 ns vs 18-20 ns);
  at 256 B-1 KiB it is roughly equal, up to ~3-6 ns higher in some cells (e.g. 22 vs 19 ns at 1 KiB), i.e. the "no worse than SHA-256" target is met at 64 B
  and only approximately at 1 KiB.
* Module has no libcrypto/libssl dependency (`ldd`), exports only `OSSL_provider_init` (`nm -D`), non-executable stack.

### Behaviour worth knowing

* `module = blake3` in `openssl.cnf` does **not** load the module (verified, OpenSSL 3.5.9); omit `module` or give a full path with extension.
  The example config does this.
* `EVP_DigestFinal_ex` writes `xoflen` bytes regardless of the output size OpenSSL passes in (as SHAKE does).
* The digest does not register `GETTABLE_CTX_PARAMS` (performance, see README "Deliberate design choices"). `SERIALIZE/DESERIALIZE` not implemented (3.5 headers).
* KDF requires both `key` (may be empty) and `info` to be set explicitly.

### Known limitations

* **Not run here, so unverified**: macOS (arm64, x86_64), Windows/MSVC (including `/analyze`), Linux aarch64 (NEON), big-endian (s390x/ppc64),
  Valgrind (not installable in the authoring environment; ASan/LSan used instead), real libFuzzer runs (no clang available here; the same target was
  run with its built-in random driver: 113k-140k random programs in 15 s per backend, 0 mismatches; wired for libFuzzer in CI), Intel SDE.
  The GitHub Actions workflow (`.github/workflows/ci.yml`) covers all of these but **has never been executed**; expect to fix typos on first run.
* On Windows/MSVC and macOS the build uses compiler intrinsics (upstream's MASM files cannot be symbol-prefixed). Their throughput has not been measured.
* A 4 KiB-chunked `update` pattern is much slower than one large `update` (upstream behaviour, same ratio to upstream): it cannot fill the SIMD lanes. Feed big buffers.
* No multithreaded hashing (by design).
