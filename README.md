# OpenSSL BLAKE3 provider

A loadable OpenSSL provider that adds **BLAKE3**: hash, extendable output (XOF), keyed MAC and key derivation.
SIMD-accelerated (SSE2, SSE4.1, AVX2, AVX-512 on x86; NEON on aarch64; portable C everywhere) with runtime CPU dispatch.

* **One binary, OpenSSL 3.5.x LTS and 4.0.x.** The module does *not* link libcrypto. It talks to OpenSSL only through
  the provider dispatch table, so the same file loads in both. (Verified: built against 3.5.9 headers, loaded and tested
  by 3.5.9 and 4.0.3.)
* Bit-exact with the [C2SP BLAKE3 spec](https://github.com/C2SP/C2SP/blob/main/BLAKE3.md) and the official test vectors.
* Vendors the upstream C implementation (BLAKE3 **1.8.7**, `third_party/blake3/VERSION`), CC0 / Apache-2.0 / Apache-2.0-with-LLVM-exception.
* **Not a FIPS provider** (algorithms carry `provider=blake3,fips=no`).
* **Not for passwords.** BLAKE3 is fast by design. Never use it as a password hash or password-based KDF; use
  Argon2id, scrypt or PBKDF2 for that. `BLAKE3-KDF` is for high-entropy key material only.

## Install

```sh
cmake -S . -B build -DOPENSSL_INCLUDE_DIR=/path/to/openssl/include     # headers only; 3.5 or newer
cmake --build build
```

Output is `blake3.so` (Linux), `blake3.dylib` (macOS) or `blake3.dll` (Windows). Then either:

1. copy it into the OpenSSL modules directory: `cp build/blake3.so "$(openssl version -m | cut -d'"' -f2)"`
   (or `cmake --install build` with `-DMODULES_DIR=...`; default is the output of `openssl version -m`), or
2. leave it anywhere and set `OPENSSL_MODULES=/dir/with/module`.

CMake options: `-DBLAKE3_PROV_USE_ASM=ON` (upstream `.S` files, Linux/BSD x86_64 only), `-DBLAKE3_PROV_MT=OFF`
(reserved stub, see "Threads"), `-DBLAKE3_PROV_BUILD_TESTS=ON -DOPENSSL_CRYPTO_LIBRARY=<libcrypto>` (tests and bench).

### Enable it

On the command line: `-provider blake3 -provider default`.

In `openssl.cnf` (see `conf/openssl-blake3.cnf.example`). Keep `default` active or OpenSSL loses its normal algorithms:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
blake3  = blake3_sect

[default_sect]
activate = 1

[blake3_sect]
activate = 1
```

> **Do not write `module = blake3`.** `module` is a file *path*; without the extension it is not found, and because
> `default` is active OpenSSL silently carries on without the provider (verified on 3.5.9). Omit `module` (the provider
> name `blake3` is looked up in the modules directory with the platform extension) or give a full path with extension.

## Algorithms

| Operation | Names | Notes |
|---|---|---|
| `OSSL_OP_DIGEST` | `BLAKE3`, `BLAKE3-256` | 32-byte default output, XOF (`xof=1`), block size 64 |
| `OSSL_OP_MAC` | `BLAKE3`, `KEYED-BLAKE3` | keyed_hash; key must be exactly 32 bytes |
| `OSSL_OP_KDF` | `BLAKE3-KDF` | derive_key; any output length |

Properties: `provider=blake3,fips=no`. Fetch explicitly with `provider=blake3`; that is also how you pick this
implementation if a future OpenSSL registers its own `BLAKE3` (checked: neither the default provider of 3.5.9 nor of 4.0.3 does).
`fips=yes` queries never return these algorithms.

### Parameters

**Digest**: get: `blocksize`=64, `size`=32, `xof`=1, `algid-absent`=1. Context set: `xoflen` (size_t), `size` (alias).
Context get: `xoflen`, `size`.

* `EVP_DigestFinal_ex` writes `xoflen` bytes (default 32) and does not look at the output size you pass, like SHAKE.
  Your buffer must hold `xoflen` bytes. `EVP_DigestFinalXOF(ctx, out, n)` writes `n` bytes, any `n`.
* `EVP_DigestSqueeze` can be called repeatedly and continues the XOF stream. After the first squeeze, `update` and `final` fail.
* `EVP_DigestInit_ex2` fully resets the context (including `xoflen`), so contexts are reusable. `EVP_MD_CTX_copy_ex` deep-copies, including the squeeze position.

**MAC**: set: `key` (octets, exactly 32 bytes, else error), `size` (output length, default 32, must be >= 1), `xof` (accepted, ignored).
The key may be passed to `EVP_MAC_init` or as a parameter; re-initialising without a key reuses the previous one.
Output of any length is the BLAKE3 XOF of the keyed hash.

**KDF**: set: `key` (key material, any length including 0), `info` (the context string; `context` is an alias). Both must be set.
Output length is the `keylen` you give `EVP_KDF_derive` (any length >= 1). `size` reports `SIZE_MAX`.
The context string must be hard-coded, globally unique and application specific (spec section 1.1), for example
`"myapp.example 2026-10-02 session keys v1"`. It is not a salt and must not contain secrets or per-user data.

**Provider**: `name`, `version`, `buildinfo` (includes BLAKE3 version and SIMD backend), `status`, and `blake3-impl`
(UTF-8, read-only): `portable|sse2|sse41|avx2|avx512|neon`.

### Deliberate design choices (measured)

* The digest does **not** register `OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS` (`get_ctx_params` is implemented and answers `xoflen`
  and `size`). If it did, `EVP_DigestFinal_ex` pays an `OSSL_PARAM` round trip per hash; at 64 B that is what separates
  "same per-call overhead as OpenSSL's SHA-256" from "slower". See `bench/RESULTS.md`.
* `OSSL_FUNC_DIGEST_SERIALIZE/DESERIALIZE` (only exist in 4.0 headers) are not implemented because the module is built
  against 3.5 headers. `COPYCTX` and `DUPCTX` are implemented.

## Examples

### CLI

```sh
export OPENSSL_MODULES=/dir/with/blake3.so
echo -n IETF | openssl dgst -provider blake3 -provider default -BLAKE3
# BLAKE3(stdin)= 83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2
echo -n IETF | openssl dgst -provider blake3 -provider default -BLAKE3 -xoflen 131
openssl mac -provider blake3 -provider default -macopt hexkey:$(printf 'cc%.0s' $(seq 32)) -in file BLAKE3
openssl kdf -provider blake3 -provider default -keylen 64 -kdfopt hexkey:00112233 -kdfopt info:myapp-2026 BLAKE3-KDF
openssl speed -provider blake3 -provider default -evp BLAKE3
openssl list -providers -verbose -provider blake3 | grep 'build info'     # shows simd=<backend>
```

### C: digest and XOF

```c
EVP_MD *md = EVP_MD_fetch(NULL, "BLAKE3", "provider=blake3");
EVP_MD_CTX *c = EVP_MD_CTX_new();
unsigned char out[32], xof[100];

EVP_DigestInit_ex2(c, md, NULL);
EVP_DigestUpdate(c, data, len);
EVP_DigestFinal_ex(c, out, NULL);               /* 32 bytes */

EVP_DigestInit_ex2(c, md, NULL);                /* reuse */
EVP_DigestUpdate(c, data, len);
EVP_DigestFinalXOF(c, xof, sizeof xof);         /* any length */
```

### C: incremental squeeze

```c
EVP_DigestInit_ex2(c, md, NULL);
EVP_DigestUpdate(c, data, len);
EVP_DigestSqueeze(c, buf1, 10);                 /* bytes 0..9   */
EVP_DigestSqueeze(c, buf2, 300);                /* bytes 10..309 (any sizes, call as often as you like) */
```

### C: keyed MAC

```c
EVP_MAC *mac = EVP_MAC_fetch(NULL, "BLAKE3", "provider=blake3");
EVP_MAC_CTX *mc = EVP_MAC_CTX_new(mac);
size_t outlen = 32, n;
OSSL_PARAM p[] = { OSSL_PARAM_construct_size_t("size", &outlen), OSSL_PARAM_construct_end() };
EVP_MAC_init(mc, key32, 32, p);                 /* key must be exactly 32 bytes */
EVP_MAC_update(mc, data, len);
EVP_MAC_final(mc, tag, &n, sizeof tag);
```

### C: KDF

```c
EVP_KDF *kdf = EVP_KDF_fetch(NULL, "BLAKE3-KDF", "provider=blake3");
EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
OSSL_PARAM p[] = {
    OSSL_PARAM_construct_octet_string("key",  material, material_len),
    OSSL_PARAM_construct_octet_string("info", (void *)"myapp.example 2026-10-02 session keys v1", 41),
    OSSL_PARAM_construct_end() };
EVP_KDF_derive(kc, out, 64, p);
```

## Which SIMD backend is used?

Chosen once at load time with `cpuid`/`xgetbv` (so an OS that has not enabled AVX/AVX-512 state is respected).
Check with `openssl list -providers -verbose` (`build info`) or the `blake3-impl` provider parameter.

For **testing only**, `BLAKE3_PROV_FORCE_IMPL=portable|sse2|sse41|avx2|avx512|neon` forces a backend.
If the CPU or build cannot run it, the provider falls back to the best available one and `blake3-impl` tells you what you got.

Widths: SSE2/SSE4.1 4 chunks in parallel, AVX2 8, AVX-512 16, NEON 4. Single-block compression uses SSE4.1/SSE2 (AVX-512VL when present).

## Design notes

* No libcrypto: only header-only parts of `openssl/core*.h` and `openssl/params.h` (struct and macros). `OSSL_PARAM`
  handling, error raising (through the core's `new_error/set_error_debug/vset_error` upcalls, with provider-local reason
  strings) and memory (`malloc`/`free`, non-elidable wipe before free) are local code in `src/`.
* Only `OSSL_provider_init` is exported (`-fvisibility=hidden` plus a linker version script / `.def` / exported-symbol list).
  All vendored upstream symbols are additionally renamed with a `b3prov_` prefix (`src/b3_prefix.h`) so a system `libblake3` cannot clash.
* Hot path: `update` hands the caller's buffer straight to `blake3_hasher_update`; the one-shot digest uses a stack hasher;
  a context is a single ~2 KB allocation; squeeze is `blake3_hasher_finalize_seek` with a stored offset.
* Upstream is unmodified apart from one 12-line runtime NEON on/off switch (`third_party/blake3/patches/`). `BLAKE3_TESTING`
  is defined for the dispatch file only to expose its feature variable to `src/b3_dispatch_ext.c`.

## PHP

`openssl_digest($data, 'BLAKE3')` works with **PHP 8.5 and newer** (tested: 8.5.11 and 8.6.0RC2 on Debian 13, OpenSSL 3.5.7, see `docker/php/Dockerfile`).
PHP 8.4 and older look algorithms up with `EVP_get_digestbyname()`, which does not see provider-only digests, so they report
"Unknown digest algorithm" even though the provider is loaded (use FFI + `EVP_Q_digest` there). `openssl_get_md_methods()` does not list BLAKE3 on any version,
and `hash('blake3')` is PHP's own hash extension, unrelated to OpenSSL.

## Threads

Contexts are independent and may be used from different threads; one context must not be used by two threads at once.
The provider itself never spawns threads (upstream's TBB multithreading is disabled). `BLAKE3_PROV_MT` is a reserved
CMake stub that errors out if turned on.

## Tests

`ctest` runs (per backend: auto, portable, sse2, sse41, avx2, avx512, neon; unavailable ones are logged as *Skipped*):
spec appendix traces (every round state, flags 0x0b/0x1c, chunk CVs), all 35 official vectors through digest/XOF/squeeze/MAC/KDF,
boundary and split tests (about 400k checks against an independent in-tree reference), EVP/API behaviour, a 16-thread test,
and a short differential fuzz. Beyond ctest: `test/cli_test.sh`, `test/cross/run_cross.py` (10,000 seeded cases against `b3sum`,
python `blake3`, upstream Rust `reference_impl`, Go `lukechampine.com/blake3`, the pure-Python spec oracle and the `openssl` CLI),
`test/big_stream.sh` (4 GiB stream vs `b3sum`), `test/fuzz/` (libFuzzer target), `bench/`. See `CHANGELOG.md` and
`bench/RESULTS.md` for what was actually run and measured.

## Known limitations

See the "Known limitations" section of `CHANGELOG.md` (platform coverage actually exercised, untested targets).

## License

Copyright 2026 Alexander Danilov. Apache-2.0 (see `LICENSE` and `NOTICE`).

Vendored BLAKE3 C sources (`third_party/blake3/`): CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception, at your option
(see `third_party/blake3/LICENSE_*`). One local modification is recorded in `third_party/blake3/patches/`.
