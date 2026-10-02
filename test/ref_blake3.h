#ifndef REF_BLAKE3_H
#define REF_BLAKE3_H
#include <stddef.h>
#include <stdint.h>

#define REF_CHUNK_START 1
#define REF_CHUNK_END 2
#define REF_PARENT 4
#define REF_ROOT 8
#define REF_KEYED_HASH 16
#define REF_DERIVE_KEY_CONTEXT 32
#define REF_DERIVE_KEY_MATERIAL 64

void ref_compress(const uint32_t h[8], const uint32_t m[16], uint64_t t, uint32_t len,
                  uint32_t flags, uint32_t out[16], uint32_t trace[8][16]);

void ref_hash(const uint8_t *in, size_t n, uint8_t *out, size_t outlen);
void ref_keyed_hash(const uint8_t key[32], const uint8_t *in, size_t n, uint8_t *out, size_t outlen);
void ref_derive_key(const uint8_t *ctx, size_t ctxlen, const uint8_t *in, size_t n, uint8_t *out,
                    size_t outlen);
#endif
