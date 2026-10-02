#include "ref_blake3.h"
#include <string.h>

static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static const int PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void g(uint32_t *v, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
  v[a] = v[a] + v[b] + mx; v[d] = rotr(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];      v[b] = rotr(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + my; v[d] = rotr(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];      v[b] = rotr(v[b] ^ v[c], 7);
}

void ref_compress(const uint32_t h[8], const uint32_t m_in[16], uint64_t t, uint32_t len,
                  uint32_t flags, uint32_t out[16], uint32_t trace[8][16]) {
  uint32_t v[16], m[16], tmp[16];
  int r, i;
  memcpy(v, h, 32);
  memcpy(v + 8, IV, 16);
  v[12] = (uint32_t)t; v[13] = (uint32_t)(t >> 32); v[14] = len; v[15] = flags;
  memcpy(m, m_in, 64);
  if (trace) memcpy(trace[0], v, 64);
  for (r = 0; r < 7; r++) {
    g(v, 0, 4, 8, 12, m[0], m[1]);   g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);  g(v, 3, 7, 11, 15, m[6], m[7]);
    g(v, 0, 5, 10, 15, m[8], m[9]);  g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]); g(v, 3, 4, 9, 14, m[14], m[15]);
    if (trace && r < 7) memcpy(trace[r + 1 > 7 ? 7 : r + 1], v, 64);
    for (i = 0; i < 16; i++) tmp[i] = m[PERM[i]];
    memcpy(m, tmp, 64);
  }
  for (i = 0; i < 8; i++) { v[i] ^= v[i + 8]; v[i + 8] ^= h[i]; }
  memcpy(out, v, 64);
}

static void words(const uint8_t *b, size_t n, uint32_t w[16]) {
  uint8_t pad[64] = {0};
  int i;
  memcpy(pad, b, n);
  for (i = 0; i < 16; i++)
    w[i] = (uint32_t)pad[4 * i] | (uint32_t)pad[4 * i + 1] << 8 | (uint32_t)pad[4 * i + 2] << 16 |
           (uint32_t)pad[4 * i + 3] << 24;
}

typedef struct { uint32_t h[8], m[16]; uint64_t t; uint32_t len, flags; } node;

static node chunk_node(const uint32_t key[8], const uint8_t *in, size_t n, uint64_t counter, uint32_t fl) {
  node nd;
  uint32_t h[8], out[16];
  size_t nblocks = n == 0 ? 1 : (n + 63) / 64, i;
  memcpy(h, key, 32);
  for (i = 0; i < nblocks; i++) {
    size_t off = i * 64, bl = n - off > 64 ? 64 : n - off;
    uint32_t f = fl | (i == 0 ? REF_CHUNK_START : 0) | (i == nblocks - 1 ? REF_CHUNK_END : 0);
    uint32_t m[16];
    words(in + off, n == 0 ? 0 : bl, m);
    if (i == nblocks - 1) {
      memcpy(nd.h, h, 32); memcpy(nd.m, m, 64); nd.t = counter; nd.len = (uint32_t)bl; nd.flags = f;
      return nd;
    }
    ref_compress(h, m, counter, 64, f, out, NULL);
    memcpy(h, out, 32);
  }
  return nd;
}

static void node_cv(const node *nd, uint32_t cv[8]) {
  uint32_t out[16];
  ref_compress(nd->h, nd->m, nd->t, nd->len, nd->flags, out, NULL);
  memcpy(cv, out, 32);
}

static node subtree(const uint32_t key[8], const uint8_t *in, size_t n, uint64_t first_chunk, uint32_t fl) {
  size_t nchunks = n == 0 ? 1 : (n + 1023) / 1024, p = 1;
  node nd, l, r;
  if (nchunks == 1) return chunk_node(key, in, n, first_chunk, fl);
  while (p * 2 < nchunks) p *= 2;
  l = subtree(key, in, p * 1024, first_chunk, fl);
  r = subtree(key, in + p * 1024, n - p * 1024, first_chunk + p, fl);
  memcpy(nd.h, key, 32);
  node_cv(&l, nd.m);
  node_cv(&r, nd.m + 8);
  nd.t = 0; nd.len = 64; nd.flags = fl | REF_PARENT;
  return nd;
}

static void root_xof(const node *nd, uint8_t *out, size_t outlen) {
  uint64_t blk = 0;
  while (outlen > 0) {
    uint32_t w[16];
    uint8_t b[64];
    size_t take = outlen > 64 ? 64 : outlen;
    int i;
    ref_compress(nd->h, nd->m, blk++, nd->len, nd->flags | REF_ROOT, w, NULL);
    for (i = 0; i < 16; i++) {
      b[4 * i] = (uint8_t)w[i]; b[4 * i + 1] = (uint8_t)(w[i] >> 8);
      b[4 * i + 2] = (uint8_t)(w[i] >> 16); b[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
    memcpy(out, b, take);
    out += take; outlen -= take;
  }
}

static void keywords(const uint8_t key[32], uint32_t kw[8]) {
  int i;
  for (i = 0; i < 8; i++)
    kw[i] = (uint32_t)key[4 * i] | (uint32_t)key[4 * i + 1] << 8 | (uint32_t)key[4 * i + 2] << 16 |
            (uint32_t)key[4 * i + 3] << 24;
}

void ref_hash(const uint8_t *in, size_t n, uint8_t *out, size_t outlen) {
  node nd = subtree(IV, in, n, 0, 0);
  root_xof(&nd, out, outlen);
}

void ref_keyed_hash(const uint8_t key[32], const uint8_t *in, size_t n, uint8_t *out, size_t outlen) {
  uint32_t kw[8];
  node nd;
  keywords(key, kw);
  nd = subtree(kw, in, n, 0, REF_KEYED_HASH);
  root_xof(&nd, out, outlen);
}

void ref_derive_key(const uint8_t *ctx, size_t ctxlen, const uint8_t *in, size_t n, uint8_t *out,
                    size_t outlen) {
  uint8_t ck[32];
  uint32_t kw[8];
  node nd = subtree(IV, ctx, ctxlen, 0, REF_DERIVE_KEY_CONTEXT);
  root_xof(&nd, ck, 32);
  keywords(ck, kw);
  nd = subtree(kw, in, n, 0, REF_DERIVE_KEY_MATERIAL);
  root_xof(&nd, out, outlen);
}
