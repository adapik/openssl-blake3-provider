#include "../t_common.h"

#define MAXMSG (1u << 20)

static EVP_MD *g_md;
static EVP_MAC *g_mac;
static EVP_KDF *g_kdf;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  if (!t_load()) abort();
  g_md = t_md(); g_mac = EVP_MAC_fetch(g_ctx, "BLAKE3", "provider=blake3"); g_kdf = EVP_KDF_fetch(g_ctx, "BLAKE3-KDF", "provider=blake3");
  if (!g_md || !g_mac || !g_kdf) abort();
  return 0;
}

typedef struct { const uint8_t *p; size_t n, i; } rd;
static unsigned rd8(rd *r) { return r->i < r->n ? r->p[r->i++] : 0; }
static size_t rd_len(rd *r) {
  unsigned k = rd8(r), v = rd8(r) | rd8(r) << 8;
  switch (k % 6) {
  case 0: return v % 70;
  case 1: return 1024 + (v % 5) - 2;
  case 2: return 64 * (v % 40) + (v % 3) - 1;
  case 3: return v % 4096;
  case 4: return 1024 * (v % 70);
  default: return v;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  rd r = {data, size, 0};
  unsigned mode = rd8(&r) % 3;
  uint8_t key[32], *msg = malloc(MAXMSG), *msg2 = NULL, *exp, *got;
  size_t i, mlen = 0, mlen2 = 0, outlen, off = 0, off2 = 0;
  EVP_MD_CTX *c = NULL, *c2 = NULL;
  int ok = 1;
  for (i = 0; i < 32; i++) key[i] = (uint8_t)(rd8(&r) * 7 + i);
  uint8_t pool[256];
  for (i = 0; i < 256; i++) pool[i] = (uint8_t)(i < size ? data[i] : i * 131) ^ (uint8_t)(i * 17);
#define APPEND(buf, len, n) do { size_t k_; for (k_ = 0; k_ < (n); k_++) (buf)[(len) + k_] = pool[(k_ * 7 + (len)) & 255] ^ (uint8_t)(k_ >> 8); } while (0)

  if (mode == 0) {
    c = EVP_MD_CTX_new(); EVP_DigestInit_ex2(c, g_md, NULL);
    exp = malloc(MAXMSG + 4096); got = malloc(MAXMSG + 4096);
    msg2 = malloc(MAXMSG);
    {
      size_t sq = 0, sq2 = 0; int squeezing = 0, have2 = 0;
      uint8_t *out1 = malloc(1 << 16), *out2 = malloc(1 << 16);
      size_t o1 = 0, o2 = 0; (void)sq; (void)sq2; (void)off; (void)off2;
      while (r.i < r.n) {
        unsigned op = rd8(&r) % 5;
        size_t n = rd_len(&r);
        if (op <= 1 && !squeezing) {
          if (mlen + n > MAXMSG) continue;
          APPEND(msg, mlen, n);
          if (!EVP_DigestUpdate(c, msg + mlen, n)) { ok = 0; break; }
          mlen += n;
          if (have2) { if (mlen2 + n > MAXMSG) continue; APPEND(msg2, mlen2, n); EVP_DigestUpdate(c2, msg2 + mlen2, n); mlen2 += n; }
        } else if (op == 2 && !have2) {
          c2 = EVP_MD_CTX_new(); if (!EVP_MD_CTX_copy_ex(c2, c)) { ok = 0; break; }
          memcpy(msg2, msg, mlen); mlen2 = mlen; have2 = 1; o2 = o1;
          memcpy(out2, out1, o1);
        } else if (op >= 3) {
          n %= 3000;
          if (o1 + n > (1 << 16)) continue;
          squeezing = 1;
          if (!EVP_DigestSqueeze(c, out1 + o1, n)) { ok = 0; break; }
          o1 += n;
          if (have2 && o2 + n <= (1 << 16)) { if (!EVP_DigestSqueeze(c2, out2 + o2, n)) { ok = 0; break; } o2 += n; }
        }
      }
      if (ok && o1 > 0) { ref_hash(msg, mlen, exp, o1); if (memcmp(exp, out1, o1) != 0) { fprintf(stderr, "MISMATCH digest squeeze (len %zu, out %zu)\n", mlen, o1); ok = 0; } }
      if (ok && have2 && o2 > 0) { ref_hash(msg2, mlen2, exp, o2); if (memcmp(exp, out2, o2) != 0) { fprintf(stderr, "MISMATCH digest squeeze copy\n"); ok = 0; } }
      if (ok && !squeezing) {
        size_t xl = 1 + (r.n ? r.p[r.n - 1] : 0) * 5; unsigned int dl = 0; (void)dl;
        if (!EVP_DigestFinalXOF(c, got, xl)) ok = 0;
        else { ref_hash(msg, mlen, exp, xl); if (memcmp(exp, got, xl) != 0) { fprintf(stderr, "MISMATCH digest final (len %zu)\n", mlen); ok = 0; } }
      }
      free(out1); free(out2);
    }
    free(exp); free(got); EVP_MD_CTX_free(c); EVP_MD_CTX_free(c2);
  } else {
    size_t total = rd_len(&r) % 300000; outlen = 1 + (rd_len(&r) % 700);
    if (total > MAXMSG) total = MAXMSG;
    APPEND(msg, 0, total); mlen = total;
    exp = malloc(outlen); got = malloc(outlen);
    if (mode == 1) {
      EVP_MAC_CTX *mc = EVP_MAC_CTX_new(g_mac); OSSL_PARAM p[2]; size_t sz = outlen, ol = 0, done = 0;
      p[0] = OSSL_PARAM_construct_size_t("size", &sz); p[1] = OSSL_PARAM_construct_end();
      if (!EVP_MAC_init(mc, key, 32, p)) ok = 0;
      while (ok && done < total) { size_t n = rd_len(&r); if (n > total - done) n = total - done; if (n == 0) n = 1 + (done & 7); if (n > total - done) n = total - done; ok = EVP_MAC_update(mc, msg + done, n); done += n; }
      if (ok) ok = EVP_MAC_final(mc, got, &ol, outlen) && ol == outlen;
      if (ok) { ref_keyed_hash(key, msg, total, exp, outlen); if (memcmp(exp, got, outlen) != 0) { fprintf(stderr, "MISMATCH keyed\n"); ok = 0; } }
      EVP_MAC_CTX_free(mc);
    } else {
      size_t cl = rd8(&r) % 40; uint8_t cx[40]; for (i = 0; i < cl; i++) cx[i] = key[i % 32];
      if (!t_kdf(cx, cl, msg, total, got, outlen)) ok = 0;
      else { ref_derive_key(cx, cl, msg, total, exp, outlen); if (memcmp(exp, got, outlen) != 0) { fprintf(stderr, "MISMATCH derive\n"); ok = 0; } }
    }
    free(exp); free(got);
  }
  free(msg); free(msg2);
  if (!ok) { fprintf(stderr, "fuzz case failed (mode %u, input %zu bytes)\n", mode, size); abort(); }
  return 0;
}

#ifndef FUZZ_LIBFUZZER
#include <time.h>
int main(int argc, char **argv) {
  double secs = argc > 1 ? atof(argv[1]) : 10; uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
  time_t end = time(NULL) + (time_t)secs; unsigned long iters = 0; uint8_t *buf = malloc(1 << 16);
  LLVMFuzzerInitialize(NULL, NULL); t_check_impl(); t_seed(seed);
  while (time(NULL) < end || iters < 20) {
    size_t n = t_rand_n(4) == 0 ? t_rand_n(60000) : t_rand_n(600), i;
    for (i = 0; i < n; i++) buf[i] = (uint8_t)t_rand();
    LLVMFuzzerTestOneInput(buf, n); iters++;
    if (time(NULL) >= end && iters >= 20) break;
  }
  printf("fuzz_ops: %lu random programs, no mismatches\n", iters);
  free(buf);
  EVP_MD_free(g_md); EVP_MAC_free(g_mac); EVP_KDF_free(g_kdf);
  return t_done();
}
#endif
