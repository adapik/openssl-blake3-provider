#ifndef T_COMMON_H
#define T_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ref_blake3.h"

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); ERR_print_errors_fp(stderr); } } while (0)
#define CHECK_MEM(a, b, n, what) do { g_checks++; if (memcmp((a), (b), (n)) != 0) { g_fail++; fprintf(stderr, "FAIL %s:%d: mismatch (%s) n=%zu\n", __FILE__, __LINE__, what, (size_t)(n)); } } while (0)

static OSSL_LIB_CTX *g_ctx;

static OSSL_PROVIDER *g_provs[64];
static int g_nprovs;
static OSSL_PROVIDER *t_provider(OSSL_LIB_CTX *c, const char *n) {
  OSSL_PROVIDER *p = OSSL_PROVIDER_load(c, n);
  if (p && c == g_ctx && g_nprovs < 64) g_provs[g_nprovs++] = p;
  return p;
}
static int t_done(void) {
  while (g_nprovs > 0) OSSL_PROVIDER_unload(g_provs[--g_nprovs]);
  OSSL_LIB_CTX_free(g_ctx); g_ctx = NULL;
  return g_fail != 0;
}

static const char *t_module_dir(void) {
  const char *d = getenv("B3_MODULE_DIR");
  return d ? d : ".";
}

static int t_load(void) {
  g_ctx = OSSL_LIB_CTX_new();
  if (g_ctx == NULL) return 0;
  if (!OSSL_PROVIDER_set_default_search_path(g_ctx, t_module_dir())) return 0;
  if (t_provider(g_ctx, "default") == NULL) return 0;
  if (t_provider(g_ctx, "blake3") == NULL) { fprintf(stderr, "cannot load blake3 from %s\n", t_module_dir()); ERR_print_errors_fp(stderr); return 0; }
  return 1;
}

static void t_check_impl(void) {
  OSSL_PROVIDER *p = t_provider(g_ctx, "blake3");
  const char *impl = NULL;
  OSSL_PARAM q[2] = {OSSL_PARAM_construct_utf8_ptr("blake3-impl", (char **)&impl, 0), OSSL_PARAM_construct_end()};
  const char *want = getenv("BLAKE3_PROV_FORCE_IMPL");
  if (p && OSSL_PROVIDER_get_params(p, q) && impl) {
    printf("backend: %s (requested: %s)\n", impl, want ? want : "auto");
    if (want && *want && strcmp(want, impl) != 0) { printf("SKIP: requested backend '%s' not available on this CPU/build (got '%s')\n", want, impl); exit(77); }
  } else { g_fail++; fprintf(stderr, "cannot read blake3-impl\n"); }
}

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static size_t unhex(const char *s, unsigned char *out) {
  size_t n = strlen(s) / 2, i;
  for (i = 0; i < n; i++) out[i] = (unsigned char)(hexval(s[2 * i]) << 4 | hexval(s[2 * i + 1]));
  return n;
}
static void tohex(const unsigned char *b, size_t n, char *out) {
  static const char *d = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
  out[2 * n] = 0;
}

static unsigned char *t_pattern(size_t n) {
  unsigned char *b = malloc(n ? n : 1);
  size_t i;
  for (i = 0; i < n; i++) b[i] = (unsigned char)(i % 251);
  return b;
}

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static void t_seed(uint64_t s) { g_rng = s ? s : 1; }
static uint64_t t_rand(void) { g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27; return g_rng * 0x2545F4914F6CDD1Dull; }
static size_t t_rand_n(size_t n) { return n ? (size_t)(t_rand() % n) : 0; }

typedef struct { size_t len; unsigned char *hash, *keyed, *derive; size_t outlen; } t_vec;
typedef struct { unsigned char key[32]; char *ctx; t_vec *v; size_t n; } t_vecs;

static char *slurp(const char *path) {
  FILE *f = fopen(path, "rb");
  long n; char *b;
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
  b = malloc((size_t)n + 1);
  if (fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
  b[n] = 0; fclose(f);
  return b;
}
static char *json_str(const char *from, const char *key, const char **end) {
  char pat[64]; const char *p, *q; char *r;
  snprintf(pat, sizeof pat, "\"%s\"", key);
  p = strstr(from, pat); if (!p) return NULL;
  p = strchr(p + strlen(pat), ':'); p = strchr(p, '"') + 1; q = strchr(p, '"');
  r = malloc((size_t)(q - p) + 1); memcpy(r, p, (size_t)(q - p)); r[q - p] = 0;
  if (end) *end = q + 1;
  return r;
}
static int t_load_vectors(t_vecs *V) {
  const char *path = getenv("B3_VECTORS");
  char *j = slurp(path ? path : "vectors/test_vectors.json");
  const char *p, *cases;
  char *k;
  size_t cap = 64;
  if (!j) { fprintf(stderr, "cannot read vectors (set B3_VECTORS)\n"); return 0; }
  k = json_str(j, "key", NULL); memcpy(V->key, k, 32); free(k);
  V->ctx = json_str(j, "context_string", NULL);
  cases = strstr(j, "\"cases\"");
  V->v = calloc(cap, sizeof(t_vec)); V->n = 0;
  p = cases;
  while ((p = strstr(p, "\"input_len\"")) != NULL) {
    t_vec *e = &V->v[V->n++]; char *h; const char *e1;
    p = strchr(p, ':') + 1; e->len = (size_t)strtoul(p, NULL, 10);
    h = json_str(p, "hash", &e1); e->outlen = strlen(h) / 2; e->hash = malloc(e->outlen); unhex(h, e->hash); free(h);
    h = json_str(p, "keyed_hash", &e1); e->keyed = malloc(e->outlen); unhex(h, e->keyed); free(h);
    h = json_str(p, "derive_key", &e1); e->derive = malloc(e->outlen); unhex(h, e->derive); free(h);
    p = e1;
  }
  free(j);
  return V->n > 0;
}

static void t_free_vectors(t_vecs *V) {
  size_t i;
  for (i = 0; i < V->n; i++) { free(V->v[i].hash); free(V->v[i].keyed); free(V->v[i].derive); }
  free(V->v); free(V->ctx);
}

static EVP_MD *t_md(void) { return EVP_MD_fetch(g_ctx, "BLAKE3", "provider=blake3"); }

static int t_digest_split(const unsigned char *in, size_t n, const size_t *splits, size_t nsplits, unsigned char *out, size_t outlen) {
  EVP_MD *md = t_md(); EVP_MD_CTX *c = EVP_MD_CTX_new();
  size_t off = 0, i; int ok = md && c && EVP_DigestInit_ex2(c, md, NULL);
  for (i = 0; ok && i < nsplits && off < n; i++) {
    size_t s = splits[i] > n - off ? n - off : splits[i];
    ok = EVP_DigestUpdate(c, in + off, s); off += s;
  }
  if (ok && off < n) ok = EVP_DigestUpdate(c, in + off, n - off);
  if (ok) ok = EVP_DigestFinalXOF(c, out, outlen);
  EVP_MD_CTX_free(c); EVP_MD_free(md);
  return ok;
}
static int t_digest(const unsigned char *in, size_t n, unsigned char *out, size_t outlen) {
  size_t s = n; return t_digest_split(in, n, &s, 1, out, outlen);
}

static int t_mac(const unsigned char *key, size_t keylen, const unsigned char *in, size_t n, unsigned char *out, size_t outlen) {
  EVP_MAC *m = EVP_MAC_fetch(g_ctx, "BLAKE3", "provider=blake3"); EVP_MAC_CTX *c = m ? EVP_MAC_CTX_new(m) : NULL;
  size_t ol = 0; int ok = 0;
  OSSL_PARAM p[2]; size_t sz = outlen;
  p[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz); p[1] = OSSL_PARAM_construct_end();
  if (c && EVP_MAC_init(c, key, keylen, p) && EVP_MAC_update(c, in, n) && EVP_MAC_final(c, out, &ol, outlen) && ol == outlen) ok = 1;
  EVP_MAC_CTX_free(c); EVP_MAC_free(m);
  return ok;
}

static int t_kdf(const unsigned char *ctx, size_t ctxlen, const unsigned char *key, size_t keylen, unsigned char *out, size_t outlen) {
  EVP_KDF *k = EVP_KDF_fetch(g_ctx, "BLAKE3-KDF", "provider=blake3"); EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
  OSSL_PARAM p[3]; int ok;
  p[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, keylen);
  p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)ctx, ctxlen);
  p[2] = OSSL_PARAM_construct_end();
  ok = c && EVP_KDF_derive(c, out, outlen, p) > 0;
  EVP_KDF_CTX_free(c); EVP_KDF_free(k);
  return ok;
}
#endif
