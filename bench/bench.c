#include <time.h>
#include "../test/t_common.h"
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#ifdef _WIN32
#include <windows.h>
static double now(void) { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double)c.QuadPart / (double)f.QuadPart; }
#else
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (double)t.tv_sec + (double)t.tv_nsec * 1e-9; }
#endif

extern void up_hash(const void *buf, size_t len, unsigned char *out, int chunked);
extern const char *up_force(void);

typedef struct { const char *name; EVP_MD *md; EVP_MD_CTX *ctx; int direct; } variant;
enum { ONESHOT, CHUNKED, EVPDIGEST };
static const unsigned char *g_buf; static unsigned char g_out[64];

static void run_once(variant *v, int mode, size_t len) {
  if (v->direct == 2) {
    SHA256_CTX c; SHA256_Init(&c);
    if (mode == CHUNKED) { size_t o = 0; while (o < len) { size_t n = len - o > 4096 ? 4096 : len - o; SHA256_Update(&c, g_buf + o, n); o += n; } }
    else SHA256_Update(&c, g_buf, len);
    SHA256_Final(g_out, &c);
    return;
  }
  if (v->direct) { up_hash(g_buf, len, g_out, mode == CHUNKED); return; }
  if (mode == EVPDIGEST) { unsigned int l; EVP_Digest(g_buf, len, g_out, &l, v->md, NULL); return; }
  EVP_DigestInit_ex2(v->ctx, v->md, NULL);
  if (mode == CHUNKED) { size_t o = 0; while (o < len) { size_t n = len - o > 4096 ? 4096 : len - o; EVP_DigestUpdate(v->ctx, g_buf + o, n); o += n; } }
  else EVP_DigestUpdate(v->ctx, g_buf, len);
  EVP_DigestFinal_ex(v->ctx, g_out, NULL);
}

static double measure(variant *v, int mode, size_t len, double min_s, int reps) {
  size_t iters = 1; double best = 1e30; int r;
  for (;;) { double t0 = now(), el; size_t i; for (i = 0; i < iters; i++) run_once(v, mode, len); el = now() - t0; if (el >= min_s / 4) { iters = (size_t)((double)iters * min_s / el) + 1; break; } iters *= 4; }
  for (r = 0; r < reps; r++) { double t0 = now(), el; size_t i; for (i = 0; i < iters; i++) run_once(v, mode, len); el = (now() - t0) / (double)iters; if (el < best) best = el; }
  return best;
}

int main(int argc, char **argv) {
  double min_s = argc > 1 ? atof(argv[1]) : 0.25; int reps = argc > 2 ? atoi(argv[2]) : 7; const char *filt = argc > 3 ? argv[3] : "";
  static const size_t sizes[] = {64, 256, 1024, 4096, 16384, 65536, 1u << 20, 64u << 20};
  variant vs[8]; size_t si, nv = 0, i; unsigned char *buf;
  const char *impl_up = up_force();
  const char *impl = "?";
  if (!t_load()) return 1;
  { OSSL_PROVIDER *p = t_provider(g_ctx, "blake3"); OSSL_PARAM q[2]; q[0] = OSSL_PARAM_construct_utf8_ptr("blake3-impl", (char **)&impl, 0); q[1] = OSSL_PARAM_construct_end(); OSSL_PROVIDER_get_params(p, q); }
  if (strcmp(impl, impl_up) != 0) fprintf(stderr, "WARNING: provider backend %s != upstream baseline backend %s\n", impl, impl_up);
  { static const char *names[] = {"SHA256", "SHA512", "BLAKE2B-512"};
    vs[nv].name = "blake3-evp"; vs[nv].md = t_md(); vs[nv].ctx = EVP_MD_CTX_new(); vs[nv++].direct = 0;
    vs[nv].name = "blake3-upstream-direct"; vs[nv].md = NULL; vs[nv].ctx = NULL; vs[nv++].direct = 1;
    vs[nv].name = "sha256-lowlevel"; vs[nv].md = NULL; vs[nv].ctx = NULL; vs[nv++].direct = 2;
    for (i = 0; i < 3; i++) { vs[nv].name = names[i]; vs[nv].md = EVP_MD_fetch(g_ctx, names[i], "provider=default"); vs[nv].ctx = EVP_MD_CTX_new(); vs[nv++].direct = 0; } }
  buf = malloc(64u << 20); for (i = 0; i < (64u << 20); i++) buf[i] = (unsigned char)(i * 2654435761u >> 24); g_buf = buf;
  fprintf(stderr, "bench backend: %s\n", impl);
  printf("#backend\t%s\n", impl);
  for (si = 0; si < sizeof sizes / sizeof *sizes; si++) {
    size_t len = sizes[si]; size_t k;
    for (k = 0; k < nv; k++) {
      int mode;
      if (vs[k].md == NULL && !vs[k].direct) continue;
      for (mode = ONESHOT; mode <= EVPDIGEST; mode++) {
        char label[64]; double s;
        if (mode == CHUNKED && len <= 4096) continue;
        if (mode == EVPDIGEST && (vs[k].direct || len > 65536)) continue;
        if (len >= (16u << 20) && min_s > 0.1) {   }
        snprintf(label, sizeof label, "%s/%s", vs[k].name, mode == ONESHOT ? "reuse-ctx" : mode == CHUNKED ? "chunked-4k" : "EVP_Digest");
        if (*filt && !strstr(label, filt)) continue;
        s = measure(&vs[k], mode, len, min_s, reps);
        printf("%s\t%zu\t%.1f\t%.1f\n", label, len, s * 1e9, (double)len / s / 1e6);
        fflush(stdout);
      }
    }
  }
  return 0;
}
