#include <stdlib.h>
#include <string.h>
#include "blake3.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
extern int g_cpu_features;
int get_cpu_features(void);

static const char *names[] = {"portable", "sse2", "sse41", "avx2", "avx512"};

const char *up_force(void) {
  const char *want = getenv("BLAKE3_PROV_FORCE_IMPL");
  int f = get_cpu_features(), have, lvl = -1, i;
  const int SSE2 = 1, SSSE3 = 2, SSE41 = 4, AVX = 8, AVX2 = 16, AVX512F = 32, AVX512VL = 64;
  have = ((f & (AVX512F | AVX512VL)) == (AVX512F | AVX512VL)) ? 4 : (f & AVX2) ? 3 : (f & SSE41) ? 2 : (f & SSE2) ? 1 : 0;
  if (want) for (i = 0; i < 5; i++) if (strcmp(want, names[i]) == 0) lvl = i;
  if (lvl >= 0 && lvl <= have) {
    int m = 0;
    if (lvl >= 1) m |= SSE2;
    if (lvl >= 2) m |= SSSE3 | SSE41;
    if (lvl >= 3) m |= AVX | AVX2;
    if (lvl >= 4) m |= AVX512F | AVX512VL;
    g_cpu_features = f & m;
    have = lvl;
  }
  return names[have];
}
#else
/* Non-x86 stock build: upstream dispatch has no g_cpu_features. The patched blake3_dispatch.c references this
   switch (normally defined in src/b3_dispatch_ext.c, which the stock library omits); stock = NEON always on. */
int b3prov_neon_enabled = 1;

const char *up_force(void) {
#if defined(__aarch64__) || defined(_M_ARM64)
  return "neon";
#else
  return "portable";
#endif
}
#endif

void up_hash(const void *buf, size_t len, unsigned char *out, int chunked) {
  blake3_hasher h;
  blake3_hasher_init(&h);
  if (chunked) {
    size_t o = 0;
    while (o < len) { size_t n = len - o > 4096 ? 4096 : len - o; blake3_hasher_update(&h, (const unsigned char *)buf + o, n); o += n; }
  } else {
    blake3_hasher_update(&h, buf, len);
  }
  blake3_hasher_finalize(&h, out, 32);
}
