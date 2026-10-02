#include <stdlib.h>
#include <string.h>

#include "b3_dispatch_ext.h"
#include "blake3_impl.h"

#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef volatile LONG b3_once_t;
#define B3_CAS(p, from, to) (InterlockedCompareExchange((p), (to), (from)) == (from))
#define B3_LOAD(p) InterlockedCompareExchange((p), 0, 0)
#define B3_STORE(p, v) InterlockedExchange((p), (v))
#define B3_YIELD() SwitchToThread()
#else
#include <sched.h>
typedef int b3_once_t;
#define B3_CAS(p, from, to) __sync_bool_compare_and_swap((p), (from), (to))
#define B3_LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define B3_STORE(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define B3_YIELD() sched_yield()
#endif

extern int g_cpu_features;
int get_cpu_features(void);

#if defined(IS_AARCH64) && BLAKE3_USE_NEON == 1
int b3prov_neon_enabled = 1;
#endif

enum {
  IMPL_PORTABLE, IMPL_SSE2, IMPL_SSE41, IMPL_AVX2, IMPL_AVX512, IMPL_NEON,
  IMPL_COUNT
};
static const char *const impl_names[IMPL_COUNT] = {
    "portable", "sse2", "sse41", "avx2", "avx512", "neon"};

static b3_once_t g_state;
static const char *g_active = "portable";
static int g_fell_back;

#if defined(IS_X86)
#define F_SSE2 (1 << 0)
#define F_SSSE3 (1 << 1)
#define F_SSE41 (1 << 2)
#define F_AVX (1 << 3)
#define F_AVX2 (1 << 4)
#define F_AVX512F (1 << 5)
#define F_AVX512VL (1 << 6)

static int detected_level(int f) {
  if ((f & (F_AVX512F | F_AVX512VL)) == (F_AVX512F | F_AVX512VL))
    return IMPL_AVX512;
  if (f & F_AVX2) return IMPL_AVX2;
  if (f & F_SSE41) return IMPL_SSE41;
  if (f & F_SSE2) return IMPL_SSE2;
  return IMPL_PORTABLE;
}

static int level_mask(int level) {
  int m = 0;
  if (level >= IMPL_SSE2) m |= F_SSE2;
  if (level >= IMPL_SSE41) m |= F_SSSE3 | F_SSE41;
  if (level >= IMPL_AVX2) m |= F_AVX | F_AVX2;
  if (level >= IMPL_AVX512) m |= F_AVX512F | F_AVX512VL;
  return m;
}
#endif

static int parse_impl(const char *s) {
  int i;
  for (i = 0; i < IMPL_COUNT; i++)
    if (strcmp(s, impl_names[i]) == 0) return i;
  return -1;
}

static void do_init(void) {
  const char *force = getenv("BLAKE3_PROV_FORCE_IMPL");
  int want = (force != NULL && force[0] != '\0') ? parse_impl(force) : -1;
  int have;
  (void)want;
#if defined(IS_X86)
  {
    int f = (int)get_cpu_features();
    have = detected_level(f);
    if (want >= 0) {
      if (want > have || want == IMPL_NEON) {
        g_fell_back = 1;
      } else {
        have = want;
        g_cpu_features = f & level_mask(want);
      }
    }
    g_active = impl_names[have];
  }
#elif defined(IS_AARCH64) && BLAKE3_USE_NEON == 1
  have = IMPL_NEON;
  if (want == IMPL_PORTABLE) {
    b3prov_neon_enabled = 0;
    have = IMPL_PORTABLE;
  } else if (want >= 0 && want != IMPL_NEON) {
    g_fell_back = 1;
  }
  g_active = impl_names[have];
#else
  have = IMPL_PORTABLE;
  if (want > 0) g_fell_back = 1;
  g_active = impl_names[have];
#endif
}

const char *b3prov_dispatch_init(void) {
  if (B3_LOAD(&g_state) != 2) {
    if (B3_CAS(&g_state, 0, 1)) {
      do_init();
      B3_STORE(&g_state, 2);
    } else {
      while (B3_LOAD(&g_state) != 2) B3_YIELD();
    }
  }
  return g_active;
}

int b3prov_dispatch_force_fell_back(void) {
  b3prov_dispatch_init();
  return g_fell_back;
}
