#include "t_common.h"
#ifdef _WIN32
#include <windows.h>
typedef HANDLE thr_t;
typedef DWORD (WINAPI *thr_fn)(void *);
static int thr_start(thr_t *t, DWORD (WINAPI *f)(void *), void *a) { *t = CreateThread(NULL, 0, f, a, 0, NULL); return *t != NULL; }
static void thr_join(thr_t t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
#define THR_RET DWORD WINAPI
#define THR_OK 0
static volatile LONG g_ready, g_go;
static void barrier_wait(int n) { InterlockedIncrement(&g_ready); while (g_ready < n) Sleep(0); (void)g_go; }
#else
#include <pthread.h>
typedef pthread_t thr_t;
static int thr_start(thr_t *t, void *(*f)(void *), void *a) { return pthread_create(t, NULL, f, a) == 0; }
static void thr_join(thr_t t) { pthread_join(t, NULL); }
#define THR_RET void *
#define THR_OK NULL
static pthread_barrier_t g_bar;
static void barrier_wait(int n) { (void)n; pthread_barrier_wait(&g_bar); }
#endif

#define NTHREADS 16
#define NOPS 10000
static volatile int g_bad[NTHREADS];

static THR_RET worker(void *arg) {
  int id = (int)(intptr_t)arg, i;
  uint64_t s = 0x1234567 + (uint64_t)id * 7919;
  OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new(); EVP_MD *md = NULL; EVP_MAC *mac = NULL; EVP_KDF *kdf = NULL; unsigned char *buf = malloc(5000), key[32]; OSSL_PROVIDER *pd, *pb;
  barrier_wait(NTHREADS);
  OSSL_PROVIDER_set_default_search_path(lc, t_module_dir());
  pd = OSSL_PROVIDER_load(lc, "default"); pb = OSSL_PROVIDER_load(lc, "blake3");
  if (!pd || !pb) { g_bad[id] = 1; return THR_OK; }
  md = EVP_MD_fetch(lc, "BLAKE3", "provider=blake3"); mac = EVP_MAC_fetch(lc, "BLAKE3", "provider=blake3"); kdf = EVP_KDF_fetch(lc, "BLAKE3-KDF", "provider=blake3");
  for (i = 0; i < 32; i++) key[i] = (unsigned char)(id * 31 + i);
  for (i = 0; i < NOPS; i++) {
    unsigned char o[100], e[100]; size_t n, ol, k;
    s ^= s >> 12; s ^= s << 25; s ^= s >> 27; n = (size_t)((s * 0x2545F4914F6CDD1Dull) % 5000);
    for (k = 0; k < n; k++) buf[k] = (unsigned char)(k * (size_t)(id + 1) + (size_t)i);
    switch (i % 3) {
    case 0: { EVP_MD_CTX *c = EVP_MD_CTX_new(); EVP_DigestInit_ex2(c, md, NULL); EVP_DigestUpdate(c, buf, n); EVP_DigestFinalXOF(c, o, 100); EVP_MD_CTX_free(c); ref_hash(buf, n, e, 100); break; }
    case 1: { EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac); OSSL_PARAM p[2]; size_t sz = 100; p[0] = OSSL_PARAM_construct_size_t("size", &sz); p[1] = OSSL_PARAM_construct_end();
      EVP_MAC_init(c, key, 32, p); EVP_MAC_update(c, buf, n); EVP_MAC_final(c, o, &ol, 100); EVP_MAC_CTX_free(c); ref_keyed_hash(key, buf, n, e, 100); break; }
    default: { EVP_KDF_CTX *c = EVP_KDF_CTX_new(kdf); OSSL_PARAM p[3];
      p[0] = OSSL_PARAM_construct_octet_string("key", buf, n); p[1] = OSSL_PARAM_construct_octet_string("info", key, 32); p[2] = OSSL_PARAM_construct_end();
      EVP_KDF_derive(c, o, 100, p); EVP_KDF_CTX_free(c); ref_derive_key(key, 32, buf, n, e, 100); break; }
    }
    if (memcmp(o, e, 100) != 0) { g_bad[id] = 1; break; }
  }
  EVP_MD_free(md); EVP_MAC_free(mac); EVP_KDF_free(kdf); free(buf); OSSL_PROVIDER_unload(pb); OSSL_PROVIDER_unload(pd); OSSL_LIB_CTX_free(lc);
  return THR_OK;
}

int main(void) {
  thr_t t[NTHREADS]; int i, bad = 0;
  setvbuf(stdout, NULL, _IOLBF, 0);
#ifndef _WIN32
  pthread_barrier_init(&g_bar, NULL, NTHREADS);
#endif
  for (i = 0; i < NTHREADS; i++) if (!thr_start(&t[i], worker, (void *)(intptr_t)i)) return 1;
  for (i = 0; i < NTHREADS; i++) thr_join(t[i]);
  for (i = 0; i < NTHREADS; i++) bad += g_bad[i];
  printf("test_threads: %d threads x %d ops, %d bad threads\n", NTHREADS, NOPS, bad);
  return bad != 0;
}
