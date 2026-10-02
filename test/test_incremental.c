#include "t_common.h"

static const size_t LENS[] = {0, 1, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073, 4096, 4097, 5120, 5121, 6144, 6145, 7168, 7169, 8192, 8193, 16384, 31744, 65537, 102400, 1048576 + 17};

static void test_len(size_t n, EVP_MD *md) {
  unsigned char *in = t_pattern(n), exp[300], got[300];
  size_t s, i, k;
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  ref_hash(in, n, exp, 300);
  CHECK(t_digest(in, n, got, 300)); CHECK_MEM(got, exp, 300, "single update");
  if (n <= 102400) {
    CHECK(EVP_DigestInit_ex2(c, md, NULL));
    for (i = 0; i < n; i++) CHECK(EVP_DigestUpdate(c, in + i, 1));
    CHECK(EVP_DigestFinalXOF(c, got, 300)); CHECK_MEM(got, exp, 300, "1-byte updates");
  }
  { static const size_t B[] = {64, 1024, 63, 65, 1023, 1025, 2048, 4096};
    for (k = 0; k < sizeof B / sizeof *B; k++) {
      CHECK(EVP_DigestInit_ex2(c, md, NULL));
      for (i = 0; i < n; ) { size_t t = B[k] > n - i ? n - i : B[k]; CHECK(EVP_DigestUpdate(c, in + i, t)); i += t; }
      CHECK(EVP_DigestFinalXOF(c, got, 300)); CHECK_MEM(got, exp, 300, "boundary split");
    } }
  for (s = 0; s < 100; s++) {
    size_t pos[8], np = n ? 1 + t_rand_n(7) : 0, j, last = 0;
    for (j = 0; j < np; j++) pos[j] = t_rand_n(n + 1);
    for (j = 0; j < np; j++) for (k = j + 1; k < np; k++) if (pos[k] < pos[j]) { size_t t = pos[j]; pos[j] = pos[k]; pos[k] = t; }
    CHECK(EVP_DigestInit_ex2(c, md, NULL));
    for (j = 0; j < np; j++) { CHECK(EVP_DigestUpdate(c, in + last, pos[j] - last)); last = pos[j]; }
    CHECK(EVP_DigestUpdate(c, in + last, n - last));
    CHECK(EVP_DigestFinalXOF(c, got, 300)); CHECK_MEM(got, exp, 300, "random split");
  }
  EVP_MD_CTX_free(c); free(in);
}

int main(void) {
  EVP_MD *md; size_t i; unsigned char exp[2000], got[2000], *in;
  CHECK(t_load()); t_check_impl();
  t_seed(0xB1A4E3);
  md = t_md(); CHECK(md != NULL);
  for (i = 0; i < sizeof LENS / sizeof *LENS; i++) test_len(LENS[i], md);

  { EVP_MD_CTX *c = EVP_MD_CTX_new(); unsigned char a[32], b[32]; int r;
    in = t_pattern(5000); ref_hash(in, 5000, exp, 32);
    for (r = 0; r < 4; r++) { unsigned int l; CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestUpdate(c, in, 5000)); CHECK(EVP_DigestFinal_ex(c, a, &l)); CHECK_MEM(a, exp, 32, "reuse"); }
    { OSSL_PARAM p[2]; size_t xl = 77; p[0] = OSSL_PARAM_construct_size_t("xoflen", &xl); p[1] = OSSL_PARAM_construct_end();
      CHECK(EVP_DigestInit_ex2(c, md, p)); CHECK(EVP_DigestUpdate(c, "x", 1)); CHECK(EVP_DigestSqueeze(c, got, 10));
      CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestUpdate(c, in, 5000)); CHECK(EVP_DigestFinal_ex(c, b, NULL)); CHECK_MEM(b, exp, 32, "reuse after squeeze"); }
    { OSSL_PARAM p[2]; size_t xl = 131; unsigned int l = 0; unsigned char big[131], e2[131];
      p[0] = OSSL_PARAM_construct_size_t("xoflen", &xl); p[1] = OSSL_PARAM_construct_end();
      CHECK(EVP_DigestInit_ex2(c, md, p)); CHECK(EVP_DigestUpdate(c, in, 5000)); CHECK(EVP_DigestFinal_ex(c, big, &l));
      ref_hash(in, 5000, e2, 131); CHECK(l == 131); CHECK_MEM(big, e2, 131, "Final_ex with xoflen"); }
    EVP_MD_CTX_free(c); free(in); }

  { EVP_MD_CTX *a = EVP_MD_CTX_new(), *b = EVP_MD_CTX_new(); size_t n = 9000; unsigned char x[200], y[200], e1[200], e2[200];
    in = t_pattern(n + 700);
    CHECK(EVP_DigestInit_ex2(a, md, NULL)); CHECK(EVP_DigestUpdate(a, in, n));
    CHECK(EVP_MD_CTX_copy_ex(b, a));
    CHECK(EVP_DigestUpdate(a, in + n, 300)); CHECK(EVP_DigestUpdate(b, in + n, 700));
    CHECK(EVP_DigestFinalXOF(a, x, 200)); CHECK(EVP_DigestFinalXOF(b, y, 200));
    ref_hash(in, n + 300, e1, 200); ref_hash(in, n + 700, e2, 200);
    CHECK_MEM(x, e1, 200, "dup A"); CHECK_MEM(y, e2, 200, "dup B");
    CHECK(EVP_DigestInit_ex2(a, md, NULL)); CHECK(EVP_DigestUpdate(a, in, 3000)); CHECK(EVP_DigestSqueeze(a, x, 37));
    EVP_MD_CTX_free(b); b = EVP_MD_CTX_new(); CHECK(EVP_MD_CTX_copy_ex(b, a));
    CHECK(EVP_DigestSqueeze(a, x + 37, 100)); CHECK(EVP_DigestSqueeze(b, y + 37, 100));
    ref_hash(in, 3000, e1, 137); CHECK_MEM(x + 37, e1 + 37, 100, "dup squeeze A"); CHECK_MEM(y + 37, e1 + 37, 100, "dup squeeze B");
    EVP_MD_CTX_free(a); EVP_MD_CTX_free(b); free(in); }

  { size_t n = 12345; unsigned char o1[1000], o2[3000], sq[3000]; EVP_MD_CTX *c = EVP_MD_CTX_new();
    in = t_pattern(n);
    CHECK(t_digest(in, n, o1, 1000)); CHECK(t_digest(in, n, o2, 3000));
    CHECK_MEM(o1, o2, 1000, "output(n) is prefix of output(m)");
    CHECK(t_digest(in, n, o1, 1)); CHECK_MEM(o1, o2, 1, "1-byte prefix");
    CHECK(t_digest(in, n, o1, 65)); CHECK_MEM(o1, o2, 65, "65-byte prefix");
    for (i = 0; i < 200; i++) {
      size_t off = 0;
      CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestUpdate(c, in, n));
      while (off < 3000) { size_t s = 1 + t_rand_n(i % 2 ? 70 : 300); if (s > 3000 - off) s = 3000 - off; CHECK(EVP_DigestSqueeze(c, sq + off, s)); off += s; }
      CHECK_MEM(sq, o2, 3000, "squeeze sequence");
    }
    EVP_MD_CTX_free(c); free(in); }

  { EVP_MD_CTX *c = EVP_MD_CTX_new(); unsigned char o[32]; unsigned int l;
    CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestUpdate(c, NULL, 0));
    CHECK(EVP_DigestSqueeze(c, o, 5));
    ERR_set_mark(); CHECK(!EVP_DigestUpdate(c, "a", 1)); CHECK(!EVP_DigestFinal_ex(c, o, &l)); ERR_pop_to_mark();
    CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestFinal_ex(c, o, &l));
    ERR_set_mark(); CHECK(!EVP_DigestUpdate(c, "a", 1)); ERR_pop_to_mark();
    CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestFinalXOF(c, o, 0));
    EVP_MD_CTX_free(c);
    { unsigned char k[40] = {0}, m[32];
      ERR_set_mark(); CHECK(!t_mac(k, 31, (const unsigned char *)"a", 1, m, 32)); CHECK(!t_mac(k, 33, (const unsigned char *)"a", 1, m, 32)); CHECK(!t_mac(k, 0, (const unsigned char *)"a", 1, m, 32)); ERR_pop_to_mark();
      CHECK(t_mac(k, 32, (const unsigned char *)"", 0, m, 32));
      ERR_set_mark(); CHECK(!t_mac(k, 32, (const unsigned char *)"a", 1, m, 0)); ERR_pop_to_mark();
      CHECK(t_mac(k, 32, (const unsigned char *)"a", 1, exp, 1)); CHECK(t_mac(k, 32, (const unsigned char *)"a", 1, exp, 2000)); }
    { EVP_KDF *kd = EVP_KDF_fetch(g_ctx, "BLAKE3-KDF", "provider=blake3"); EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kd); OSSL_PARAM p[2];
      p[0] = OSSL_PARAM_construct_octet_string("key", "material", 8); p[1] = OSSL_PARAM_construct_end();
      ERR_set_mark(); CHECK(EVP_KDF_derive(kc, o, 32, p) <= 0); ERR_pop_to_mark();
      CHECK(EVP_KDF_CTX_get_kdf_size(kc) == SIZE_MAX);
      EVP_KDF_CTX_free(kc); EVP_KDF_free(kd); }
    { unsigned char a[64], b[64]; static const char *cx = "app 2026 ctx";
      CHECK(t_kdf((const unsigned char *)cx, strlen(cx), (const unsigned char *)"", 0, a, 64)); ref_derive_key((const unsigned char *)cx, strlen(cx), (const unsigned char *)"", 0, b, 64); CHECK_MEM(a, b, 64, "kdf empty material");
      { EVP_KDF *kd = EVP_KDF_fetch(g_ctx, "BLAKE3-KDF", "provider=blake3"); EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kd); OSSL_PARAM p[3];
        p[0] = OSSL_PARAM_construct_octet_string("key", "", 0); p[1] = OSSL_PARAM_construct_octet_string("context", (void *)cx, strlen(cx)); p[2] = OSSL_PARAM_construct_end();
        CHECK(EVP_KDF_derive(kc, a, 64, p) > 0); CHECK_MEM(a, b, 64, "kdf context alias"); EVP_KDF_CTX_free(kc); EVP_KDF_free(kd); } }
  }
  EVP_MD_free(md);
  printf("test_incremental: %d checks, %d failures\n", g_checks, g_fail);
  return t_done();
}
