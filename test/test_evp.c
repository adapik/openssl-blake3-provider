#include "t_common.h"

int main(void) {
  EVP_MD *md; EVP_MAC *mac; EVP_KDF *kdf; OSSL_LIB_CTX *plain; unsigned char d[32];
  CHECK(t_load()); t_check_impl();

  md = EVP_MD_fetch(g_ctx, "BLAKE3", "provider=blake3"); CHECK(md != NULL);
  CHECK(EVP_MD_is_a(md, "BLAKE3") && EVP_MD_is_a(md, "BLAKE3-256"));
  CHECK(EVP_MD_get_size(md) == 32); CHECK(EVP_MD_get_block_size(md) == 64);
  CHECK((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0);
  CHECK((EVP_MD_get_flags(md) & EVP_MD_FLAG_DIGALGID_ABSENT) != 0);
  CHECK(strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)), "blake3") == 0);
  CHECK(EVP_MD_up_ref(md)); EVP_MD_free(md); EVP_MD_free(md);
  { EVP_MD *m2 = EVP_MD_fetch(g_ctx, "BLAKE3-256", "provider=blake3"); CHECK(m2 != NULL); EVP_MD_free(m2); }
  { EVP_MD *m2 = EVP_MD_fetch(g_ctx, "BLAKE3", "provider=blake3,fips=no"); CHECK(m2 != NULL); EVP_MD_free(m2); }
  ERR_set_mark();
  { EVP_MD *m2 = EVP_MD_fetch(g_ctx, "BLAKE3", "fips=yes"); CHECK(m2 == NULL); EVP_MD_free(m2);
    m2 = EVP_MD_fetch(g_ctx, "BLAKE3", "provider=default"); CHECK(m2 == NULL); EVP_MD_free(m2); }
  ERR_pop_to_mark();

  mac = EVP_MAC_fetch(g_ctx, "BLAKE3", "provider=blake3"); CHECK(mac != NULL); EVP_MAC_free(mac);
  mac = EVP_MAC_fetch(g_ctx, "KEYED-BLAKE3", "provider=blake3"); CHECK(mac != NULL); EVP_MAC_free(mac);
  kdf = EVP_KDF_fetch(g_ctx, "BLAKE3-KDF", "provider=blake3"); CHECK(kdf != NULL); EVP_KDF_free(kdf);

  plain = OSSL_LIB_CTX_new(); CHECK(plain != NULL);
  { OSSL_PROVIDER *dp = OSSL_PROVIDER_load(plain, "default"); EVP_MD *m2;
    CHECK(dp != NULL);
    ERR_set_mark(); m2 = EVP_MD_fetch(plain, "BLAKE3", NULL); CHECK(m2 == NULL); EVP_MD_free(m2);
    { EVP_MAC *x = EVP_MAC_fetch(plain, "BLAKE3", NULL); CHECK(x == NULL); EVP_MAC_free(x); }
    { EVP_KDF *x = EVP_KDF_fetch(plain, "BLAKE3-KDF", NULL); CHECK(x == NULL); EVP_KDF_free(x); }
    ERR_pop_to_mark(); OSSL_PROVIDER_unload(dp); }
  OSSL_LIB_CTX_free(plain);

  { OSSL_PROVIDER *p = t_provider(g_ctx, "blake3"); const char *name = NULL, *ver = NULL, *bi = NULL, *impl = NULL; int st = 0;
    OSSL_PARAM q[6];
    q[0] = OSSL_PARAM_construct_utf8_ptr("name", (char **)&name, 0); q[1] = OSSL_PARAM_construct_utf8_ptr("version", (char **)&ver, 0);
    q[2] = OSSL_PARAM_construct_utf8_ptr("buildinfo", (char **)&bi, 0); q[3] = OSSL_PARAM_construct_int("status", &st);
    q[4] = OSSL_PARAM_construct_utf8_ptr("blake3-impl", (char **)&impl, 0); q[5] = OSSL_PARAM_construct_end();
    CHECK(OSSL_PROVIDER_get_params(p, q));
    CHECK(name && strcmp(name, "OpenSSL BLAKE3 Provider") == 0); CHECK(ver && *ver); CHECK(st == 1);
    CHECK(bi && strstr(bi, "1.8.7") && strstr(bi, impl)); CHECK(impl && (!strcmp(impl, "portable") || !strcmp(impl, "sse2") || !strcmp(impl, "sse41") || !strcmp(impl, "avx2") || !strcmp(impl, "avx512") || !strcmp(impl, "neon")));
    printf("provider: %s %s [%s]\n", name, ver, bi); }

  { EVP_MD_CTX *c = EVP_MD_CTX_new(); OSSL_PARAM p[2]; size_t v = 99, got = 0; md = t_md();
    p[0] = OSSL_PARAM_construct_size_t("size", &v); p[1] = OSSL_PARAM_construct_end();
    CHECK(EVP_DigestInit_ex2(c, md, p));
    p[0] = OSSL_PARAM_construct_size_t("xoflen", &got); CHECK(EVP_MD_CTX_get_params(c, p)); CHECK(got == 99);
    CHECK(EVP_MD_CTX_get_size(c) == 99 || EVP_MD_CTX_get_size(c) == 32);
    { uint32_t v32 = 41; OSSL_PARAM p4[2]; p4[0].key = "xoflen"; p4[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER; p4[0].data = &v32; p4[0].data_size = 4; p4[0].return_size = 0; p4[1] = OSSL_PARAM_construct_end();
      CHECK(EVP_MD_CTX_set_params(c, p4)); got = 0; p[0] = OSSL_PARAM_construct_size_t("xoflen", &got); CHECK(EVP_MD_CTX_get_params(c, p)); CHECK(got == 41); }
    EVP_MD_CTX_free(c); EVP_MD_free(md); }

  { unsigned char k[7] = {0}, m[32]; unsigned long e; char buf[256]; int found = 0;
    ERR_clear_error(); CHECK(!t_mac(k, 7, (const unsigned char *)"x", 1, m, 32));
    while ((e = ERR_get_error()) != 0) { ERR_error_string_n(e, buf, sizeof buf); if (strstr(buf, "key length")) found = 1; }
    CHECK(found); }

  { size_t l = 0; CHECK(EVP_Q_digest(g_ctx, "BLAKE3", "provider=blake3", "", 0, d, &l)); CHECK(l == 32);
    { unsigned char e[32]; unhex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", e); CHECK_MEM(d, e, 32, "empty"); } }

  printf("test_evp: %d checks, %d failures\n", g_checks, g_fail);
  return t_done();
}
