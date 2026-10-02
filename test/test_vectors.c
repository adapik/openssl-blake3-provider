#include "t_common.h"

static int squeeze_pieces(const unsigned char *in, size_t n, unsigned char *out, size_t total, int keyed_dummy) {
  static const size_t pieces[] = {1, 7, 64, 59};
  EVP_MD *md = t_md(); EVP_MD_CTX *c = EVP_MD_CTX_new();
  size_t off = 0, i = 0; int ok = md && c && EVP_DigestInit_ex2(c, md, NULL) && EVP_DigestUpdate(c, in, n);
  (void)keyed_dummy;
  while (ok && off < total) {
    size_t s = pieces[i++ % 4]; if (s > total - off) s = total - off;
    ok = EVP_DigestSqueeze(c, out + off, s); off += s;
  }
  if (ok) { ERR_set_mark(); CHECK(!EVP_DigestUpdate(c, in, n ? 1 : 0) || n == 0); ERR_pop_to_mark(); }
  EVP_MD_CTX_free(c); EVP_MD_free(md);
  return ok;
}

int main(void) {
  t_vecs V; size_t i; unsigned char out[200], *in;
  CHECK(t_load()); t_check_impl();
  if (!t_load_vectors(&V)) return 1;
  for (i = 0; i < V.n; i++) {
    t_vec *v = &V.v[i];
    in = t_pattern(v->len);
    {
      EVP_MD *md = t_md(); unsigned int ol = 0;
      { size_t l = 0; CHECK(EVP_Q_digest(g_ctx, "BLAKE3", "provider=blake3", in, v->len, out, &l)); CHECK(l == 32); CHECK_MEM(out, v->hash, 32, "digest one-shot"); }
      { EVP_MD_CTX *c = EVP_MD_CTX_new(); CHECK(EVP_DigestInit_ex2(c, md, NULL)); CHECK(EVP_DigestUpdate(c, in, v->len)); CHECK(EVP_DigestFinal_ex(c, out, &ol)); CHECK(ol == 32); CHECK_MEM(out, v->hash, 32, "digest incremental"); EVP_MD_CTX_free(c); }
      CHECK(t_digest(in, v->len, out, v->outlen)); CHECK_MEM(out, v->hash, v->outlen, "digest FinalXOF 131");
      memset(out, 0, sizeof out); CHECK(squeeze_pieces(in, v->len, out, v->outlen, 0)); CHECK_MEM(out, v->hash, v->outlen, "digest squeeze pieces");
      EVP_MD_free(md);
    }
    CHECK(t_mac(V.key, 32, in, v->len, out, 32)); CHECK_MEM(out, v->keyed, 32, "mac 32");
    CHECK(t_mac(V.key, 32, in, v->len, out, v->outlen)); CHECK_MEM(out, v->keyed, v->outlen, "mac 131");
    CHECK(t_kdf((const unsigned char *)V.ctx, strlen(V.ctx), in, v->len, out, v->outlen)); CHECK_MEM(out, v->derive, v->outlen, "kdf 131");
    CHECK(t_kdf((const unsigned char *)V.ctx, strlen(V.ctx), in, v->len, out, 32)); CHECK_MEM(out, v->derive, 32, "kdf 32");
    free(in);
  }
  t_free_vectors(&V);
  printf("test_vectors: %zu cases, %d checks, %d failures\n", V.n, g_checks, g_fail);
  return t_done();
}
