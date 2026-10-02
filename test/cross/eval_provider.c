#include "../t_common.h"

int main(int argc, char **argv) {
  FILE *mf, *bf; char line[8192]; size_t idx = 0; unsigned char *buf = NULL, *out = NULL; size_t cap = 0;
  if (argc < 3) return 2;
  if (!t_load()) return 1;
  { OSSL_PROVIDER *p = t_provider(g_ctx, "blake3"); const char *impl = ""; OSSL_PARAM q[2];
    q[0] = OSSL_PARAM_construct_utf8_ptr("blake3-impl", (char **)&impl, 0); q[1] = OSSL_PARAM_construct_end();
    OSSL_PROVIDER_get_params(p, q); fprintf(stderr, "eval_provider backend: %s\n", impl); }
  mf = fopen(argv[1], "r"); bf = fopen(argv[2], "rb");
  if (!mf || !bf) return 2;
  out = malloc(4096);
  while (fgets(line, sizeof line, mf)) {
    char mode[16], keyh[200], ctxh[4096]; size_t len, outlen; unsigned long long off; unsigned char key[32], ctx[2048]; size_t ctxlen = 0; char *hx;
    if (sscanf(line, "%15s %zu %199s %4095s %zu %llu", mode, &len, keyh, ctxh, &outlen, &off) != 6) return 3;
    if (len + 1 > cap) { cap = len + 1; buf = realloc(buf, cap); }
    fseek(bf, (long)off, SEEK_SET);
    if (len && fread(buf, 1, len, bf) != len) return 4;
    if (strcmp(keyh, "-")) unhex(keyh, key);
    if (strcmp(ctxh, "-")) ctxlen = unhex(ctxh, ctx);
    if (strcmp(mode, "hash") == 0) { if (!t_digest(buf, len, out, outlen)) return 5; }
    else if (strcmp(mode, "keyed") == 0) { if (!t_mac(key, 32, buf, len, out, outlen)) return 5; }
    else { if (!t_kdf(ctx, ctxlen, buf, len, out, outlen)) return 5; }
    hx = malloc(outlen * 2 + 1); tohex(out, outlen, hx);
    printf("%zu %s\n", idx++, hx); free(hx);
  }
  free(buf); free(out); fclose(mf); fclose(bf);
  return t_done();
}
