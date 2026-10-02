#include <stdlib.h>
#include <string.h>

#include "b3_dispatch_ext.h"
#include "blake3.h"
#include "prov_common.h"

typedef struct {
  const B3P_PROV *prov;
  unsigned char *key;
  size_t keylen;
  int have_key;
  unsigned char *info;
  size_t infolen;
  int have_info;
} B3_KDF_CTX;

static void b3_kdf_clear(B3_KDF_CTX *c) {
  if (c->key != NULL) {
    b3p_cleanse(c->key, c->keylen);
    free(c->key);
  }
  if (c->info != NULL) {
    b3p_cleanse(c->info, c->infolen);
    free(c->info);
  }
  c->key = c->info = NULL;
  c->keylen = c->infolen = 0;
  c->have_key = c->have_info = 0;
}

static void *b3_kdf_newctx(void *provctx) {
  B3_KDF_CTX *c;
  b3prov_dispatch_init();
  c = (B3_KDF_CTX *)calloc(1, sizeof(*c));
  if (c == NULL) {
    B3P_RAISE((const B3P_PROV *)provctx, B3P_R_ALLOC, "kdf context");
    return NULL;
  }
  c->prov = (const B3P_PROV *)provctx;
  return c;
}

static void b3_kdf_freectx(void *vctx) {
  B3_KDF_CTX *c = (B3_KDF_CTX *)vctx;
  if (c == NULL) return;
  b3_kdf_clear(c);
  b3p_cleanse(c, sizeof(*c));
  free(c);
}

static void b3_kdf_reset(void *vctx) {
  B3_KDF_CTX *c = (B3_KDF_CTX *)vctx;
  const B3P_PROV *prov = c->prov;
  b3_kdf_clear(c);
  c->prov = prov;
}

static unsigned char *dup_buf(const unsigned char *src, size_t n) {
  unsigned char *d = (unsigned char *)malloc(n > 0 ? n : 1);
  if (d != NULL && n > 0) memcpy(d, src, n);
  return d;
}

static void *b3_kdf_dupctx(void *vctx) {
  B3_KDF_CTX *in = (B3_KDF_CTX *)vctx, *c;
  if (in == NULL) return NULL;
  c = (B3_KDF_CTX *)calloc(1, sizeof(*c));
  if (c == NULL) goto err;
  c->prov = in->prov;
  if (in->have_key) {
    if ((c->key = dup_buf(in->key, in->keylen)) == NULL) goto err;
    c->keylen = in->keylen;
    c->have_key = 1;
  }
  if (in->have_info) {
    if ((c->info = dup_buf(in->info, in->infolen)) == NULL) goto err;
    c->infolen = in->infolen;
    c->have_info = 1;
  }
  return c;
err:
  B3P_RAISE(in->prov, B3P_R_ALLOC, "kdf context");
  if (c != NULL) b3_kdf_freectx(c);
  return NULL;
}

static int set_buf(B3_KDF_CTX *c, const OSSL_PARAM *p, unsigned char **dst,
                   size_t *dstlen, int *have) {
  const unsigned char *d;
  size_t l;
  unsigned char *copy;
  if (!b3p_param_get_octets(p, &d, &l)) {
    B3P_RAISE(c->prov, B3P_R_INVALID_PARAM, "%s", p->key);
    return 0;
  }
  if ((copy = dup_buf(d, l)) == NULL) {
    B3P_RAISE(c->prov, B3P_R_ALLOC, "kdf parameter");
    return 0;
  }
  if (*dst != NULL) {
    b3p_cleanse(*dst, *dstlen);
    free(*dst);
  }
  *dst = copy;
  *dstlen = l;
  *have = 1;
  return 1;
}

static int b3_kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  B3_KDF_CTX *c = (B3_KDF_CTX *)vctx;
  const OSSL_PARAM *p;
  if (params == NULL) return 1;
  if ((p = b3p_param_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL &&
      !set_buf(c, p, &c->key, &c->keylen, &c->have_key))
    return 0;
  if ((p = b3p_param_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL &&
      !set_buf(c, p, &c->info, &c->infolen, &c->have_info))
    return 0;
  if ((p = b3p_param_locate_const(params, "context")) != NULL &&
      !set_buf(c, p, &c->info, &c->infolen, &c->have_info))
    return 0;
  return 1;
}

static int b3_kdf_derive(void *vctx, unsigned char *out, size_t outlen,
                         const OSSL_PARAM params[]) {
  B3_KDF_CTX *c = (B3_KDF_CTX *)vctx;
  blake3_hasher h;
  if (!b3_kdf_set_ctx_params(c, params)) return 0;
  if (!c->have_info) {
    B3P_RAISE(c->prov, B3P_R_MISSING_CONTEXT, "set \"info\" (BLAKE3 derive_key context)");
    return 0;
  }
  if (!c->have_key) {
    B3P_RAISE(c->prov, B3P_R_MISSING_KEY, "set \"key\" (key material)");
    return 0;
  }
  if (out == NULL || outlen == 0) {
    B3P_RAISE(c->prov, B3P_R_INVALID_OUTPUT_LENGTH, "derive");
    return 0;
  }
  blake3_hasher_init_derive_key_raw(&h, c->info, c->infolen);
  blake3_hasher_update(&h, c->key, c->keylen);
  blake3_hasher_finalize(&h, out, outlen);
  b3p_cleanse(&h, sizeof(h));
  return 1;
}

static int b3_kdf_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  OSSL_PARAM *p;
  (void)vctx;
  if ((p = b3p_param_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, SIZE_MAX))
    return 0;
  return 1;
}

static const OSSL_PARAM kdf_gettable[] = {
    OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL), OSSL_PARAM_END};
static const OSSL_PARAM *b3_kdf_gettable_ctx_params(void *vctx, void *provctx) {
  (void)vctx;
  (void)provctx;
  return kdf_gettable;
}

static const OSSL_PARAM kdf_settable[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
    OSSL_PARAM_octet_string("context", NULL, 0), OSSL_PARAM_END};
static const OSSL_PARAM *b3_kdf_settable_ctx_params(void *vctx, void *provctx) {
  (void)vctx;
  (void)provctx;
  return kdf_settable;
}

#define FN(x) ((void (*)(void))(x))
const OSSL_DISPATCH b3p_kdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, FN(b3_kdf_newctx)},
    {OSSL_FUNC_KDF_DUPCTX, FN(b3_kdf_dupctx)},
    {OSSL_FUNC_KDF_FREECTX, FN(b3_kdf_freectx)},
    {OSSL_FUNC_KDF_RESET, FN(b3_kdf_reset)},
    {OSSL_FUNC_KDF_DERIVE, FN(b3_kdf_derive)},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, FN(b3_kdf_gettable_ctx_params)},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, FN(b3_kdf_get_ctx_params)},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, FN(b3_kdf_settable_ctx_params)},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, FN(b3_kdf_set_ctx_params)},
    {0, NULL}};
