#include <stdlib.h>
#include <string.h>

#include "b3_dispatch_ext.h"
#include "blake3.h"
#include "prov_common.h"

typedef struct {
  const B3P_PROV *prov;
  blake3_hasher hasher;
  size_t xoflen;
  uint64_t squeeze_off;
  int state;
} B3_DIGEST_CTX;

static void *b3_digest_newctx(void *provctx) {
  B3_DIGEST_CTX *c;
  b3prov_dispatch_init();
  c = (B3_DIGEST_CTX *)calloc(1, sizeof(*c));
  if (c == NULL) {
    B3P_RAISE((const B3P_PROV *)provctx, B3P_R_ALLOC, "digest context");
    return NULL;
  }
  c->prov = (const B3P_PROV *)provctx;
  blake3_hasher_init(&c->hasher);
  c->xoflen = B3P_DEFAULT_OUTLEN;
  return c;
}

static void b3_digest_freectx(void *vctx) {
  if (vctx == NULL) return;
  b3p_cleanse(vctx, sizeof(B3_DIGEST_CTX));
  free(vctx);
}

static void b3_digest_copyctx(void *vout, void *vin) {
  memcpy(vout, vin, sizeof(B3_DIGEST_CTX));
}

static void *b3_digest_dupctx(void *vctx) {
  B3_DIGEST_CTX *in = (B3_DIGEST_CTX *)vctx, *c;
  if (in == NULL) return NULL;
  c = (B3_DIGEST_CTX *)malloc(sizeof(*c));
  if (c == NULL) {
    B3P_RAISE(in->prov, B3P_R_ALLOC, "digest context");
    return NULL;
  }
  b3_digest_copyctx(c, in);
  return c;
}

static int b3_digest_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  const OSSL_PARAM *p;
  size_t n;
  if (params == NULL) return 1;
  p = b3p_param_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
  if (p == NULL) p = b3p_param_locate_const(params, OSSL_DIGEST_PARAM_SIZE);
  if (p != NULL) {
    if (!b3p_param_get_size_t(p, &n)) {
      B3P_RAISE(c->prov, B3P_R_INVALID_PARAM, "xoflen");
      return 0;
    }
    c->xoflen = n;
  }
  return 1;
}

static int b3_digest_init(void *vctx, const OSSL_PARAM params[]) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  blake3_hasher_init(&c->hasher);
  c->xoflen = B3P_DEFAULT_OUTLEN;
  c->squeeze_off = 0;
  c->state = 0;
  return b3_digest_set_ctx_params(c, params);
}

static int b3_digest_update(void *vctx, const unsigned char *in, size_t inl) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  if (c->state != 0) {
    B3P_RAISE(c->prov, B3P_R_UPDATE_AFTER_FINAL, "digest");
    return 0;
  }
  blake3_hasher_update(&c->hasher, in, inl);
  return 1;
}

static int b3_digest_final(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsz) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  (void)outsz;
  if (c->state != 0) {
    B3P_RAISE(c->prov, B3P_R_FINAL_AFTER_FINAL, "digest");
    return 0;
  }
  c->state = 1;
  if (out != NULL) blake3_hasher_finalize(&c->hasher, out, c->xoflen);
  if (outl != NULL) *outl = c->xoflen;
  return 1;
}

static int b3_digest_squeeze(void *vctx, unsigned char *out, size_t *outl,
                             size_t outlen) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  if (c->state == 1) {
    B3P_RAISE(c->prov, B3P_R_FINAL_AFTER_FINAL, "squeeze after final");
    return 0;
  }
  if ((uint64_t)outlen > UINT64_MAX - c->squeeze_off) {
    B3P_RAISE(c->prov, B3P_R_OUTPUT_TOO_LONG, "squeeze");
    return 0;
  }
  c->state = 2;
  if (outlen > 0 && out != NULL) {
    blake3_hasher_finalize_seek(&c->hasher, c->squeeze_off, out, outlen);
    c->squeeze_off += outlen;
  }
  if (outl != NULL) *outl = outlen;
  return 1;
}

static int b3_digest_digest(void *provctx, const unsigned char *in, size_t inl,
                            unsigned char *out, size_t *outl, size_t outsz) {
  blake3_hasher h;
  (void)provctx;
  if (outsz < BLAKE3_OUT_LEN) return 0;
  b3prov_dispatch_init();
  blake3_hasher_init(&h);
  blake3_hasher_update(&h, in, inl);
  blake3_hasher_finalize(&h, out, BLAKE3_OUT_LEN);
  b3p_cleanse(&h, sizeof(h));
  if (outl != NULL) *outl = BLAKE3_OUT_LEN;
  return 1;
}

static int b3_digest_get_params(OSSL_PARAM params[]) {
  OSSL_PARAM *p;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, BLAKE3_BLOCK_LEN))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, BLAKE3_OUT_LEN))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_XOF)) != NULL &&
      !b3p_param_set_int(p, 1))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT)) != NULL &&
      !b3p_param_set_int(p, 1))
    return 0;
  return 1;
}

static const OSSL_PARAM digest_gettable[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL), OSSL_PARAM_END};

static const OSSL_PARAM *b3_digest_gettable_params(void *provctx) {
  (void)provctx;
  return digest_gettable;
}

static int b3_digest_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  B3_DIGEST_CTX *c = (B3_DIGEST_CTX *)vctx;
  OSSL_PARAM *p;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_XOFLEN)) != NULL &&
      !b3p_param_set_size_t(p, c->xoflen))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, c->xoflen))
    return 0;
  return 1;
}

static const OSSL_PARAM digest_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL), OSSL_PARAM_END};

static const OSSL_PARAM *b3_digest_settable_ctx_params(void *vctx,
                                                       void *provctx) {
  (void)vctx;
  (void)provctx;
  return digest_ctx_settable;
}

#define FN(x) ((void (*)(void))(x))
const OSSL_DISPATCH b3p_digest_functions[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, FN(b3_digest_newctx)},
    {OSSL_FUNC_DIGEST_INIT, FN(b3_digest_init)},
    {OSSL_FUNC_DIGEST_UPDATE, FN(b3_digest_update)},
    {OSSL_FUNC_DIGEST_FINAL, FN(b3_digest_final)},
    {OSSL_FUNC_DIGEST_SQUEEZE, FN(b3_digest_squeeze)},
    {OSSL_FUNC_DIGEST_DIGEST, FN(b3_digest_digest)},
    {OSSL_FUNC_DIGEST_FREECTX, FN(b3_digest_freectx)},
    {OSSL_FUNC_DIGEST_DUPCTX, FN(b3_digest_dupctx)},
#ifdef OSSL_FUNC_DIGEST_COPYCTX
    {OSSL_FUNC_DIGEST_COPYCTX, FN(b3_digest_copyctx)},
#endif
    {OSSL_FUNC_DIGEST_GET_PARAMS, FN(b3_digest_get_params)},
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, FN(b3_digest_gettable_params)},
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, FN(b3_digest_set_ctx_params)},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, FN(b3_digest_settable_ctx_params)},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, FN(b3_digest_get_ctx_params)},
    {0, NULL}};
