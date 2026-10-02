#include <stdlib.h>
#include <string.h>

#include "b3_dispatch_ext.h"
#include "blake3.h"
#include "prov_common.h"

typedef struct {
  const B3P_PROV *prov;
  blake3_hasher hasher;
  unsigned char key[BLAKE3_KEY_LEN];
  size_t outlen;
  int have_key;
  int finalized;
} B3_MAC_CTX;

static void *b3_mac_newctx(void *provctx) {
  B3_MAC_CTX *c;
  b3prov_dispatch_init();
  c = (B3_MAC_CTX *)calloc(1, sizeof(*c));
  if (c == NULL) {
    B3P_RAISE((const B3P_PROV *)provctx, B3P_R_ALLOC, "mac context");
    return NULL;
  }
  c->prov = (const B3P_PROV *)provctx;
  c->outlen = B3P_DEFAULT_OUTLEN;
  return c;
}

static void b3_mac_freectx(void *vctx) {
  if (vctx == NULL) return;
  b3p_cleanse(vctx, sizeof(B3_MAC_CTX));
  free(vctx);
}

static void *b3_mac_dupctx(void *vctx) {
  B3_MAC_CTX *in = (B3_MAC_CTX *)vctx, *c;
  if (in == NULL) return NULL;
  c = (B3_MAC_CTX *)malloc(sizeof(*c));
  if (c == NULL) {
    B3P_RAISE(in->prov, B3P_R_ALLOC, "mac context");
    return NULL;
  }
  memcpy(c, in, sizeof(*c));
  return c;
}

static int b3_mac_set_key(B3_MAC_CTX *c, const unsigned char *key, size_t len) {
  if (len != BLAKE3_KEY_LEN) {
    B3P_RAISE(c->prov, B3P_R_INVALID_KEY_LENGTH, "got %zu bytes", len);
    return 0;
  }
  memcpy(c->key, key, len);
  c->have_key = 1;
  return 1;
}

static int b3_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  B3_MAC_CTX *c = (B3_MAC_CTX *)vctx;
  const OSSL_PARAM *p;
  if (params == NULL) return 1;
  if ((p = b3p_param_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
    const unsigned char *k;
    size_t kl;
    if (!b3p_param_get_octets(p, &k, &kl)) {
      B3P_RAISE(c->prov, B3P_R_INVALID_PARAM, "key");
      return 0;
    }
    if (!b3_mac_set_key(c, k, kl)) return 0;
  }
  if ((p = b3p_param_locate_const(params, OSSL_MAC_PARAM_SIZE)) != NULL) {
    size_t n;
    if (!b3p_param_get_size_t(p, &n) || n < 1) {
      B3P_RAISE(c->prov, B3P_R_INVALID_OUTPUT_LENGTH, "size must be >= 1");
      return 0;
    }
    c->outlen = n;
  }
  if ((p = b3p_param_locate_const(params, OSSL_MAC_PARAM_XOF)) != NULL) {
    int v;
    if (!b3p_param_get_int(p, &v)) {
      B3P_RAISE(c->prov, B3P_R_INVALID_PARAM, "xof");
      return 0;
    }
  }
  return 1;
}

static int b3_mac_init(void *vctx, const unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[]) {
  B3_MAC_CTX *c = (B3_MAC_CTX *)vctx;
  if (key != NULL && !b3_mac_set_key(c, key, keylen)) return 0;
  if (!b3_mac_set_ctx_params(c, params)) return 0;
  if (!c->have_key) {
    B3P_RAISE(c->prov, B3P_R_MISSING_KEY, "keyed BLAKE3 needs a 32-byte key");
    return 0;
  }
  blake3_hasher_init_keyed(&c->hasher, c->key);
  c->finalized = 0;
  return 1;
}

static int b3_mac_update(void *vctx, const unsigned char *in, size_t inl) {
  B3_MAC_CTX *c = (B3_MAC_CTX *)vctx;
  if (!c->have_key || c->finalized) {
    B3P_RAISE(c->prov, c->have_key ? B3P_R_UPDATE_AFTER_FINAL : B3P_R_MISSING_KEY,
              "mac update");
    return 0;
  }
  blake3_hasher_update(&c->hasher, in, inl);
  return 1;
}

static int b3_mac_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize) {
  B3_MAC_CTX *c = (B3_MAC_CTX *)vctx;
  if (!c->have_key || c->finalized) {
    B3P_RAISE(c->prov, c->have_key ? B3P_R_FINAL_AFTER_FINAL : B3P_R_MISSING_KEY,
              "mac final");
    return 0;
  }
  if (out == NULL) {
    if (outl != NULL) *outl = c->outlen;
    return 1;
  }
  if (outsize < c->outlen) {
    B3P_RAISE(c->prov, B3P_R_OUTPUT_BUFFER_TOO_SMALL, "need %zu, have %zu",
              c->outlen, outsize);
    return 0;
  }
  c->finalized = 1;
  blake3_hasher_finalize(&c->hasher, out, c->outlen);
  if (outl != NULL) *outl = c->outlen;
  return 1;
}

static int b3_mac_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  B3_MAC_CTX *c = (B3_MAC_CTX *)vctx;
  OSSL_PARAM *p;
  if ((p = b3p_param_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, c->outlen))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, BLAKE3_BLOCK_LEN))
    return 0;
  return 1;
}

static int b3_mac_get_params(OSSL_PARAM params[]) {
  OSSL_PARAM *p;
  if ((p = b3p_param_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, BLAKE3_OUT_LEN))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL &&
      !b3p_param_set_size_t(p, BLAKE3_BLOCK_LEN))
    return 0;
  return 1;
}

static const OSSL_PARAM mac_gettable[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL), OSSL_PARAM_END};
static const OSSL_PARAM *b3_mac_gettable_params(void *provctx) {
  (void)provctx;
  return mac_gettable;
}
static const OSSL_PARAM *b3_mac_gettable_ctx_params(void *vctx, void *provctx) {
  (void)vctx;
  (void)provctx;
  return mac_gettable;
}

static const OSSL_PARAM mac_settable[] = {
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL), OSSL_PARAM_END};
static const OSSL_PARAM *b3_mac_settable_ctx_params(void *vctx, void *provctx) {
  (void)vctx;
  (void)provctx;
  return mac_settable;
}

#define FN(x) ((void (*)(void))(x))
const OSSL_DISPATCH b3p_mac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, FN(b3_mac_newctx)},
    {OSSL_FUNC_MAC_DUPCTX, FN(b3_mac_dupctx)},
    {OSSL_FUNC_MAC_FREECTX, FN(b3_mac_freectx)},
    {OSSL_FUNC_MAC_INIT, FN(b3_mac_init)},
    {OSSL_FUNC_MAC_UPDATE, FN(b3_mac_update)},
    {OSSL_FUNC_MAC_FINAL, FN(b3_mac_final)},
    {OSSL_FUNC_MAC_GET_PARAMS, FN(b3_mac_get_params)},
    {OSSL_FUNC_MAC_GETTABLE_PARAMS, FN(b3_mac_gettable_params)},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, FN(b3_mac_get_ctx_params)},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, FN(b3_mac_gettable_ctx_params)},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, FN(b3_mac_set_ctx_params)},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, FN(b3_mac_settable_ctx_params)},
    {0, NULL}};
