#define _DEFAULT_SOURCE 1
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "b3_dispatch_ext.h"
#include "blake3.h"
#include "prov_common.h"

#if defined(_WIN32)
#include <windows.h>
void b3p_cleanse(void *p, size_t n) { SecureZeroMemory(p, n); }
#elif defined(__APPLE__)
void b3p_cleanse(void *p, size_t n) { memset_s(p, n, 0, n); }
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
void b3p_cleanse(void *p, size_t n) { explicit_bzero(p, n); }
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
void b3p_cleanse(void *p, size_t n) { explicit_bzero(p, n); }
#else
void b3p_cleanse(void *p, size_t n) {
  memset(p, 0, n);
  __asm__ __volatile__("" : : "r"(p) : "memory");
}
#endif

void b3p_raise(const B3P_PROV *prov, int reason, const char *file, int line,
               const char *func, const char *fmt, ...) {
  va_list ap;
  if (prov == NULL || prov->core_new_error == NULL ||
      prov->core_vset_error == NULL)
    return;
  prov->core_new_error(prov->handle);
  if (prov->core_set_error_debug != NULL)
    prov->core_set_error_debug(prov->handle, file, line, func);
  va_start(ap, fmt);
  prov->core_vset_error(prov->handle, (uint32_t)reason, fmt, ap);
  va_end(ap);
}

static const OSSL_ITEM reason_strings[] = {
    {B3P_R_ALLOC, "memory allocation failure"},
    {B3P_R_INVALID_KEY_LENGTH, "invalid key length (BLAKE3 keyed mode needs exactly 32 bytes)"},
    {B3P_R_MISSING_KEY, "missing key"},
    {B3P_R_MISSING_CONTEXT, "missing context string (info)"},
    {B3P_R_INVALID_OUTPUT_LENGTH, "invalid output length"},
    {B3P_R_OUTPUT_BUFFER_TOO_SMALL, "output buffer too small"},
    {B3P_R_UPDATE_AFTER_FINAL, "update after final or squeeze"},
    {B3P_R_FINAL_AFTER_FINAL, "final after final or squeeze"},
    {B3P_R_INVALID_PARAM, "invalid parameter"},
    {B3P_R_OUTPUT_TOO_LONG, "output exceeds 2^64-1 bytes"},
    {0, NULL}};

static const OSSL_ALGORITHM digests[] = {
    {"BLAKE3:BLAKE3-256", B3P_PROPS, b3p_digest_functions,
     "BLAKE3 extendable-output hash (default 256-bit)"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM macs[] = {
    {"BLAKE3:KEYED-BLAKE3", B3P_PROPS, b3p_mac_functions,
     "BLAKE3 keyed_hash"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM kdfs[] = {
    {"BLAKE3-KDF", B3P_PROPS, b3p_kdf_functions, "BLAKE3 derive_key"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM *b3p_query(void *provctx, int operation_id,
                                       int *no_cache) {
  (void)provctx;
  *no_cache = 0;
  switch (operation_id) {
  case OSSL_OP_DIGEST: return digests;
  case OSSL_OP_MAC: return macs;
  case OSSL_OP_KDF: return kdfs;
  }
  return NULL;
}

static const OSSL_PARAM b3p_gettable[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_utf8_ptr("blake3-impl", NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *b3p_gettable_params(void *provctx) {
  (void)provctx;
  return b3p_gettable;
}

static int b3p_get_params(void *provctx, OSSL_PARAM params[]) {
  const B3P_PROV *prov = (const B3P_PROV *)provctx;
  const char *impl = b3prov_dispatch_init();
  OSSL_PARAM *p;
  if ((p = b3p_param_locate(params, OSSL_PROV_PARAM_NAME)) != NULL &&
      !b3p_param_set_utf8(p, "OpenSSL BLAKE3 Provider"))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL &&
      !b3p_param_set_utf8(p, B3P_VERSION))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL &&
      !b3p_param_set_utf8(p, prov->buildinfo))
    return 0;
  if ((p = b3p_param_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL &&
      !b3p_param_set_int(p, 1))
    return 0;
  if ((p = b3p_param_locate(params, "blake3-impl")) != NULL &&
      !b3p_param_set_utf8(p, impl))
    return 0;
  return 1;
}

static const OSSL_ITEM *b3p_reason_strings(void *provctx) {
  (void)provctx;
  return reason_strings;
}

static void b3p_teardown(void *provctx) { free(provctx); }

static const OSSL_DISPATCH b3p_dispatch[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))b3p_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))b3p_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))b3p_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))b3p_query},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))b3p_reason_strings},
    {0, NULL}};

B3P_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                                  const OSSL_DISPATCH *in,
                                  const OSSL_DISPATCH **out, void **provctx) {
  B3P_PROV *prov = (B3P_PROV *)calloc(1, sizeof(*prov));
  if (prov == NULL) return 0;
  prov->handle = handle;
  for (; in != NULL && in->function_id != 0; in++) {
    switch (in->function_id) {
    case OSSL_FUNC_CORE_NEW_ERROR:
      prov->core_new_error = OSSL_FUNC_core_new_error(in);
      break;
    case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
      prov->core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
      break;
    case OSSL_FUNC_CORE_VSET_ERROR:
      prov->core_vset_error = OSSL_FUNC_core_vset_error(in);
      break;
    default:
      break;
    }
  }
  {
    const char *impl = b3prov_dispatch_init();
    const char *parts[] = {"blake3 ", BLAKE3_VERSION_STRING, " simd=", impl, NULL};
    size_t n = 0;
    int i;
    for (i = 0; parts[i] != NULL; i++) {
      size_t l = strlen(parts[i]);
      if (n + l >= sizeof(prov->buildinfo)) l = sizeof(prov->buildinfo) - 1 - n;
      memcpy(prov->buildinfo + n, parts[i], l);
      n += l;
    }
    prov->buildinfo[n] = '\0';
  }
  *provctx = prov;
  *out = b3p_dispatch;
  return 1;
}
