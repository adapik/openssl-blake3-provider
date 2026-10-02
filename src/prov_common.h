#ifndef B3P_COMMON_H
#define B3P_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "prov_params.h"

#if defined(_WIN32)
#define B3P_EXPORT __declspec(dllexport)
#else
#define B3P_EXPORT __attribute__((visibility("default")))
#endif

#define B3P_VERSION "0.1.0"
#define B3P_PROPS "provider=blake3,fips=no"
#define B3P_DEFAULT_OUTLEN 32

enum {
  B3P_R_ALLOC = 1,
  B3P_R_INVALID_KEY_LENGTH,
  B3P_R_MISSING_KEY,
  B3P_R_MISSING_CONTEXT,
  B3P_R_INVALID_OUTPUT_LENGTH,
  B3P_R_OUTPUT_BUFFER_TOO_SMALL,
  B3P_R_UPDATE_AFTER_FINAL,
  B3P_R_FINAL_AFTER_FINAL,
  B3P_R_INVALID_PARAM,
  B3P_R_OUTPUT_TOO_LONG
};

typedef struct b3p_prov_st {
  const OSSL_CORE_HANDLE *handle;
  OSSL_FUNC_core_new_error_fn *core_new_error;
  OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
  OSSL_FUNC_core_vset_error_fn *core_vset_error;
  char buildinfo[96];
} B3P_PROV;

void b3p_raise(const B3P_PROV *prov, int reason, const char *file, int line,
               const char *func, const char *fmt, ...);
#define B3P_RAISE(prov, reason, ...) \
  b3p_raise((prov), (reason), __FILE__, __LINE__, __func__, __VA_ARGS__)

void b3p_cleanse(void *p, size_t n);

extern const OSSL_DISPATCH b3p_digest_functions[];
extern const OSSL_DISPATCH b3p_mac_functions[];
extern const OSSL_DISPATCH b3p_kdf_functions[];

#endif
