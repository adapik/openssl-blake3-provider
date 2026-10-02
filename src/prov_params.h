#ifndef B3P_PARAMS_H
#define B3P_PARAMS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

OSSL_PARAM *b3p_param_locate(OSSL_PARAM *params, const char *key);
const OSSL_PARAM *b3p_param_locate_const(const OSSL_PARAM *params,
                                         const char *key);

int b3p_param_get_size_t(const OSSL_PARAM *p, size_t *out);
int b3p_param_get_int(const OSSL_PARAM *p, int *out);
int b3p_param_get_octets(const OSSL_PARAM *p, const unsigned char **data,
                         size_t *len);

int b3p_param_set_size_t(OSSL_PARAM *p, size_t val);
int b3p_param_set_int(OSSL_PARAM *p, int val);
int b3p_param_set_utf8(OSSL_PARAM *p, const char *val);

#endif
