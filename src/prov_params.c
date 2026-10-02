#include <string.h>

#include "prov_params.h"

OSSL_PARAM *b3p_param_locate(OSSL_PARAM *params, const char *key) {
  if (params != NULL && key != NULL)
    for (; params->key != NULL; params++)
      if (strcmp(key, params->key) == 0) return params;
  return NULL;
}

const OSSL_PARAM *b3p_param_locate_const(const OSSL_PARAM *params,
                                         const char *key) {
  return b3p_param_locate((OSSL_PARAM *)params, key);
}

static int read_u64(const OSSL_PARAM *p, uint64_t *out) {
  const unsigned char *d;
  if (p == NULL || p->data == NULL) return 0;
  if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER &&
      p->data_type != OSSL_PARAM_INTEGER)
    return 0;
  d = (const unsigned char *)p->data;
  switch (p->data_size) {
  case 1: *out = *d; break;
  case 2: { uint16_t v; memcpy(&v, d, 2); *out = v; break; }
  case 4: { uint32_t v; memcpy(&v, d, 4); *out = v; break; }
  case 8: { uint64_t v; memcpy(&v, d, 8); *out = v; break; }
  default: return 0;
  }
  if (p->data_type == OSSL_PARAM_INTEGER) {
    int64_t sv;
    switch (p->data_size) {
    case 1: sv = (int8_t)*out; break;
    case 2: sv = (int16_t)*out; break;
    case 4: sv = (int32_t)*out; break;
    default: sv = (int64_t)*out; break;
    }
    if (sv < 0) return 0;
  }
  return 1;
}

int b3p_param_get_size_t(const OSSL_PARAM *p, size_t *out) {
  uint64_t v;
  if (!read_u64(p, &v)) return 0;
  if (v > (uint64_t)SIZE_MAX) return 0;
  *out = (size_t)v;
  return 1;
}

int b3p_param_get_int(const OSSL_PARAM *p, int *out) {
  uint64_t v;
  if (!read_u64(p, &v) || v > 0x7fffffffu) return 0;
  *out = (int)v;
  return 1;
}

int b3p_param_get_octets(const OSSL_PARAM *p, const unsigned char **data,
                         size_t *len) {
  if (p == NULL) return 0;
  switch (p->data_type) {
  case OSSL_PARAM_OCTET_STRING:
  case OSSL_PARAM_UTF8_STRING:
    *data = (const unsigned char *)p->data;
    *len = p->data_size;
    return p->data != NULL || p->data_size == 0;
  case OSSL_PARAM_OCTET_PTR:
  case OSSL_PARAM_UTF8_PTR:
    if (p->data == NULL) return 0;
    memcpy(data, p->data, sizeof(*data));
    *len = p->data_size;
    return 1;
  default:
    return 0;
  }
}

static int write_u64(OSSL_PARAM *p, uint64_t v) {
  p->return_size = 0;
  if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER &&
      p->data_type != OSSL_PARAM_INTEGER)
    return 0;
  if (p->data == NULL) {
    p->return_size = sizeof(uint64_t);
    return 1;
  }
  switch (p->data_size) {
  case 4: {
    uint32_t t;
    if (v > 0xffffffffu) return 0;
    if (p->data_type == OSSL_PARAM_INTEGER && v > 0x7fffffffu) return 0;
    t = (uint32_t)v;
    memcpy(p->data, &t, 4);
    break;
  }
  case 8:
    if (p->data_type == OSSL_PARAM_INTEGER && v > INT64_MAX) return 0;
    memcpy(p->data, &v, 8);
    break;
  default:
    return 0;
  }
  p->return_size = p->data_size;
  return 1;
}

int b3p_param_set_size_t(OSSL_PARAM *p, size_t val) {
  return p != NULL && write_u64(p, (uint64_t)val);
}

int b3p_param_set_int(OSSL_PARAM *p, int val) {
  if (p == NULL || val < 0) return 0;
  return write_u64(p, (uint64_t)val);
}

int b3p_param_set_utf8(OSSL_PARAM *p, const char *val) {
  size_t n;
  if (p == NULL || val == NULL) return 0;
  n = strlen(val);
  p->return_size = n;
  if (p->data_type == OSSL_PARAM_UTF8_PTR) {
    if (p->data == NULL) return 1;
    memcpy(p->data, &val, sizeof(val));
    return 1;
  }
  if (p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
  if (p->data == NULL) return 1;
  if (p->data_size < n + 1) return 0;
  memcpy(p->data, val, n + 1);
  return 1;
}
