#include "t_common.h"
#include "spec_trace_data.h"

static void words_fill(uint32_t m[16], uint32_t w) { int i; for (i = 0; i < 16; i++) m[i] = w; }

int main(void) {
  static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint32_t out[16], trace[8][16], m[16] = {0x46544549}, h[8], kw[8], cv[2][8];
  unsigned char d[131], exp[131], key[32], msg[2048];
  int r, c, b;

  ref_compress(IV, m, 0, 4, REF_CHUNK_START | REF_CHUNK_END | REF_ROOT, out, trace);
  CHECK((REF_CHUNK_START | REF_CHUNK_END | REF_ROOT) == 0x0b);
  for (r = 0; r < 7; r++) CHECK_MEM(trace[r + 1], SPEC_IETF_ROUNDS[r], 64, "IETF round state");
  CHECK_MEM(out, SPEC_IETF_OUT, 32, "IETF compress output");

  memset(key, 0xcc, 32);
  for (r = 0; r < 8; r++) kw[r] = 0xccccccccu;
  for (c = 0; c < 2; c++) {
    memcpy(h, kw, 32);
    words_fill(m, c ? 0xbbbbbbbbu : 0xaaaaaaaau);
    for (b = 0; b < 16; b++) {
      uint32_t fl = REF_KEYED_HASH | (b == 0 ? REF_CHUNK_START : 0) | (b == 15 ? REF_CHUNK_END : 0);
      ref_compress(h, m, (uint64_t)c, 64, fl, out, NULL);
      memcpy(h, out, 32);
      CHECK_MEM(h, c ? SPEC_KEYED_C1[b] : SPEC_KEYED_C0[b], 32, "keyed block output");
    }
    memcpy(cv[c], h, 32);
  }
  CHECK(cv[0][0] == 0x29262c25 && cv[1][0] == 0xa1df18f4);
  memcpy(m, cv[0], 32); memcpy(m + 8, cv[1], 32);
  CHECK((REF_PARENT | REF_KEYED_HASH | REF_ROOT) == 0x1c);
  ref_compress(kw, m, 0, 64, 0x1c, out, NULL);
  CHECK_MEM(out, SPEC_KEYED_PARENT, 32, "parent output");

  CHECK(t_load()); t_check_impl();
  unhex("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2", exp);
  CHECK(t_digest((const unsigned char *)"IETF", 4, d, 32)); CHECK_MEM(d, exp, 32, "provider hash(IETF)");
  unhex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", exp);
  CHECK(t_digest((const unsigned char *)"", 0, d, 32)); CHECK_MEM(d, exp, 32, "provider hash(empty)");
  memset(msg, 0xaa, 1024); memset(msg + 1024, 0xbb, 1024);
  unhex("34afab3d37b3971642df4b84862c3dfa5c50d5351be79ce33bd924de559f8d05", exp);
  CHECK(t_mac(key, 32, msg, 2048, d, 32)); CHECK_MEM(d, exp, 32, "provider keyed_hash");
  printf("spec_traces: %d checks, %d failures\n", g_checks, g_fail);
  return t_done();
}
