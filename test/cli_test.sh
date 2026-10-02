#!/bin/sh
set -u
OSSL=$1; MOD=$2; HERE=$(cd "$(dirname "$0")" && pwd); CONF=${3:-$HERE/../conf/openssl-blake3.cnf.example}
export OPENSSL_MODULES=$(dirname "$MOD")
ORACLE="$HERE/oracle"; fail=0
ok()  { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; fail=1; }
eq()  { [ "$2" = "$3" ] && ok "$1" || { bad "$1"; echo "   got:  $2"; echo "   want: $3"; }; }
orc() { python3 -c "import sys;sys.path.insert(0,'$ORACLE');import blake3_spec as b;$1"; }
P="-provider blake3 -provider default"

"$OSSL" version
"$OSSL" list -providers $P | grep -q "OpenSSL BLAKE3 Provider" && ok "provider listed" || bad "provider listed"
"$OSSL" list -digest-algorithms -provider blake3 | grep -q "BLAKE3.*@ blake3" && ok "digest listed" || bad "digest listed"
"$OSSL" list -mac-algorithms $P | grep -q "BLAKE3" && ok "mac listed" || bad "mac listed"
"$OSSL" list -kdf-algorithms $P | grep -q "BLAKE3-KDF" && ok "kdf listed" || bad "kdf listed"
"$OSSL" list -digest-algorithms -provider default | grep -qi blake3 && bad "default provider has no BLAKE3" || ok "default provider has no BLAKE3"

got=$(printf IETF | "$OSSL" dgst $P -BLAKE3 -r | cut -d' ' -f1)
eq "dgst IETF" "$got" 83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2
got=$(printf IETF | "$OSSL" dgst $P -BLAKE3 -xoflen 131 -r | cut -d' ' -f1)
eq "dgst IETF xoflen 131" "$got" "$(orc "print(b.hash_(b'IETF',131).hex())")"
got=$(printf '' | "$OSSL" dgst $P -BLAKE3 -r | cut -d' ' -f1)
eq "dgst empty" "$got" af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262

KEY=$(python3 -c "print('cc'*32)"); T=$(mktemp); head -c 2048 /dev/zero | tr '\0' '\252' >"$T"
got=$("$OSSL" mac $P -macopt hexkey:$KEY -in "$T" BLAKE3 | tr 'A-F' 'a-f')
eq "mac keyed (2048xaa)" "$got" "$(orc "print(b.keyed_hash(bytes([0xcc])*32,bytes([0xaa])*2048).hex())")"
got=$("$OSSL" mac $P -macopt hexkey:$KEY -macopt size:77 -in "$T" BLAKE3 | tr 'A-F' 'a-f')
eq "mac keyed size 77" "$got" "$(orc "print(b.keyed_hash(bytes([0xcc])*32,bytes([0xaa])*2048,77).hex())")"
"$OSSL" mac $P -macopt hexkey:cccc -in "$T" BLAKE3 >/dev/null 2>&1 && bad "mac rejects 2-byte key" || ok "mac rejects 2-byte key"
got=$("$OSSL" kdf $P -keylen 64 -kdfopt hexkey:00112233 -kdfopt info:myapp-2026 BLAKE3-KDF | tr -d ':' | tr 'A-F' 'a-f')
eq "kdf derive 64" "$got" "$(orc "print(b.derive_key(b'myapp-2026',bytes.fromhex('00112233'),64).hex())")"
"$OSSL" kdf $P -keylen 64 -kdfopt hexkey:00112233 BLAKE3-KDF >/dev/null 2>&1 && bad "kdf rejects missing info" || ok "kdf rejects missing info"
rm -f "$T"

got=$(printf IETF | OPENSSL_CONF=$CONF "$OSSL" dgst -BLAKE3 -r | cut -d' ' -f1)
eq "config-only load" "$got" 83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2

"$OSSL" dgst -provider blake3 -provider default -propquery provider=blake3 -BLAKE3 /dev/null >/dev/null 2>&1 && ok "propquery provider=blake3" || bad "propquery provider=blake3"
"$OSSL" dgst $P -propquery fips=yes -BLAKE3 /dev/null >/dev/null 2>&1 && bad "fips=yes must not fetch BLAKE3" || ok "fips=yes must not fetch BLAKE3"

for impl in portable sse2 sse41 avx2 avx512 neon; do
  r=$(BLAKE3_PROV_FORCE_IMPL=$impl "$OSSL" list -providers -verbose -provider blake3 | sed -n 's/.*build info: blake3 [0-9.]* simd=//p')
  echo "info - force $impl -> backend ${r:-?}"
done

case $(uname) in
Linux) ldd "$MOD" | grep -Eq 'libcrypto|libssl' && bad "no libcrypto/libssl dependency" || ok "no libcrypto/libssl dependency"
       syms=$(nm -D --defined-only "$MOD" | awk '{print $3}' | tr '\n' ' ')
       eq "exports only OSSL_provider_init" "$syms" "OSSL_provider_init " ;;
Darwin) otool -L "$MOD" | grep -Eq 'libcrypto|libssl' && bad "no libcrypto/libssl dependency" || ok "no libcrypto/libssl dependency"
       syms=$(nm -gU "$MOD" | awk '{print $3}' | tr '\n' ' ')
       eq "exports only OSSL_provider_init" "$syms" "_OSSL_provider_init " ;;
esac

"$OSSL" speed $P -seconds 1 -evp BLAKE3 >/dev/null 2>&1 && ok "openssl speed -evp BLAKE3" || bad "openssl speed -evp BLAKE3"
[ $fail = 0 ] && echo "CLI: all passed" || echo "CLI: FAILURES"
exit $fail
