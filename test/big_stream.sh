#!/bin/sh
set -eu
OSSL=$1; export OPENSSL_MODULES=$2; B3SUM=$3; EXTRA=${4:-4097}
gen() { python3 - "$EXTRA" <<'PY'
import sys
extra=int(sys.argv[1]); total=(1<<32)+extra
blk=bytes(i%251 for i in range(251*4096))
out=sys.stdout.buffer; left=total
while left>=len(blk): out.write(blk); left-=len(blk)
out.write(blk[:left])
PY
}
a=$(gen | "$OSSL" dgst -provider blake3 -provider default -BLAKE3 -r | cut -d' ' -f1)
b=$(gen | "$B3SUM" --no-names)
echo "provider: $a"; echo "b3sum:    $b"
[ "$a" = "$b" ] && echo "big stream: OK" || { echo "big stream: MISMATCH"; exit 1; }
