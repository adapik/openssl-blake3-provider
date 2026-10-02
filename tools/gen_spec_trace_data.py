#!/usr/bin/env python3
import re, sys
t = open(sys.argv[1]).read()
ietf = t[t.index("COMPRESS: CHUNK  1, BLOCK  0"):t.index("### `keyed_hash`")]
rounds = re.findall(r"after round (\d):\n((?: [0-9a-f]{8}.*\n)+)", ietf)
       'static const uint32_t SPEC_IETF_ROUNDS[7][16] = {']
for r, body in rounds:
    w = body.split(); assert len(w) == 16
    out.append("  {" + ", ".join("0x" + x for x in w) + "},")
out.append("};")
m = re.search(r"compress output:\n ((?:[0-9a-f]{8} ?){8})", ietf).group(1).split()
out.append("static const uint32_t SPEC_IETF_OUT[8] = {" + ", ".join("0x" + x for x in m) + "};")
keyed = t[t.index("### `keyed_hash` of Multiple"):]
outs = {}
for mm in re.finditer(r"== COMPRESS: (CHUNK +(\d+), BLOCK +(\d+)|PARENT) ==.*?compress output:\n ((?:[0-9a-f]{8} ?){8})", keyed, re.S):
    key = (int(mm.group(2)), int(mm.group(3))) if mm.group(2) else "P"
    outs[key] = mm.group(4).split()
assert len(outs) == 33
for c in (0, 1):
    out.append("static const uint32_t SPEC_KEYED_C%d[16][8] = {" % c)
    for b in range(16):
        out.append("  {" + ", ".join("0x" + x for x in outs[(c, b)]) + "},")
    out.append("};")
out.append("static const uint32_t SPEC_KEYED_PARENT[8] = {" + ", ".join("0x" + x for x in outs["P"]) + "};")
open("test/spec_trace_data.h", "w").write("\n".join(out) + "\n")
