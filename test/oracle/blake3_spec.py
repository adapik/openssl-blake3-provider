#!/usr/bin/env python3
import struct, sys, json

M = 0xFFFFFFFF
IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 0x10, 0x20, 0x40

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M

def g(v, a, b, c, d, mx, my):
    v[a] = (v[a] + v[b] + mx) & M
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & M
    v[b] = rotr(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + my) & M
    v[d] = rotr(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & M
    v[b] = rotr(v[b] ^ v[c], 7)

def round_fn(v, m):
    g(v, 0, 4, 8, 12, m[0], m[1])
    g(v, 1, 5, 9, 13, m[2], m[3])
    g(v, 2, 6, 10, 14, m[4], m[5])
    g(v, 3, 7, 11, 15, m[6], m[7])
    g(v, 0, 5, 10, 15, m[8], m[9])
    g(v, 1, 6, 11, 12, m[10], m[11])
    g(v, 2, 7, 8, 13, m[12], m[13])
    g(v, 3, 4, 9, 14, m[14], m[15])

def compress(h, m, t, blen, flags, trace=None):
    v = list(h) + IV[:4] + [t & M, (t >> 32) & M, blen, flags]
    m = list(m)
    if trace is not None:
        trace.append(list(v))
    for r in range(7):
        round_fn(v, m)
        if trace is not None:
            trace.append(list(v))
        if r < 6:
            m = [m[p] for p in PERM]
    for i in range(8):
        v[i] ^= v[i + 8]
        v[i + 8] ^= h[i]
    return v

def words(b):
    b = b + b"\0" * (64 - len(b))
    return list(struct.unpack("<16I", b))

def chunk_output(key, chunk, counter, base_flags):
    h = list(key)
    n = max(1, (len(chunk) + 63) // 64)
    for i in range(n):
        blk = chunk[i * 64:(i + 1) * 64]
        fl = base_flags
        if i == 0:
            fl |= CHUNK_START
        if i == n - 1:
            fl |= CHUNK_END
            return (h, words(blk), counter, len(blk), fl)
        h = compress(h, words(blk), counter, 64, fl)[:8]

def cv(out):
    return compress(*out)[:8]

def parent_output(key, l, r, base_flags):
    return (list(key), l + r, 0, 64, base_flags | PARENT)

def root_node(key, data, base_flags):
    chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)] or [b""]
    def sub(lo, hi):
        if hi - lo == 1:
            return chunk_output(key, chunks[lo], lo, base_flags)
        n = hi - lo
        p = 1
        while p * 2 < n:
            p *= 2
        return parent_output(key, cv(sub(lo, lo + p)), cv(sub(lo + p, hi)), base_flags)
    return sub(0, len(chunks))

def xof(node, n):
    h, m, _, blen, fl = node
    out = b""
    t = 0
    while len(out) < n:
        out += struct.pack("<16I", *compress(h, m, t, blen, fl | ROOT))
        t += 1
    return out[:n]

def hash_(data, n=32):
    return xof(root_node(IV, data, 0), n)

def keyed_hash(key, data, n=32):
    assert len(key) == 32
    return xof(root_node(struct.unpack("<8I", key), data, KEYED_HASH), n)

def derive_key(context, material, n=32):
    ck = xof(root_node(IV, context, DERIVE_KEY_CONTEXT), 32)
    return xof(root_node(struct.unpack("<8I", ck), material, DERIVE_KEY_MATERIAL), n)

def selftest(vectors_path=None):
    assert hash_(b"IETF").hex() == "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2"
    assert hash_(b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    k = bytes([0xcc]) * 32
    msg = bytes([0xaa]) * 1024 + bytes([0xbb]) * 1024
    assert keyed_hash(k, msg).hex() == "34afab3d37b3971642df4b84862c3dfa5c50d5351be79ce33bd924de559f8d05"
    kw = struct.unpack("<8I", k)
    c0 = cv(chunk_output(kw, msg[:1024], 0, KEYED_HASH))
    c1 = cv(chunk_output(kw, msg[1024:], 1, KEYED_HASH))
    assert c0[0] == 0x29262c25
    assert c1[0] == 0xa1df18f4
    assert parent_output(kw, c0, c1, KEYED_HASH)[4] | ROOT == 0x1c
    if vectors_path:
        tv = json.load(open(vectors_path))
        key = tv["key"].encode()
        ctx = tv["context_string"].encode()
        for c in tv["cases"]:
            d = bytes(i % 251 for i in range(c["input_len"]))
            for name, fn in (("hash", lambda: hash_(d, 131)),
                             ("keyed_hash", lambda: keyed_hash(key, d, 131)),
                             ("derive_key", lambda: derive_key(ctx, d, 131))):
                assert fn().hex() == c[name], (name, c["input_len"])
        print("vectors ok:", len(tv["cases"]))
    print("selftest ok")

if __name__ == "__main__":
    selftest(sys.argv[1] if len(sys.argv) > 1 else None)
