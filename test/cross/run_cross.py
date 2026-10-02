#!/usr/bin/env python3
import argparse, os, random, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "oracle"))
import blake3_spec

SPECIAL_LENS = [0, 1, 2, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073,
                4095, 4096, 4097, 8192, 8193, 16384, 16385, 31744, 32768, 65536, 65537, 131072, 262144]
SPECIAL_OUT = [1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 131, 1000]
ALPHABET = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 .-_:/ äöüß€漢字🙂"

def gen(n, seed, outdir):
    r = random.Random(seed)
    cases = []
    blob = open(os.path.join(outdir, "blob.bin"), "wb")
    off = 0
    for i in range(n):
        mode = r.choice(["hash", "keyed", "derive"])
        if i < len(SPECIAL_LENS) * 3:
            ln = SPECIAL_LENS[i // 3]
        else:
            x = r.random()
            ln = r.randint(0, 2048) if x < 0.34 else r.randint(0, 32768) if x < 0.67 else r.randint(0, 262144)
        outlen = r.choice(SPECIAL_OUT) if r.random() < 0.25 else r.randint(1, 1000)
        key = r.randbytes(32)
        ctx = "".join(r.choice(ALPHABET) for _ in range(r.randint(0, 60))).encode()
        data = r.randbytes(ln)
        blob.write(data)
        cases.append(dict(mode=mode, len=ln, key=key, ctx=ctx, outlen=outlen, off=off, data=None))
        off += ln
    blob.close()
    with open(os.path.join(outdir, "manifest.tsv"), "w") as m:
        for c in cases:
            m.write("%s\t%d\t%s\t%s\t%d\t%d\n" % (c["mode"], c["len"], c["key"].hex() if c["mode"] == "keyed" else "-",
                                                 c["ctx"].hex() if c["ctx"] else "-", c["outlen"], c["off"]))
    return cases

def read_data(blobpath):
    f = open(blobpath, "rb")
    def get(c):
        f.seek(c["off"]); return f.read(c["len"])
    return get

def run_lines(cmd, env=None):
    t = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit("command failed (%s): %s\n%s" % (p.returncode, cmd, p.stderr[-2000:]))
    res = {}
    for ln in p.stdout.splitlines():
        a, b = ln.split(" ")
        res[int(a)] = b
    return res, time.time() - t, p.stderr.strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--eval-provider", required=True, help="built eval_provider binary")
    ap.add_argument("--module-dir", required=True)
    ap.add_argument("--openssl", help="openssl CLI for the CLI subset")
    ap.add_argument("--cli-cases", type=int, default=300)
    ap.add_argument("--b3sum"); ap.add_argument("--rust-ref"); ap.add_argument("--go-ref")
    ap.add_argument("--oracle-cases", type=int, default=500)
    ap.add_argument("--backends", default="auto,portable,sse2,sse41,avx2,avx512,neon")
    ap.add_argument("--workdir", default=tempfile.mkdtemp(prefix="b3cross_"))
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)
    print("workdir:", a.workdir)
    cases = gen(a.cases, a.seed, a.workdir)
    man, blob = os.path.join(a.workdir, "manifest.tsv"), os.path.join(a.workdir, "blob.bin")
    get = read_data(blob)
    n = len(cases)
    bad = 0

    def compare(name, res, ref, ids=None):
        nonlocal bad
        ids = range(n) if ids is None else ids
        mism = [i for i in ids if res.get(i) != ref[i]]
        print("%-28s %6d cases, %d mismatches" % (name, len(list(ids)), len(mism)))
        for i in mism[:5]:
            c = cases[i]
            print("   MISMATCH case %d mode=%s len=%d outlen=%d\n     ref: %s\n     got: %s" % (i, c["mode"], c["len"], c["outlen"], ref[i][:64], str(res.get(i))[:64]))
        bad += len(mism)

    import blake3 as pyb3
    pyres = {}
    for i, c in enumerate(cases):
        d = get(c)
        if c["mode"] == "hash": h = pyb3.blake3(d)
        elif c["mode"] == "keyed": h = pyb3.blake3(d, key=c["key"])
        else: h = pyb3.blake3(d, derive_key_context=c["ctx"].decode())
        pyres[i] = h.digest(length=c["outlen"]).hex()
    print("python blake3 %s computed" % getattr(pyb3, "__version__", ""))

    seen = set()
    for be in a.backends.split(","):
        env = dict(os.environ, B3_MODULE_DIR=a.module_dir)
        if be != "auto": env["BLAKE3_PROV_FORCE_IMPL"] = be
        res, dt, err = run_lines([a.eval_provider, man, blob], env)
        actual = err.split(":")[-1].strip()
        if be != "auto" and actual != be:
            print("%-28s skipped (requested %s, CPU/build gave %s)" % ("provider[%s]" % be, be, actual)); continue
        if actual in seen and be == "auto":
            pass
        seen.add(actual)
        compare("provider EVP [%s]%s" % (be, " (=%s)" % actual if be == "auto" else ""), res, pyres)
        print("   (%.1fs)" % dt)

    if a.b3sum:
        res = {}
        tmp = os.path.join(a.workdir, "one.bin")
        for i, c in enumerate(cases):
            open(tmp, "wb").write(get(c))
            cmd = [a.b3sum, "--no-names", "--length", str(c["outlen"])]
            if c["mode"] == "keyed": cmd += ["--keyed"]
            if c["mode"] == "derive": cmd += ["--derive-key=" + c["ctx"].decode()]
            p = subprocess.run(cmd + [tmp], input=c["key"] if c["mode"] == "keyed" else None, capture_output=True)
            if p.returncode: sys.exit("b3sum failed on case %d: %s" % (i, p.stderr))
            res[i] = p.stdout.decode().strip()
        compare("b3sum", res, pyres)
    if a.rust_ref:
        res, dt, _ = run_lines([a.rust_ref, man, blob]); compare("rust reference_impl", res, pyres)
    if a.go_ref:
        res, dt, _ = run_lines([a.go_ref, man, blob]); compare("go lukechampine/blake3", res, pyres)
    m = min(a.oracle_cases, n); res = {}
    t = time.time()
    for i in range(m):
        c = cases[i]; d = get(c)
        if c["mode"] == "hash": o = blake3_spec.hash_(d, c["outlen"])
        elif c["mode"] == "keyed": o = blake3_spec.keyed_hash(c["key"], d, c["outlen"])
        else: o = blake3_spec.derive_key(c["ctx"], d, c["outlen"])
        res[i] = o.hex()
    compare("blake3_spec.py oracle", res, pyres, range(m)); print("   (%.0fs)" % (time.time() - t))
    if a.openssl:
        res, ids = {}, []
        env = dict(os.environ, OPENSSL_MODULES=a.module_dir)
        tmp = os.path.join(a.workdir, "cli.bin")
        P = ["-provider", "blake3", "-provider", "default"]
        for i, c in enumerate(cases[:a.cli_cases * 4]):
            if len(ids) >= a.cli_cases: break
            if c["mode"] == "derive" and (c["len"] == 0 or not c["ctx"] or c["len"] > 32768): continue
            open(tmp, "wb").write(get(c))
            if c["mode"] == "hash":
                cmd = [a.openssl, "dgst"] + P + ["-BLAKE3", "-xoflen", str(c["outlen"]), "-r", tmp]
            elif c["mode"] == "keyed":
                cmd = [a.openssl, "mac"] + P + ["-macopt", "hexkey:" + c["key"].hex(), "-macopt", "size:%d" % c["outlen"], "-in", tmp, "BLAKE3"]
            else:
                cmd = [a.openssl, "kdf"] + P + ["-keylen", str(c["outlen"]), "-kdfopt", "hexkey:" + get(c).hex(), "-kdfopt", "hexinfo:" + c["ctx"].hex(), "BLAKE3-KDF"]
            p = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if p.returncode: sys.exit("openssl CLI failed on case %d: %s" % (i, p.stderr))
            out = p.stdout.strip()
            res[i] = out.split()[0].lower() if c["mode"] == "hash" else out.replace(":", "").lower()
            ids.append(i)
        compare("openssl CLI", res, pyres, ids)
    print("TOTAL MISMATCHES:", bad)
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
