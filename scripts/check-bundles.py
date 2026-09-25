#!/usr/bin/env python3
"""check-bundles.py: every dist bundle compiles for a consumer (3.13.0).

A consumer includes `dist/<bundle>.cyr` and vendors only the stdlib leaves its
`.deps` sidecar lists. CI's freshness gate proves the bundles match the source;
it does not prove they compile that way. Twice a bundle did not: the confine
bundle shipped 3.12.4 and 3.12.5 unable to compile (CHANGELOG 3.12.6), and a
3.13.0 draft called `is_digit_c`, which lives in a module `[lib.confine]` does
not carry.

For each bundle this builds a throwaway project that declares the sidecar's
leaves, includes them and the bundle, and has an empty `main`. It fails on a
failed build and on any `undefined function` warning, reachable or not: cyrius
refuses to emit a binary only for a reachable one, and a consumer's own code
decides what is reachable.

Run from the repo root after `cyrius distlib --all`. Exit 0 when every bundle
compiles, 1 otherwise.
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pin():
    with open(os.path.join(ROOT, "cyrius.cyml")) as f:
        m = re.search(r'^cyrius\s*=\s*"([^"]+)"', f.read(), re.M)
    if not m:
        sys.exit("check-bundles: no cyrius pin in cyrius.cyml")
    return m.group(1)


def leaves(deps_path):
    with open(deps_path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def check(bundle, version):
    deps = bundle[:-len(".cyr")] + ".deps"
    if not os.path.exists(deps):
        return [f"{bundle}: no sidecar {deps}"]
    mods = leaves(deps)
    with tempfile.TemporaryDirectory(prefix="kavach-bundle-") as tmp:
        shutil.copy(bundle, tmp)
        with open(os.path.join(tmp, "cyrius.cyml"), "w") as f:
            f.write('[package]\nname = "bundle-consumer"\nversion = "0.0.1"\n')
            f.write(f'cyrius = "{version}"\n\n[build]\nentry = "main.cyr"\n')
            f.write('output = "consumer"\n\n[deps]\nstdlib = [\n')
            f.write("".join(f'    "{m}",\n' for m in mods))
            f.write("]\n")
        with open(os.path.join(tmp, "main.cyr"), "w") as f:
            f.write("".join(f'include "lib/{m}.cyr"\n' for m in mods))
            f.write(f'include "{os.path.basename(bundle)}"\n\n')
            f.write("fn main() {\n    alloc_init();\n    return 0;\n}\n")
            f.write("var r = main();\nsys_exit(r);\n")
        d = subprocess.run(["cyrius", "deps"], cwd=tmp, capture_output=True, text=True)
        if d.returncode != 0:
            return [f"{bundle}: cyrius deps failed\n{d.stdout}{d.stderr}"]
        b = subprocess.run(["cyrius", "build", "main.cyr", "consumer"], cwd=tmp,
                           capture_output=True, text=True)
        out = b.stdout + b.stderr
        bad = sorted(set(re.findall(r"undefined function '([^']+)'", out)))
        errs = []
        if bad:
            errs.append(f"{bundle}: undefined with only its sidecar's stdlib: {', '.join(bad)}")
        if b.returncode != 0:
            errs.append(f"{bundle}: build failed\n{out[-2000:]}")
        return errs


def main():
    os.chdir(ROOT)
    version = pin()
    bundles = sorted(glob.glob("dist/*.cyr"))
    if not bundles:
        sys.exit("check-bundles: no dist/*.cyr; run `cyrius distlib --all` first")
    errs = []
    for bundle in bundles:
        errs += check(bundle, version)
    if errs:
        print("\n".join(errs))
        return 1
    print(f"check-bundles: ok — {len(bundles)} bundles compile with only their sidecar's stdlib")
    return 0


if __name__ == "__main__":
    sys.exit(main())
