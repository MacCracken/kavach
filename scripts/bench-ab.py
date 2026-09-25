#!/usr/bin/env python3
"""bench-ab.py — compare two builds of kavach's benchmarks, interleaved and pinned.

Usage:
  scripts/bench-ab.py <ref-a> <ref-b> [--rounds N] [--cpu C]

Each side is a git ref (a tag, a branch, a commit) or `.` for the working tree
as it is on disk, committed or not. A ref is checked out into a temporary
worktree, gets its own `cyrius deps`, and is removed afterwards.

Why this shape (3.12.9). On a host with frequency scaling, one unpinned run of
the exec benchmarks lands in one of two modes, so a release row read +24%
(3.12.7) or -19.9% (3.12.8) against the previous one with nothing changed on
that path. This runs both builds on the same CPU (`taskset -c`), alternating
A,B,B,A,... so drift over the run affects both sides alike, and reports per
benchmark the median, the range, and whether the two ranges overlap. Read an
overlapping pair as "no measured change", whatever the medians say.

Replaces the ad-hoc scripts used for the 3.12.6-3.12.8 comparisons.
"""
import argparse
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

UNIT = {"ns": 1.0, "us": 1e3, "µs": 1e3, "ms": 1e6, "s": 1e9}
LINE = re.compile(r"^\s+([a-z0-9_]+): ([0-9.]+)(ns|us|µs|ms|s) avg")


def run(cmd, cwd=None, **kw):
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, **kw)


def build(ref, root, scratch):
    """Build tests/kavach.bcyr for `ref`; return the binary's path."""
    if ref == ".":
        src = root
    else:
        src = os.path.join(scratch, "tree-" + re.sub(r"[^A-Za-z0-9._-]", "_", ref))
        run(["git", "worktree", "add", "--detach", src, ref], cwd=root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(["cyrius", "deps"], cwd=src, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = os.path.join(scratch, "bench-" + re.sub(r"[^A-Za-z0-9._-]", "_", ref))
    res = subprocess.run(["cyrius", "build", "tests/kavach.bcyr", out], cwd=src,
                         capture_output=True, text=True)
    if res.returncode != 0 or not os.path.exists(out):
        sys.exit(f"bench-ab: building {ref} failed:\n{res.stdout}{res.stderr}")
    return out, (src if ref != "." else None)


def sample(binary, cpu, cwd):
    """One run of the bench binary: {name: ns}."""
    out = subprocess.run(["taskset", "-c", str(cpu), binary], cwd=cwd,
                         capture_output=True, text=True).stdout
    got = {}
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            got[m.group(1)] = float(m.group(2)) * UNIT[m.group(3)]
    return got


def fmt(ns):
    if ns >= 1e6:
        return f"{ns / 1e6:.3f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.2f} µs"
    return f"{ns:.0f} ns"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--cpu", type=int, default=os.cpu_count() - 1)
    args = ap.parse_args()
    if shutil.which("taskset") is None:
        sys.exit("bench-ab: needs taskset (util-linux) to pin both builds to one CPU")

    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                          text=True, check=True).stdout.strip()
    scratch = tempfile.mkdtemp(prefix="kavach-bench-ab-")
    trees = []
    try:
        bin_a, tree = build(args.a, root, scratch)
        trees.append(tree)
        bin_b, tree = build(args.b, root, scratch)
        trees.append(tree)
        results = {args.a: {}, args.b: {}}
        for r in range(args.rounds):
            order = [(args.a, bin_a), (args.b, bin_b)]
            if r % 2 == 1:
                order.reverse()
            for label, binary in order:
                # From the repo root: some benchmarks write under /tmp and the
                # suite expects a cwd outside it.
                for name, ns in sample(binary, args.cpu, root).items():
                    results[label].setdefault(name, []).append(ns)
            print(f"round {r + 1}/{args.rounds} done", file=sys.stderr)

        print(f"{args.rounds} interleaved rounds per side, pinned to CPU {args.cpu}\n")
        print(f"| bench | {args.a} | {args.b} | Δ | ranges |")
        print("|---|---|---|---|---|")
        for name, xs in results[args.a].items():
            ys = results[args.b].get(name)
            if not ys:
                continue
            ma, mb = statistics.median(xs), statistics.median(ys)
            overlap = max(min(xs), min(ys)) <= min(max(xs), max(ys))
            note = "overlap" if overlap else "**separate**"
            print(f"| `{name}` | {fmt(ma)} | {fmt(mb)} | {(mb - ma) / ma * 100:+.1f}% | {note} |")
    finally:
        for tree in trees:
            if tree:
                subprocess.run(["git", "worktree", "remove", "--force", tree], cwd=root,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
