#!/usr/bin/env python3
"""check-symbols.py — guard kavach's names in cyrius's flat namespace.

Cyrius has one global symbol table and last-definition-wins. The compiler warns on
a duplicate `fn` and is SILENT on a duplicate `var` or enum member, and an enum's
qualifier is cosmetic (`InjectionMethod.STDIN` is just `STDIN`). So a name kavach
shares with any other module in a build resolves by source order, with no
diagnostic when it is a constant. That is how `InjectionMethod.STDIN` (2) became
the stdlib's `var STDIN = 0` in a consumer (CHANGELOG 3.12.9) and how
`BACKEND_COUNT` became ai-hwaccel's (3.11.15).

Rules, over the modules of kavach's `[lib]` bundle (cyrius.cyml) against every
module in lib/ (what `cyrius deps` vendored: the stdlib snapshot, sigil, samay,
ai-hwaccel):

  1. No name is defined twice inside kavach, in any kind: fn, var, enum member,
     or struct accessor (`#derive(accessors)` generates `Struct_field` and
     `Struct_set_field`).
  2. No fn or accessor name is shared with lib/. The compiler would only warn,
     and one of the two bodies would silently serve both callers.
  3. No constant (var or enum member) is shared with lib/ at a different value.
     Shared constants at an EQUAL literal value (errno numbers, which the stdlib
     and sigil also define) are reported, not failed.

Code under `#ifdef CYRIUS_TARGET_MACOS` / `CYRIUS_TARGET_WIN` is skipped, and so
are the macOS / Windows-only stdlib peers: kavach does not build for either.
Every other conditional is read with both arms, which can only over-report.

Known exceptions go in scripts/symbol-allow.txt, one name per line, each with a
`#` comment saying why it is safe. Empty at 3.12.9.

  --tree DIR   also report (never fail on) names kavach shares with the dist/
               bundles of sibling repos under DIR, e.g. `--tree ..`: the
               libraries a consumer may compile next to kavach.

Exits 1 on any violation. Run from the repo root after `cyrius deps`.
"""
import glob
import os
import re
import sys
from collections import defaultdict

SKIP_SYMBOLS = {"CYRIUS_TARGET_MACOS", "CYRIUS_TARGET_WIN"}
SKIP_FILES = re.compile(r"_(macos|win|windows)\.cyr$")

FN = re.compile(r"^fn\s+([A-Za-z_]\w*)\s*\(")
VAR = re.compile(r"^var\s+([A-Za-z_]\w*)(?:\s*=\s*([^;]+);)?")
ENUM = re.compile(r"^enum\s+\w+\s*\{(.*)$")
STRUCT = re.compile(r"^struct\s+(\w+)\s*\{")
MEMBER = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:=\s*([^;]+))?;")
FIELD = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^;]*)?;")
IFDEF = re.compile(r"^\s*#(ifdef|ifndef)\s+(\w+)")
ELSE = re.compile(r"^\s*#(else|elif)\b")
ENDIF = re.compile(r"^\s*#endif\b")


def strip_comment(line):
    out, quoted = [], False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        if ch == "#" and not quoted:
            break
        out.append(ch)
    return "".join(out)


def live_lines(path):
    """(lineno, text) for every line outside a skipped platform block."""
    stack = []  # one entry per open conditional: True when this arm is skipped
    for lineno, raw in enumerate(open(path, errors="replace"), 1):
        raw = raw.rstrip("\n")
        m = IFDEF.match(raw)
        if m:
            kind, sym = m.groups()
            stack.append(kind == "ifdef" and sym in SKIP_SYMBOLS)
            continue
        if ELSE.match(raw):
            # The other arm of a skipped `#ifdef MACOS` is the non-macOS code:
            # keep it. Every other conditional keeps both arms.
            if stack:
                stack[-1] = False
            continue
        if ENDIF.match(raw):
            if stack:
                stack.pop()
            continue
        if any(stack):
            continue
        yield lineno, raw


def norm(value):
    return None if value is None else re.sub(r"\s+", "", value)


def int_literal(value):
    """The integer a literal spells (decimal or 0x hex), or None."""
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def definitions(path):
    """[(name, kind, lineno, value)] for the top-level definitions in `path`."""
    out = []
    lines = list(live_lines(path))
    i, derive = 0, False
    while i < len(lines):
        lineno, raw = lines[i]
        if raw.startswith("#derive(accessors)"):
            derive = True
            i += 1
            continue
        text = strip_comment(raw)
        m = FN.match(text)
        if m:
            out.append((m.group(1), "fn", lineno, None))
            derive = False
            i += 1
            continue
        m = VAR.match(text)
        if m:
            value = norm(m.group(2))
            lit = int_literal(value)
            out.append((m.group(1), "var", lineno, value if lit is None else str(lit)))
            derive = False
            i += 1
            continue
        m = ENUM.match(text)
        if m:
            rest = m.group(1)
            members = []  # (name, lineno, explicit value or None)
            if "}" in rest:  # one-line enum
                for part in rest.split("}")[0].split(";"):
                    mm = re.match(r"\s*([A-Za-z_]\w*)\s*(?:=\s*(.+))?$", part)
                    if mm and mm.group(1):
                        members.append((mm.group(1), lineno, norm(mm.group(2))))
                i += 1
            else:
                i += 1
                while i < len(lines) and "}" not in strip_comment(lines[i][1]):
                    mm = MEMBER.match(strip_comment(lines[i][1]))
                    if mm:
                        members.append((mm.group(1), lines[i][0], norm(mm.group(2))))
                    i += 1
                i += 1
            # An implicit member is the previous value + 1, from 0 (the guide's
            # `enum Color { RED; GREEN; BLUE; }` is 0/1/2). After an explicit value
            # that is not an integer literal, the numbering is unknown (None).
            nxt = 0
            for name, ln, explicit in members:
                value = explicit if explicit is not None else (None if nxt is None else str(nxt))
                lit = int_literal(value)
                nxt = None if lit is None else lit + 1
                out.append((name, "enum", ln, value if lit is None else str(lit)))
            derive = False
            continue
        m = STRUCT.match(text)
        if m:
            name, fields = m.group(1), []
            i += 1
            while i < len(lines) and "}" not in strip_comment(lines[i][1]):
                mf = FIELD.match(strip_comment(lines[i][1]))
                if mf:
                    fields.append(mf.group(1))
                i += 1
            if derive:
                for f in fields:
                    out.append((f"{name}_{f}", "accessor", lineno, None))
                    out.append((f"{name}_set_{f}", "accessor", lineno, None))
            derive = False
            i += 1
            continue
        if text.strip():
            derive = False
        i += 1
    return out


def lib_modules(manifest="cyrius.cyml"):
    text = strip_comment_block(open(manifest).read())
    m = re.search(r"^\[lib\]\s*$(.*?)^\[", text, re.M | re.S)
    if not m:
        sys.exit("check-symbols: no [lib] section in cyrius.cyml")
    return re.findall(r'"([^"]+\.cyr)"', m.group(1))


def strip_comment_block(text):
    return "\n".join(strip_comment(line) for line in text.split("\n"))


def load_allow(path="scripts/symbol-allow.txt"):
    allow = set()
    if os.path.exists(path):
        for line in open(path):
            name = line.split("#", 1)[0].strip()
            if name:
                allow.add(name)
    return allow


def collect(paths):
    table = defaultdict(list)
    for p in paths:
        for name, kind, lineno, value in definitions(p):
            table[name].append((p, kind, lineno, value))
    return table


def main(argv):
    tree = None
    if "--tree" in argv:
        tree = argv[argv.index("--tree") + 1]

    kavach = collect(lib_modules())
    libs = sorted(p for p in glob.glob("lib/*.cyr") if not SKIP_FILES.search(p))
    if not libs:
        sys.exit("check-symbols: lib/ is empty; run `cyrius deps` first")
    lib = collect(libs)
    allow = load_allow()

    failures, equal = [], []

    # Rule 1: duplicates inside kavach.
    for name, sites in sorted(kavach.items()):
        if len(sites) > 1 and name not in allow:
            where = ", ".join(f"{p}:{n} ({k})" for p, k, n, _ in sites)
            failures.append(f"defined {len(sites)} times in kavach: {name} — {where}")

    # Rules 2 and 3: shared with lib/.
    for name, sites in sorted(kavach.items()):
        if name not in lib or name in allow:
            continue
        mine = sites[0]
        theirs = lib[name]
        kinds = {k for _, k, _, _ in sites} | {k for _, k, _, _ in theirs}
        where = ", ".join(sorted({f"{p}:{n}" for p, _, n, _ in theirs}))
        if kinds & {"fn", "accessor"}:
            failures.append(f"fn shared with lib/: {name} ({mine[0]}:{mine[2]}) — also {where}")
            continue
        values = {v for _, _, _, v in sites} | {v for _, _, _, v in theirs}
        if None in values or len(values) > 1:
            shown = ", ".join(sorted(str(v) for v in values))
            failures.append(f"constant shared with lib/ at different values: {name} = {{{shown}}} "
                            f"({mine[0]}:{mine[2]}) — also {where}")
        else:
            equal.append(name)

    if equal:
        print(f"check-symbols: {len(equal)} constants shared with lib/ at equal values "
              f"(allowed): {' '.join(equal)}")

    if tree:
        others = defaultdict(set)
        for p in sorted(glob.glob(os.path.join(tree, "*", "dist", "*.cyr"))):
            repo = p.split(os.sep)[-3]
            if repo == "kavach":
                continue
            for name, kind, _, value in definitions(p):
                others[name].add((repo, kind, value))
        shared = [(n, sorted(others[n])) for n in sorted(kavach) if n in others]
        print(f"check-symbols: {len(shared)} kavach names also defined by sibling dist/ bundles "
              f"under {tree} (report only):")
        for name, where in shared:
            v = {x for _, _, x in where} | {x for _, _, _, x in kavach[name]}
            flag = "  ⚠ values differ" if len(v) > 1 or None in v and kavach[name][0][1] != "fn" else ""
            print(f"  {name}: {', '.join(f'{r} ({k})' for r, k, _ in where)}{flag}")

    if failures:
        print(f"check-symbols: {len(failures)} violation(s)")
        for f in failures:
            print("  " + f)
        return 1
    print(f"check-symbols: ok — {len(kavach)} kavach names, {len(libs)} lib/ modules")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
