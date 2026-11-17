#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
"""Coverage gate for rxenstored: applies the reviewed exclusions to the
reports of cargo-llvm-cov, prints per-file line and region coverage and
checks each crate against its threshold.

  covgate.py markers
      Checks every exclusion marker in crates/*/src against
      docs/coverage-exclusions.md, and the reverse. Exit 1 on any mismatch.

  covgate.py report CRATE JSON LCOV_IN LCOV_OUT [--lines PCT] [--regions PCT]
      JSON and LCOV_IN are `cargo llvm-cov report --json` / `--lcov` output
      for CRATE. Writes LCOV_OUT with the excluded lines removed. Exit 1 if
      a given threshold is not met.

Exclusions (listed in docs/coverage-exclusions.md):
  - `// cov:excl-line ID` excludes the line it ends;
  - `// cov:excl-start ID` ... `// cov:excl-stop ID` excludes both marker
    lines and everything between them;
  - code under `#[cfg(test)]` is the tests themselves and is not measured
    (rule `test-code` in the exclusions file).
A region is excluded only if every line it spans is excluded.

Uses only the Python standard library.
"""

import json
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXCLUSIONS = os.path.join(ROOT, "docs", "coverage-exclusions.md")
MARKER = re.compile(r"//\s*cov:excl-(line|start|stop)\b\s*([A-Za-z0-9_-]*)")
ROW = re.compile(r"^\|\s*`([a-z0-9][a-z0-9-]*)`\s*\|\s*`([^`]+)`\s*\|(.*)\|\s*$")
RULES = {"test-code"}


def rel(path):
    return os.path.relpath(path, ROOT)


def read_entries():
    """Id -> (file, reason) from the exclusions file."""
    entries, problems = {}, []
    with open(EXCLUSIONS, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            m = ROW.match(line.strip())
            if not m:
                continue
            ident, path, reason = m.group(1), m.group(2), m.group(3).strip()
            if ident in entries:
                problems.append(f"{rel(EXCLUSIONS)}:{n}: duplicate id `{ident}`")
            if not reason:
                problems.append(f"{rel(EXCLUSIONS)}:{n}: `{ident}` has no reason")
            entries[ident] = (path, reason)
    return entries, problems


def source_files():
    crates = os.path.join(ROOT, "crates")
    for crate in sorted(os.listdir(crates)):
        src = os.path.join(crates, crate, "src")
        for d, _, files in os.walk(src):
            for name in sorted(files):
                if name.endswith(".rs"):
                    yield os.path.join(d, name)


def scan_markers(path):
    """Excluded line ranges of one file: [(id, first, last)], plus problems."""
    ranges, problems, open_ = [], [], None
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    for n, text in enumerate(lines, 1):
        for m in MARKER.finditer(text):
            kind, ident = m.group(1), m.group(2)
            where = f"{rel(path)}:{n}"
            if not ident:
                problems.append(f"{where}: cov:excl-{kind} without an id")
                continue
            if kind == "line":
                ranges.append((ident, n, n))
            elif kind == "start":
                if open_:
                    problems.append(f"{where}: cov:excl-start {ident} inside {open_[0]} (line {open_[1]})")
                open_ = (ident, n)
            else:
                if not open_ or open_[0] != ident:
                    problems.append(f"{where}: cov:excl-stop {ident} without a matching start")
                else:
                    ranges.append((ident, open_[1], n))
                open_ = None
    if open_:
        problems.append(f"{rel(path)}:{open_[1]}: cov:excl-start {open_[0]} is never stopped")
    return ranges, problems


def check_markers():
    entries, problems = read_entries()
    seen = {}
    for path in source_files():
        ranges, p = scan_markers(path)
        problems += p
        for ident, first, _ in ranges:
            where = f"{rel(path)}:{first}"
            if ident in RULES:
                problems.append(f"{where}: `{ident}` is a rule, not a marker id")
            elif ident not in entries:
                problems.append(f"{where}: marker `{ident}` has no entry in {rel(EXCLUSIONS)}")
            elif entries[ident][0] != rel(path):
                problems.append(f"{where}: marker `{ident}` is listed for {entries[ident][0]}")
            elif ident in seen:
                problems.append(f"{where}: marker `{ident}` already used at {seen[ident]}")
            seen.setdefault(ident, where)
    for ident in entries:
        if ident not in seen and ident not in RULES:
            problems.append(f"{rel(EXCLUSIONS)}: `{ident}` is listed but no marker uses it")
    return entries, seen, problems


def test_code(path):
    """Line ranges under #[cfg(test)], and files that are #[cfg(test)] modules."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    ranges, files = [], []
    i = 0
    while i < len(lines):
        if lines[i].strip() != "#[cfg(test)]":
            i += 1
            continue
        indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
        j = i + 1
        while j < len(lines) and (lines[j].strip().startswith("#[") or lines[j].strip().startswith("//")):
            j += 1
        if j == len(lines):
            break
        item = lines[j].strip()
        m = re.fullmatch(r"(pub(\([^)]*\))?\s+)?mod\s+(\w+)\s*;", item)
        if m:
            d, base = os.path.split(path)
            if base not in ("lib.rs", "main.rs", "mod.rs"):
                d = os.path.join(d, base[:-3])
            for cand in (os.path.join(d, m.group(3) + ".rs"), os.path.join(d, m.group(3), "mod.rs")):
                if os.path.exists(cand):
                    files.append(os.path.normpath(cand))
            ranges.append((i + 1, j + 1))
            i = j + 1
            continue
        if item.endswith(";") or (item.endswith("}") and "{" in item):
            ranges.append((i + 1, j + 1))
            i = j + 1
            continue
        k = j + 1
        while k < len(lines) and not lines[k].startswith(indent + "}"):
            k += 1
        ranges.append((i + 1, k + 1))
        i = k + 1
    return ranges, files


def pct(covered, total):
    """Rounded down, so that 99.999% never prints as 100.00%."""
    return 100.0 if total == 0 else math.floor(covered * 10000 / total) / 100


def compress(nums):
    out, start, prev = [], None, None
    for n in sorted(nums):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f"{start}" if start == prev else f"{start}-{prev}")
            start = prev = n
    if start is not None:
        out.append(f"{start}" if start == prev else f"{start}-{prev}")
    return out


def report(crate, json_path, lcov_in, lcov_out, gate_lines, gate_regions):
    src = os.path.join(ROOT, "crates", crate, "src") + os.sep
    entries, _, problems = check_markers()
    if problems:
        for p in problems:
            print(f"  exclusion error: {p}")
        return 1

    excluded, marker_ranges, test_files = {}, {}, set()
    for path in source_files():
        if not path.startswith(src):
            continue
        ranges, _ = scan_markers(path)
        tranges, tfiles = test_code(path)
        test_files.update(tfiles)
        marker_ranges[path] = ranges
        s = excluded.setdefault(path, set())
        for _, a, b in ranges:
            s.update(range(a, b + 1))
        for a, b in tranges:
            s.update(range(a, b + 1))

    def wanted(path):
        return path.startswith(src) and path not in test_files

    # Lines, from lcov.
    lines = {}
    with open(lcov_in, encoding="utf-8") as f:
        sf = None
        for raw in f:
            raw = raw.strip()
            if raw.startswith("SF:"):
                sf = os.path.normpath(raw[3:])
            elif raw.startswith("DA:") and sf and wanted(sf):
                n, count = raw[3:].split(",")[:2]
                d = lines.setdefault(sf, {})
                d[int(n)] = max(d.get(int(n), 0), int(count))

    # Regions, from the JSON export. Instantiations of one generic function
    # share their spans; a span is covered if any instantiation ran it.
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)["data"][0]
    regions = {}
    for fn in data["functions"]:
        for r in fn["regions"]:
            l0, c0, l1, c1, count, file_id, _, kind = r[:8]
            path = os.path.normpath(fn["filenames"][file_id])
            if kind != 0 or not wanted(path):
                continue
            d = regions.setdefault(path, {})
            key = (l0, c0, l1, c1)
            d[key] = d.get(key, False) or count > 0

    files = sorted(set(lines) | set(regions))
    tot = [0, 0, 0, 0]
    rows, gaps, stale = [], [], []
    for path in files:
        ex = excluded.get(path, set())
        la = {n: c for n, c in lines.get(path, {}).items() if n not in ex}
        ra = {k: c for k, c in regions.get(path, {}).items() if not all(n in ex for n in range(k[0], k[2] + 1))}
        lc, lt = sum(1 for c in la.values() if c > 0), len(la)
        rc, rt = sum(1 for c in ra.values() if c), len(ra)
        tot = [tot[0] + lc, tot[1] + lt, tot[2] + rc, tot[3] + rt]
        rows.append((rel(path), lc, lt, rc, rt))
        missed_lines = [n for n, c in la.items() if c == 0]
        missed_regions = sorted(k for k, c in ra.items() if not c)
        if missed_lines or missed_regions:
            gaps.append((rel(path), missed_lines, missed_regions))
        # An exclusion whose code is all executed is stale.
        for ident, a, b in marker_ranges.get(path, []):
            span = range(a, b + 1)
            ls = [lines.get(path, {}).get(n) for n in span if n in lines.get(path, {})]
            rs = [c for k, c in regions.get(path, {}).items() if all(n in span for n in range(k[0], k[2] + 1))]
            if (ls or rs) and all(c and c > 0 for c in ls) and all(rs):
                stale.append(f"{rel(path)}:{a}: exclusion `{ident}` covers only executed code")

    width = max([len(r[0]) for r in rows] + [20])
    print(f"  {'file':<{width}}  {'lines':>15}  {'regions':>15}")
    for name, lc, lt, rc, rt in rows:
        print(f"  {name:<{width}}  {lc:>5}/{lt:<5}{pct(lc, lt):>6.2f}%  {rc:>5}/{rt:<5}{pct(rc, rt):>6.2f}%")
    print(f"  {crate + ' total':<{width}}  {tot[0]:>5}/{tot[1]:<5}{pct(tot[0], tot[1]):>6.2f}%  {tot[2]:>5}/{tot[3]:<5}{pct(tot[2], tot[3]):>6.2f}%")
    n_marks = sum(len(r) for r in marker_ranges.values())
    print(f"  excluded: {n_marks} marker(s), {len(test_files)} test module file(s) and #[cfg(test)] code")
    for name, ml, mr in gaps:
        if ml:
            print(f"  uncovered lines   {name}: {', '.join(compress(ml))}")
        if mr:
            print(f"  uncovered regions {name}: {', '.join(f'{a}:{b}-{c}:{d}' for a, b, c, d in mr)}")
    for s in stale:
        print(f"  note: {s}")

    with open(lcov_in, encoding="utf-8") as f, open(lcov_out, "w", encoding="utf-8") as out:
        sf, keep, hit, found = None, True, 0, 0
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("SF:"):
                sf = os.path.normpath(line[3:])
                keep, hit, found = wanted(sf), 0, 0
            if not keep:
                continue
            if line.startswith("DA:"):
                n, count = line[3:].split(",")[:2]
                if int(n) in excluded.get(sf, set()):
                    continue
                found += 1
                hit += int(count) > 0
            elif line.startswith("LF:"):
                line = f"LF:{found}"
            elif line.startswith("LH:"):
                line = f"LH:{hit}"
            out.write(line + "\n")

    failed = []
    if gate_lines is not None and tot[0] * 100 < gate_lines * tot[1]:
        failed.append(f"lines {pct(tot[0], tot[1]):.2f}% < {gate_lines:g}%")
    if gate_regions is not None and tot[2] * 100 < gate_regions * tot[3]:
        failed.append(f"regions {pct(tot[2], tot[3]):.2f}% < {gate_regions:g}%")
    gate = []
    if gate_lines is not None:
        gate.append(f"lines >= {gate_lines:g}%")
    if gate_regions is not None:
        gate.append(f"regions >= {gate_regions:g}%")
    if not gate:
        print(f"  gate: none ({crate} is not gated)")
    elif failed:
        print(f"  gate {', '.join(gate)}: FAIL ({'; '.join(failed)})")
    else:
        print(f"  gate {', '.join(gate)}: pass")
    print(f"  summary {crate} lines {tot[0]}/{tot[1]} {pct(tot[0], tot[1]):.2f}% regions {tot[2]}/{tot[3]} {pct(tot[2], tot[3]):.2f}% {'FAIL' if failed else 'ok'}")
    return 1 if failed else 0


def main(argv):
    if len(argv) >= 1 and argv[0] == "markers":
        entries, seen, problems = check_markers()
        for p in problems:
            print(f"exclusion error: {p}")
        if not problems:
            print(f"exclusions: {len(seen)} marker(s), all listed in {rel(EXCLUSIONS)}")
        return 1 if problems else 0
    if len(argv) >= 5 and argv[0] == "report":
        crate, js, lin, lout = argv[1:5]
        opts = {"--lines": None, "--regions": None}
        rest = argv[5:]
        while rest:
            if rest[0] not in opts or len(rest) < 2:
                print(f"covgate: bad option {rest[0]}", file=sys.stderr)
                return 2
            opts[rest[0]] = float(rest[1])
            rest = rest[2:]
        return report(crate, js, lin, lout, opts["--lines"], opts["--regions"])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
