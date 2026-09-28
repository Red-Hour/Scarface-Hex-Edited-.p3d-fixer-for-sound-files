#!/usr/bin/env python3
"""
Validate - and optionally FIX - a hand-edited P3D sound-event file before loading it in the game.

Usage:
  python validate_p3d.py Test.p3d                  check only
  python validate_p3d.py Test.p3d --fix            write Test_fixed.p3d (your original is never touched)
  python validate_p3d.py Test.p3d --fix --new-ids  ...and also give duplicated 8-byte IDs new values
  python validate_p3d.py Test.p3d --fix -o out.p3d choose the output name

Rules (learned from Test.p3d, so they assume the same layout):
  File   : magic 'P3D'+0xFF | @0x08 == file size | @0x10 == @0x14 == file size - 12
           | @0x34 child count == number of children in the file
  Child  : [len][name][00] + 27-byte header, then nodes. The name's length prefix must be present and
           correct. Header dword @+23 == number of TOP-LEVEL nodes in that child.
  Node   : [len]["SeqEvent<Type>"][00][8-byte ID] ... every node's length prefix must be correct.
  LogicOr: child-count dword == number of SeqEventClip nodes directly after it.
  Clip   : path length prefix == real string length (up to its 00); the last clip of every child is
           followed by exactly 25 bytes.
  Notes  : duplicate 8-byte IDs (warning only).

--fix repairs everything that can be derived from the rules above: missing/wrong child-name prefix,
node prefixes, LogicOr counts, top-level counts, clip path prefixes, child count and the three size
fields. It does NOT guess at things it cannot derive (e.g. stray extra bytes after a clip): those are
reported for you to fix by hand.
"""
import argparse
import os
import re
import struct
import sys

COUNT_OFF = 0x34       # child-count dword in Test.p3d
HEADER_LEN = 27        # fixed block between a child's name and its first SeqEvent node
LAST_CLIP_TRAILER = 25
NODE_RE = re.compile(rb'SeqEvent([A-Za-z]+)\x00')


def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def le(n):
    return struct.pack('<I', n).hex(' ')


def find_children(d):
    """Find every child by its shape: name 00 + 27-byte header + a 'SeqEvent...' node.
    Returns dicts with name, name position, and whether a correct length prefix sits in front of it."""
    out = []
    for e in range(0x18, len(d) - HEADER_LEN - 12):
        if d[e] != 0:
            continue
        p = e
        while p > 0x18 and 32 <= d[p - 1] < 127 and d[p - 1] != 0x5C:
            p -= 1
        if not 1 <= e - p <= 100 or bytes(d[p:e]).startswith(b'SeqEvent'):
            continue
        j = e + 1 + HEADER_LEN
        if bytes(d[j + 4:j + 12]) != b'SeqEvent':
            continue
        name_pos = p
        # a printable length byte (0x20-0x7E) gets swallowed into the run; peel it off if so
        if p >= 4 and u32(d, p) == e - p - 4 and bytes(d[p + 1:p + 4]) == b'\0\0\0' and e - p > 4:
            name_pos = p + 4
        name = bytes(d[name_pos:e])
        ok = name_pos >= 4 and u32(d, name_pos - 4) == len(name)
        out.append(dict(name=name.decode(), pos=name_pos, end=e, ok=ok))
    return out


def block_bounds(d, kids):
    starts = [k['pos'] - 4 if k['ok'] else k['pos'] for k in kids]
    return starts, starts[1:] + [len(d)]


def clip_fields(blk, m):
    """Offsets for one SeqEventClip node: (q = path length dword, ps = path start, pe = path terminator)."""
    q = m.end() + 8 + 1
    ps = q + 4
    return q, ps, blk.find(b'\0', ps)


def analyze_child(d, ch, start, stop):
    """Everything derivable about one child. Returns a dict of the facts both check and fix need."""
    name = ch['name']
    blk = bytes(d[start:stop])
    hdr = (ch['pos'] - start) + len(name) + 1
    nodes = [(m.group(1).decode(), m) for m in NODE_RE.finditer(blk)]
    logic, child_clips, i = [], 0, 0
    while i < len(nodes):
        typ, m = nodes[i]
        if typ == 'LogicOr':
            run = 0
            while i + 1 + run < len(nodes) and nodes[i + 1 + run][0] == 'Clip':
                run += 1
            logic.append((m.end() + 8 + 4, u32(blk, m.end() + 8 + 4), run))
            child_clips += run
            i += run
        i += 1
    return dict(name=name, blk=blk, hdr=hdr, nodes=nodes, logic=logic, top=len(nodes) - child_clips)


def check(d):
    problems, notes, ids = [], [], {}
    if d[:4] != b'P3D\xff':
        problems.append('Bad magic (expected 50 33 44 FF)')
    if u32(d, 0x08) != len(d):
        problems.append(f'@0x08 file size is {u32(d, 0x08)} but the file is {len(d)} bytes -> should be {len(d)} = {le(len(d))}')
    for off in (0x10, 0x14):
        if u32(d, off) != len(d) - 12:
            problems.append(f'@{off:#x} body size is {u32(d, off)} -> should be {len(d) - 12} = {le(len(d) - 12)}')

    kids = find_children(d)
    declared = u32(d, COUNT_OFF)
    if declared != len(kids):
        problems.append(f'@{COUNT_OFF:#x} child count says {declared} but {len(kids)} children were found -> should be {len(kids)} = {le(len(kids))}')

    starts, stops = block_bounds(d, kids)
    for k, s, t in zip(kids, starts, stops):
        name = k['name']
        if not k['ok']:
            problems.append(f'{name} @{k["pos"]:#x}: name length prefix missing or wrong -> the 4 bytes before it must be {le(len(name))}')
        a = analyze_child(d, k, s, t)
        blk = a['blk']
        ids.setdefault(bytes(blk[a['hdr'] + 15:a['hdr'] + 23]), []).append(f'{name} (child)')
        for typ, m in a['nodes']:
            nl = len(m.group(0)) - 1
            if m.start() < 4 or u32(blk, m.start() - 4) != nl:
                problems.append(f'{name}: node "SeqEvent{typ}" has a wrong/missing length prefix (should be {le(nl)})')
            ids.setdefault(bytes(blk[m.end():m.end() + 8]), []).append(f'{name} ({typ})')
        for _, declared_n, run in a['logic']:
            if declared_n != run:
                problems.append(f'{name}: LogicOr says {declared_n} clips but {run} SeqEventClip nodes follow it -> child-count dword should be {run} = {le(run)}')
        if u32(blk, a['hdr'] + 23) != a['top']:
            problems.append(f'{name}: header says {u32(blk, a["hdr"] + 23)} top-level nodes but there are {a["top"]} -> dword at name+{len(name) + 1 + 23} should be {le(a["top"])}')
        bad, last_trailer = [], None
        for typ, m in a['nodes']:
            if typ != 'Clip':
                continue
            q, ps, pe = clip_fields(blk, m)
            if u32(blk, q) != pe - ps:
                bad.append((blk[ps:pe].decode('latin-1'), u32(blk, q), pe - ps))
            last_trailer = len(blk) - (pe + 1)
        if bad:
            p, plen, actual = bad[0]
            problems.append(f'{name}: {len(bad)} clip path(s) have a wrong length prefix, e.g. "{p}" says {plen} but is {actual} chars -> should be {le(actual)}')
        if last_trailer is not None and last_trailer != LAST_CLIP_TRAILER:
            problems.append(f'{name}: last clip is followed by {last_trailer} bytes, expected {LAST_CLIP_TRAILER}')

    dups = {i: w for i, w in ids.items() if len(w) > 1}
    if dups:
        ex = next(iter(dups.items()))
        notes.append(f'{len(dups)} 8-byte ID(s) are shared by several nodes (e.g. {ex[0].hex(" ")} x{len(ex[1])}); use --fix --new-ids or give cloned nodes new IDs')
    return kids, problems, notes


def fix(data, new_ids=False):
    """Returns (fixed_bytes, list_of_what_changed, list_of_things_needing_manual_fixing)."""
    d = bytearray(data)
    log, manual, skipped = [], [], set()

    # 1) child-name length prefixes - may need an INSERT, so handled one at a time, then re-scan
    for _ in range(1000):
        kids = find_children(d)
        starts, _ = block_bounds(d, kids)
        idx = next((i for i, k in enumerate(kids) if not k['ok'] and k['pos'] not in skipped), None)
        if idx is None:
            break
        k = kids[idx]
        want = struct.pack('<I', len(k['name']))
        if idx == 0:
            skipped.add(k['pos']); manual.append(f'{k["name"]}: first child has a bad name prefix - fix by hand'); continue
        prev = bytes(d[starts[idx - 1]:k['pos']])
        clips = [m for m in NODE_RE.finditer(prev) if m.group(1) == b'Clip']
        if not clips:
            skipped.add(k['pos']); manual.append(f'{k["name"]}: cannot tell whether its name prefix is missing or wrong - fix by hand'); continue
        _, _, pe = clip_fields(prev, clips[-1])
        expected_end = starts[idx - 1] + pe + 1 + LAST_CLIP_TRAILER
        if expected_end == k['pos']:
            d[k['pos']:k['pos']] = want
            log.append(f'{k["name"]}: inserted the missing name length prefix ({want.hex(" ")}) at {k["pos"]:#x}')
        elif expected_end == k['pos'] - 4:
            d[k['pos'] - 4:k['pos']] = want
            log.append(f'{k["name"]}: name length prefix corrected to {want.hex(" ")} at {k["pos"] - 4:#x}')
        else:
            skipped.add(k['pos'])
            manual.append(f'{k["name"]}: previous block does not end where expected ({expected_end:#x} vs {k["pos"]:#x}) - stray or missing bytes, fix by hand')

    # 2) in-place fixes (nothing here changes the file length)
    kids = find_children(d)
    starts, stops = block_bounds(d, kids)
    counts = {'node prefix': [], 'LogicOr count': [], 'top-level count': [], 'clip path prefix': []}
    for k, s, t in zip(kids, starts, stops):
        a = analyze_child(d, k, s, t)
        blk, name = a['blk'], k['name']
        for typ, m in a['nodes']:
            nl = len(m.group(0)) - 1
            if m.start() >= 4 and u32(blk, m.start() - 4) != nl:
                counts['node prefix'].append(f'{name}: SeqEvent{typ} {u32(blk, m.start() - 4)} -> {nl}')
                struct.pack_into('<I', d, s + m.start() - 4, nl)
            if typ == 'Clip':
                q, ps, pe = clip_fields(blk, m)
                if pe != -1 and u32(blk, q) != pe - ps:
                    counts['clip path prefix'].append(f'{name}: {u32(blk, q)} -> {pe - ps}')
                    struct.pack_into('<I', d, s + q, pe - ps)
        for off, declared_n, run in a['logic']:
            if declared_n != run:
                counts['LogicOr count'].append(f'{name}: {declared_n} -> {run}')
                struct.pack_into('<I', d, s + off, run)
        if u32(blk, a['hdr'] + 23) != a['top']:
            counts['top-level count'].append(f'{name}: {u32(blk, a["hdr"] + 23)} -> {a["top"]}')
            struct.pack_into('<I', d, s + a['hdr'] + 23, a['top'])
    for what, items in counts.items():
        if items:
            log.append(f'{len(items)} {what}(s) corrected, e.g. {items[0]}')

    # 3) optional: unique IDs
    if new_ids:
        kids = find_children(d)
        starts, stops = block_bounds(d, kids)
        seen, changed = set(), 0
        for k, s, t in zip(kids, starts, stops):
            a = analyze_child(d, k, s, t)
            positions = [s + a['hdr'] + 15] + [s + m.end() for _, m in a['nodes']]
            for pos in positions:
                while bytes(d[pos:pos + 8]) in seen:
                    v = (u32(d, pos) + 0x111) & 0xFFFFFFFF
                    struct.pack_into('<I', d, pos, v)
                    changed += 1
                seen.add(bytes(d[pos:pos + 8]))
        if changed:
            log.append('duplicate 8-byte IDs given new values')

    # 4) counters and sizes, always last
    n = len(find_children(d))
    declared = u32(d, COUNT_OFF)
    if n < declared:
        manual.append(f'child count says {declared} but only {n} children are recognisable - a child header or node name is '
                      f'damaged (or the count is too high). Left the count alone; fix by hand')
        n = declared
    for off, val, what in ((COUNT_OFF, n, 'child count'), (0x08, len(d), 'file size'),
                           (0x10, len(d) - 12, 'body size'), (0x14, len(d) - 12, 'body size (copy)')):
        if u32(d, off) != val:
            log.append(f'@{off:#x} {what}: {u32(d, off)} -> {val} ({le(val)})')
            struct.pack_into('<I', d, off, val)
    return bytes(d), log, manual


def report(path, d, kids, problems, notes):
    declared = u32(d, COUNT_OFF)
    print(f'{path}: {len(d)} bytes, {len(kids)} children found, count field = {declared}')
    print(f'Last child: {kids[-1]["name"] if kids else "none"}')
    for n in notes:
        print('  note (may be fine):', n)
    if problems:
        print(f'\nFAIL - {len(problems)} problem(s):')
        for p in problems:
            print('  x', p)
        return False
    print('\nPASS - structure looks consistent.')
    return True


def main():
    ap = argparse.ArgumentParser(description='Validate / fix a P3D sound-event file.')
    ap.add_argument('file')
    ap.add_argument('--fix', action='store_true', help='write a repaired copy (original untouched)')
    ap.add_argument('--new-ids', action='store_true', help='with --fix: give duplicated IDs new values')
    ap.add_argument('-o', '--out', help='output path for --fix (default: <name>_fixed.p3d)')
    args = ap.parse_args()

    d = open(args.file, 'rb').read()
    kids, problems, notes = check(d)
    ok = report(args.file, d, kids, problems, notes)
    if not args.fix:
        sys.exit(0 if ok else 1)

    fixed, log, manual = fix(d, args.new_ids)
    if fixed == d:
        print('\nNothing to fix automatically.')
        sys.exit(0 if ok else 1)
    out = args.out or os.path.splitext(args.file)[0] + '_fixed.p3d'
    if os.path.abspath(out) == os.path.abspath(args.file):
        sys.exit('Refusing to overwrite the input file; choose another -o.')
    open(out, 'wb').write(fixed)
    print(f'\nFIXED - wrote {out} ({len(fixed)} bytes). Changes:')
    for line in log:
        print('  +', line)
    for line in manual:
        print('  !', line)
    print('\nRe-checking the fixed file:')
    k2, p2, n2 = check(fixed)
    ok2 = report(out, fixed, k2, p2, n2)
    if not ok2:
        print('\nThe remaining problems need a manual fix (the tool will not guess at them).')
    sys.exit(0 if ok2 else 1)


if __name__ == '__main__':
    main()