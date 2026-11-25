"""Regenerate src/patterns/database.rs from the static pattern table of a cs2-sdk exe.

The exe is only read as bytes, never executed.

    python -I tools/sync_patterns_from_exe.py <cs2-sdk.exe> [--db src/patterns/database.rs] [--check]

Record layout in .rdata (88 bytes, verified on 578 of 578 entries of the 2.1.8 release build):
    resolve tag (u8 in a u64), rel_off (u64), name (ptr,len), module (ptr,len),
    needle (ptr,len), prototype (ptr,len), extra_off (i64)
The needle string is the anchor; a record starts 48 bytes before it. Pointers are absolute VAs
(ImageBase + RVA) and are resolved through the PE section table.

--check only prints what would change and leaves the file alone.
"""
import argparse
import json
import re
import struct
import sys

NEEDLE = re.compile(r"^(?:(?:[0-9A-F]{2}|\?{1,2}) )+(?:[0-9A-F]{2}|\?{1,2})$")
TAGS = {0: "NONE", 1: "REL32", 2: "RIPREL"}
CONSTS = {("NONE", 0): "NONE", ("REL32", 1): "REL32_1", ("RIPREL", 3): "RIPREL_3", ("RIPREL", 2): "RIPREL_2"}
SRC_CONSTS = {"NONE": ("NONE", 0), "REL32_1": ("REL32", 1), "RIPREL_3": ("RIPREL", 3), "RIPREL_2": ("RIPREL", 2)}


class Pe:
    def __init__(self, path):
        self.data = d = open(path, "rb").read()
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt = struct.unpack_from("<H", d, pe + 20)[0]
        self.base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
        self.secs = []
        for i in range(nsec):
            o = pe + 24 + opt + 40 * i
            name = d[o : o + 8].rstrip(b"\0").decode()
            vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
            self.secs.append((name, rva, vsize, rawptr, rawsize))

    def off(self, va):
        rva = va - self.base
        for _, srva, vsize, rawptr, rawsize in self.secs:
            if srva <= rva < srva + min(vsize, rawsize or vsize):
                return rawptr + rva - srva
        return None

    def string(self, va, ln):
        if not 0 < ln <= 4000:
            return None
        o = self.off(va)
        raw = self.data[o : o + ln] if o is not None else b""
        try:
            return raw.decode("utf-8") if len(raw) == ln else None
        except UnicodeDecodeError:
            return None


def extract(path):
    pe = Pe(path)
    rdata = next(s for s in pe.secs if s[0] == ".rdata")
    recs, bad = [], 0
    for o in range(rdata[3] + 48, rdata[3] + rdata[4] - 16, 8):
        ptr, ln = struct.unpack_from("<QQ", pe.data, o)
        if not (pe.base < ptr < pe.base + 0x10000000 and 5 <= ln <= 3000):
            continue
        needle = pe.string(ptr, ln)
        if not needle or not NEEDLE.match(needle):
            continue
        f = struct.unpack_from("<11Q", pe.data, o - 48)
        tag, rel = f[0] & 0xFF, f[1]  # upper bytes of the tag qword are padding
        name, module = pe.string(f[2], f[3]), pe.string(f[4], f[5])
        proto = "" if f[9] == 0 else pe.string(f[8], f[9])
        if tag not in TAGS or None in (name, module, proto) or not module.endswith(".dll"):
            bad += 1
            continue
        recs.append(
            dict(
                name=name,
                module=module,
                needle=needle,
                resolve=TAGS[tag],
                rel_off=rel if tag else 0,
                extra_off=struct.unpack("<q", struct.pack("<Q", f[10]))[0],
                prototype=proto,
            )
        )
    return recs, bad


def parse_source(path):
    src = open(path, encoding="utf-8-sig", errors="replace").read()
    recs = []
    for m in re.finditer(r"Pattern\s*\{", src):
        i, depth, j, instr = m.end(), 1, m.end(), False
        while depth and j < len(src):
            c = src[j]
            if instr:
                if c == "\\":
                    j += 1
                elif c == '"':
                    instr = False
            elif c == '"':
                instr = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
        body = src[i : j - 1]
        if "needle" not in body:
            continue

        def s(field):
            mm = re.search(field + r'\s*:\s*"((?:[^"\\]|\\.)*)"', body)
            return mm.group(1).encode().decode("unicode_escape") if mm else ""

        rv = re.search(r"resolve\s*:\s*(.+?)\s*,\s*extra_off", body, re.S).group(1).strip()
        if rv in SRC_CONSTS:
            kind, rel = SRC_CONSTS[rv]
        else:
            mm = re.match(r"ResolveKind::(None|Rel32|RipRel)\s*(?:\{\s*rel_off\s*:\s*(\d+)\s*\})?", rv)
            kind, rel = {"None": "NONE", "Rel32": "REL32", "RipRel": "RIPREL"}[mm.group(1)], int(mm.group(2) or 0)
        extra = int(re.search(r"extra_off\s*:\s*(-?(?:0x[0-9a-fA-F]+|\d+))", body).group(1), 0)
        recs.append(
            dict(name=s("name"), module=s("module"), needle=s("needle"), resolve=kind, rel_off=rel,
                 extra_off=extra, prototype=s("prototype"))
        )
    return recs


def key(r):
    return tuple(r[k] for k in ("name", "module", "needle", "resolve", "rel_off", "extra_off", "prototype"))


def render(db_path, recs, label):
    old = open(db_path, "rb").read().decode("utf-8")
    text = old.lstrip("﻿")
    head = text[: text.index("pub static CS2_PATTERNS: &[Pattern] = &[")].replace("\r\n", "\n")
    head = re.sub(r"// Regenerated from .*?\n// entries keep the order of that table\.\n", "", head, flags=re.S)

    def esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def res(r):
        k = (r["resolve"], r["rel_off"] if r["resolve"] != "NONE" else 0)
        if k in CONSTS:
            return CONSTS[k]
        return f"ResolveKind::{'Rel32' if r['resolve'] == 'REL32' else 'RipRel'} {{ rel_off: {r['rel_off']} }}"

    out = [head.rstrip("\n") + "\n", f"// Regenerated from {label} by tools/sync_patterns_from_exe.py;\n"
           "// entries keep the order of that table.\n", "pub static CS2_PATTERNS: &[Pattern] = &[\n"]
    mod = None
    for r in recs:
        if r["module"] != mod:
            mod = r["module"]
            out.append(f"    // {'=' * 76}\n    // {mod}\n    // {'=' * 76}\n")
        out.append(f'    Pattern {{ name: "{esc(r["name"])}", module: "{r["module"]}", needle: "{esc(r["needle"])}", '
                   f'resolve: {res(r)}, extra_off: {r["extra_off"]}, prototype: "{esc(r["prototype"])}" }},\n')
    out.append("];\n")
    body = "".join(out)
    if "\r\n" in text:
        body = body.replace("\n", "\r\n")
    return ("﻿" if old.startswith("﻿") else "") + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--db", default="src/patterns/database.rs")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    recs, bad = extract(a.exe)
    cur = {key(r) for r in parse_source(a.db)}
    new = {key(r) for r in recs}
    print(f"exe: {len(recs)} records ({bad} unreadable) | database.rs: {len(cur)} | "
          f"new or changed: {len(new - cur)} | dropped or changed: {len(cur - new)}")
    if a.check or not recs or bad:
        return 0 if recs and not bad else 1
    # render first: opening for write truncates the file that render reads
    content = render(a.db, recs, "the cs2-sdk exe").encode("utf-8")
    with open(a.db, "wb") as fh:
        fh.write(content)
    print("wrote", a.db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
