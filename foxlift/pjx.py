# ABOUTME: Reader/writer for Visual FoxPro .pjx/.pjt project tables — phase-5's final emitter.
# ABOUTME: Schema measured against fb2p_test.pjx/pjt and proj1.pjx/PJT (see probes/exe_container).

import struct

from dataclasses import dataclass, field

from pathlib import Path

# Field layout measured from real projects (record length 130, header length 1192).
# Order and displacements are part of the on-disk contract; do not reorder.
_FIELDS = [
    ("NAME",      "M", 4),
    ("TYPE",      "C", 1),
    ("ID",        "N", 10),
    ("TIMESTAMP", "N", 10),
    ("OUTFILE",   "M", 4),
    ("HOMEDIR",   "M", 4),
    ("EXCLUDE",   "L", 1),
    ("MAINPROG",  "L", 1),
    ("SAVECODE",  "L", 1),
    ("DEBUG",     "L", 1),
    ("ENCRYPT",   "L", 1),
    ("NOLOGO",    "L", 1),
    ("CMNTSTYLE", "N", 1),
    ("OBJREV",    "N", 5),
    ("DEVINFO",   "M", 4),
    ("SYMBOLS",   "M", 4),
    ("OBJECT",    "M", 4),
    ("CKVAL",     "N", 6),
    ("CPID",      "N", 5),
    ("OSTYPE",    "C", 4),
    ("OSCREATOR", "C", 4),
    ("COMMENTS",  "M", 4),
    ("RESERVED1", "M", 4),
    ("RESERVED2", "M", 4),
    ("SCCDATA",   "M", 4),
    ("LOCAL",     "L", 1),
    ("KEY",       "C", 32),
    ("USER",      "M", 4),
]

RECORD_LEN = 130
HEADER_LEN = 1192          # includes zero padding after the field terminator

# TYPE codes measured against authored ground truth (fb2p_test.pjt / proj1.PJT KEY fields):
TYPE_PROJECT_HEADER = "H"
TYPE_DATABASE = "d"
TYPE_FORM = "K"
TYPE_PROGRAM = "P"
TYPE_REPORT = "R"
TYPE_CLASSLIB = "V"
TYPE_IMAGE = "x"
TYPE_TEXT = "T"


@dataclass
class Entry:
    name: str
    type: str
    key: str = ""
    outfile: str = ""
    homedir: str = ""
    exclude: bool = False
    mainprog: bool = False
    cpid: int = 1252


@dataclass
class Project:
    header_name: str = ""
    entries: list = field(default_factory=list)


def parse_header(buf):
    rec_count = struct.unpack_from("<I", buf, 4)[0]
    hdr_len = struct.unpack_from("<H", buf, 8)[0]
    rec_len = struct.unpack_from("<H", buf, 10)[0]
    fields = []
    off = 32
    while off < hdr_len and buf[off] != 0x0D and off + 32 <= len(buf):
        name = buf[off:off+11].split(b"\x00")[0].decode("latin1")
        typ = chr(buf[off+11])
        disp = struct.unpack_from("<I", buf, off+12)[0]
        ln = buf[off+16]
        fields.append((name, typ, disp, ln))
        off += 32
    return rec_count, hdr_len, rec_len, fields


def _memo_at(memo, block):
    """.pjt headers store BLOCK SIZE big-endian at offset 6; pointers are BLOCK
    numbers; each entry is [BE u32 type=1][BE u32 len][data padded to block]."""
    if memo is None or block == 0 or len(memo) < 8:
        return ""
    bs = struct.unpack_from(">H", memo, 6)[0] or 64
    off = block * bs
    if off + 8 > len(memo):
        return ""
    ln = struct.unpack_from(">I", memo, off + 4)[0]
    return memo[off + 8:off + 8 + ln].decode("latin1", "replace")


def read_project(pjx_path, pjt_path=None):
    """Parse a .pjx (+ optional .pjt) into (header_entry_or_None, [Entry...])."""
    buf = Path(pjx_path).read_bytes()
    rec_count, hdr_len, rec_len, fields = parse_header(buf)
    memo = Path(pjt_path).read_bytes() if (pjt_path and Path(pjt_path).exists()) else None

    header_entry, entries = None, []
    for k in range(rec_count):
        roff = hdr_len + k * rec_len
        rec = buf[roff:roff + rec_len]
        vals = {}
        for name, typ, disp, ln in fields:
            raw = rec[disp:disp + ln]
            if typ == "M":
                ptr = struct.unpack_from("<I", raw[:4])[0]
                vals[name] = _memo_at(memo, ptr)
            elif typ == "L":
                vals[name] = raw[:1] in (b"T", b"Y")
            else:
                vals[name] = raw.decode("latin1", "replace").rstrip(chr(0)).strip()
        e = Entry(name=vals.get("NAME", ""), type=vals.get("TYPE", "?"),
                  key=vals.get("KEY", ""), outfile=vals.get("OUTFILE", ""),
                  homedir=vals.get("HOMEDIR", ""),
                  mainprog=bool(vals.get("MAINPROG")),
                  exclude=bool(vals.get("EXCLUDE")))
        if e.type == TYPE_PROJECT_HEADER:
            header_entry = e
        else:
            entries.append(e)
    return header_entry, entries


def _emit_memo_entry(blob, text, bs=64):
    while len(blob) % bs:
        blob.append(0)
    start = len(blob) // bs
    data = text.encode("latin1")
    blob.extend(struct.pack(">I", 1))
    blob.extend(struct.pack(">I", len(data)))
    blob.extend(data)
    while len(blob) % bs:
        blob.append(0)
    return start

def build_files(project, template_pjx=None, block_size=64):
    """Build (pjx_bytes, pjt_bytes) for the project. With template_pjx, its header
    and field descriptors are reused verbatim."""
    if template_pjx is not None:
        tbuf = template_pjx
        _, hdr_len_t, rec_len_t, fields = parse_header(tbuf)
        header_block = bytearray(tbuf[:hdr_len_t])
    else:
        # Self-contained header built from the measured schema in _FIELDS. Displacements start
        # at 1 (after the DBF deletion-flag byte); hdr_len/rec_len must be filled in or the
        # file we just wrote cannot be read back. Until 2026-08-24 this branch crashed on an
        # incomplete tuple unpack — it was dead code because every test passed a real .pjx
        # from the corpus as its template.
        d = bytearray(32)
        d[0] = 0x30
        d[1:4] = bytes((26, 5, 24))
        fields = []
        dd = bytearray()
        pos = 1
        for n, t, l in _FIELDS:
            e = bytearray(n.encode("latin1")[:11].ljust(11, b"\x00"))
            e.append(ord(t))
            e += struct.pack("<I", pos)
            e += bytes([l, 0]) + bytes(14)
            dd += e
            fields.append((n, t, pos, l))
            pos += l
        dd += b"\x0d"
        # dd already includes its 0x0D terminator; zero-pad exactly to HEADER_LEN.
        # The old "- 1" here double-counted the terminator and emitted a 1191-byte
        # header against a declared hdr_len of 1192, shifting every record by one.
        pad = max(HEADER_LEN - 32 - len(dd), 0)
        header_block = bytearray(bytes(d) + bytes(dd) + b"\x00" * max(pad, 0))
        struct.pack_into("<H", header_block, 8, HEADER_LEN)
        struct.pack_into("<H", header_block, 10, RECORD_LEN)

    all_entries = [Entry(name=project.header_name, type=TYPE_PROJECT_HEADER,
                         key=Path(project.header_name).stem.upper())] + \
                  list(project.entries)

    BS = 64
    blob = bytearray(64)
    struct.pack_into(">H", blob, 6, BS)
    body = bytearray()
    for e in all_entries:
        row = bytearray(b" ")
        for name, typ, disp, ln in fields:
            val = b"\x00" * ln
            if typ == "M":
                text = {"NAME": e.name, "OUTFILE": e.outfile,
                        "HOMEDIR": e.homedir}.get(name, "")
                if text:
                    blk = _emit_memo_entry(blob, text, BS)
                    val = struct.pack("<I", blk)
            elif typ == "L":
                v = {"EXCLUDE": e.exclude, "MAINPROG": e.mainprog}.get(name, False)
                val = b"T" if v else b"F"
            elif typ == "N":
                txt = {"CPID": str(e.cpid)}.get(name, "")
                val = txt.rjust(ln)[:ln].encode("latin1")
            else:
                txt = {"TYPE": e.type,
                       "KEY": (e.key or Path(e.name).stem.upper()).upper()}.get(name, "")
                val = txt.encode("latin1")[:ln].ljust(ln, b" ")
            row += val
        body += row

    out = bytearray(header_block)
    out[4:8] = struct.pack("<I", len(all_entries))
    out.extend(body)
    return bytes(out), bytes(blob)


def write_project(pjx_path, pjt_path, project, template_pjx=None, block_size=64):
    out, blob = build_files(project, template_pjx=template_pjx, block_size=block_size)
    Path(pjx_path).write_bytes(out)
    Path(pjt_path).write_bytes(bytes(blob))
    return len(out), 64 + len(blob)
