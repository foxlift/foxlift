# ABOUTME: Reader for the DBF+FPT pairs VFP uses to store forms, class libs, reports and menus.
# ABOUTME: Exposes records as field dicts with memos resolved, which is where OBJCODE bytecode lives.

import struct
from dataclasses import dataclass
from pathlib import Path

# .scx/.vcx/.frx/.mnx are DBF tables; their memo side-files carry the same stem.
MEMO_EXT = {".scx": ".sct", ".vcx": ".vct", ".frx": ".frt", ".mnx": ".mnt",
            ".dbf": ".fpt", ".lbx": ".lbt"}

# Code-page mark at byte 29 of the DBF header. Only the three marks every xBase tool agrees on
# are mapped; anything else falls back to latin-1, which preserves bytes 1:1 but not semantics.
# The public corpus is dominated by mark 0x7a (82% of records) INFERRED from corpus decode quality (gbk decodes valid Chinese; latin1 does not) —
# oracle CPCURRENT()/CPDBF() measurement still pending.
CODE_PAGE_MARKS = {
    0x00: None,      # no code page information
    0x01: "cp437",   # US MS-DOS
    0x02: "cp850",   # International MS-DOS
    0x03: "cp1252",  # Windows ANSI
    0x7a: "gbk",     # Simplified Chinese GB2312/GBK (inferred from corpus decode quality; oracle CPCURRENT() PENDING)
    0xc8: "cp1250",  # INFERRED from common xBase tables, not oracle-verified
}


def decode_text(raw: bytes, mark: int | None) -> str:
    """Decode table/memo text honouring the declared code page when it is known.

    A declared-codec failure falls back to latin-1: bytes stay 1:1 — so verbatim
    payloads and OBJCODE framing survive untouched — while character semantics
    degrade, the same trade the unmapped-mark path already makes. Measured
    2026-08-23: six corpus tables (login.scx, checkmat*.scx, checkmatq.scx,
    gridtree.vcx) carry memo bytes strict GBK rejects; strict decoding made
    objcode_records raise mid-table and the freeze dropped ALL their records
    (5,802 development pairs vs the 5,893 the published phase-2 sample drew from).
    """
    codec = CODE_PAGE_MARKS.get(mark if mark is not None else 0)
    if codec:
        try:
            return raw.decode(codec)
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("latin1")


@dataclass
class Field:
    name: str
    type: str
    length: int


class Table:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.memo = self._open_memo()

        self.record_count = struct.unpack_from("<I", self.data, 4)[0]
        self.header_len = struct.unpack_from("<H", self.data, 8)[0]
        self.record_len = struct.unpack_from("<H", self.data, 10)[0]
        self.code_page_mark = self.data[29] if len(self.data) > 29 else 0

        self.fields: list[Field] = []
        off = 32
        while off < len(self.data) and self.data[off] != 0x0D:
            self.fields.append(Field(
                name=self.data[off:off + 11].split(b"\0")[0].decode("latin1"),
                type=chr(self.data[off + 11]),
                length=self.data[off + 16],
            ))
            off += 32

    def _open_memo(self) -> tuple[bytes, int] | None:
        ext = MEMO_EXT.get(self.path.suffix.lower())
        if not ext:
            return None
        for cand in (self.path.with_suffix(ext), self.path.with_suffix(ext.upper())):
            if cand.exists():
                buf = cand.read_bytes()
                block = struct.unpack_from(">H", buf, 6)[0] or 512
                return buf, block
        return None

    def _memo(self, block: int) -> bytes:
        # Block numbers are stored binary little-endian in VFP tables, not as ASCII digits.
        if not block or not self.memo:
            return b""
        buf, size = self.memo
        pos = block * size
        if pos + 8 > len(buf):
            return b""
        _typ, length = struct.unpack_from(">II", buf, pos)
        return buf[pos + 8: pos + 8 + length]

    def records(self):
        for r in range(self.record_count):
            pos = self.header_len + r * self.record_len
            if pos + self.record_len > len(self.data):
                return
            deleted = self.data[pos:pos + 1] == b"*"
            pos += 1
            row = {}
            for f in self.fields:
                raw = self.data[pos:pos + f.length]
                pos += f.length
                if f.type == "M":
                    row[f.name] = self._memo(struct.unpack_from("<I", raw)[0]
                                             if len(raw) >= 4 else 0)
                else:
                    row[f.name] = raw
            row["_deleted"] = deleted
            yield row


def objcode_records(path: Path):
    """Yield (objname, source_text, bytecode) for every method-bearing record.

    Records carrying both METHODS and OBJCODE are pre-aligned source/bytecode pairs — the
    gold standard the lifter is scored against.
    """
    t = Table(path)
    names = {f.name for f in t.fields}
    if not {"METHODS", "OBJCODE"} <= names:
        return
    for row in t.records():
        if row["_deleted"]:
            continue
        src, code = row.get("METHODS", b""), row.get("OBJCODE", b"")
        if src or code:
            yield (decode_text(row.get("OBJNAME", b""), t.code_page_mark).strip(),
                   decode_text(src, t.code_page_mark), code)
