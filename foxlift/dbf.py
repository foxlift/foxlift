# ABOUTME: Reader/writer for the DBF+FPT pairs VFP uses for forms, class libs, reports, menus, projects.
# ABOUTME: Parse-to-records re-serializes byte-identical; reconstruction mutates only declared memos.

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

# .scx/.vcx/.frx/.mnx are DBF tables; their memo side-files carry the same stem.
MEMO_EXT = {".scx": ".sct", ".vcx": ".vct", ".frx": ".frt", ".mnx": ".mnt",
            ".dbf": ".fpt", ".lbx": ".lbt", ".pjx": ".pjt"}

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
    descriptor: bytes = field(default_factory=bytes)


class MalformedTable(ValueError):
    """A DBF header that is not self-consistent with the file holding it."""


def header_bounds(blob: bytes) -> str | None:
    """Why these bytes are not a self-consistent DBF header, or None.

    A file can carry a table extension over something else entirely. Corpus 2
    holds 87 such files, 39 of them .scx/.vcx: 284-byte XML documents whose
    bytes 4..8 read as a record count of 1,819,113,535 and whose bytes 10..12
    read as a record length of 29,285. A reader that trusts that header builds
    a list of nearly two billion record slices; the freeze that first met one
    spent 65 CPU-minutes on a single file with no end in sight.

    Three conditions decide it: the header must fit inside the file, the record
    length must be nonzero, and the records the header declares must fit after
    the header. A file that fails any of them is refused BY NAME rather than
    read as a table whose records all slice short — which is a table that
    reports zero records and says nothing about why.
    """
    if len(blob) < 32:
        return "shorter than a 32-byte DBF header"
    n = int.from_bytes(blob[4:8], "little")
    header_len = int.from_bytes(blob[8:10], "little")
    record_len = int.from_bytes(blob[10:12], "little")
    if header_len < 32 or header_len > len(blob):
        return "header length %d against a %d-byte file" % (header_len, len(blob))
    if record_len == 0:
        return "record length 0"
    if header_len + n * record_len > len(blob):
        return ("declares %d records of %d bytes after a %d-byte header, but "
                "the file is %d bytes" % (n, record_len, header_len, len(blob)))
    return None


def corpus_root() -> Path:
    return Path(os.environ.get(
        "FOXLIFT_CORPUS", "~/work/foxlift-root/foxlift-corpus"
    )).expanduser()


def refuse_corpus_dest(path: Path) -> None:
    """Writers never land under the corpus root (round-44 rule 12)."""
    resolved = path.resolve()
    try:
        resolved.relative_to(corpus_root().resolve())
    except ValueError:
        return
    raise ValueError("refusing output under corpus root: %s" % resolved)


def changed_ranges(before: bytes, after: bytes) -> list[tuple[int, int]]:
    """Coalesced [start, end) ranges where before and after differ.

    Length mismatch is one range covering the tail of the longer buffer.
    """
    n = min(len(before), len(after))
    ranges: list[tuple[int, int]] = []
    block = 4096
    i = 0
    while i < n:
        if before[i] == after[i]:
            # Skip equal stretches a block at a time: a reconstructed memo is
            # megabytes of which a handful of records differ, and comparing
            # byte by byte in Python made this function the whole harness's
            # hot spot (65 s on one form). Slice equality is the same test,
            # run in C; the bytewise walk below still finds the exact first
            # differing byte inside the block that fails.
            while i < n:
                end = i + block if i + block < n else n
                if before[i:end] != after[i:end]:
                    break
                i = end
            while i < n and before[i] == after[i]:
                i += 1
            continue
        j = i + 1
        while j < n and before[j] != after[j]:
            j += 1
        ranges.append((i, j))
        i = j
    if len(before) != len(after):
        ranges.append((n, max(len(before), len(after))))
    return ranges


class Table:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        why = header_bounds(self.data)
        if why is not None:
            raise MalformedTable("%s: %s" % (path, why))
        self.memo = self._open_memo()

        self.record_count = struct.unpack_from("<I", self.data, 4)[0]
        self.header_len = struct.unpack_from("<H", self.data, 8)[0]
        self.record_len = struct.unpack_from("<H", self.data, 10)[0]
        self.code_page_mark = self.data[29] if len(self.data) > 29 else 0

        self.header = self.data[:self.header_len]
        rec_start = self.header_len
        rec_end = rec_start + self.record_count * self.record_len
        self.record_bytes: list[bytes] = [
            self.data[rec_start + i * self.record_len:
                      rec_start + (i + 1) * self.record_len]
            for i in range(self.record_count)
        ]
        self.trailer = self.data[rec_end:]
        self.memo_bytes = self.memo[0] if self.memo else None
        self.memo_block_size = self.memo[1] if self.memo else None

        self.fields: list[Field] = []
        off = 32
        while off < len(self.data) and self.data[off] != 0x0D:
            slot = self.data[off:off + 32]
            self.fields.append(Field(
                name=slot[:11].split(b"\0")[0].decode("latin1"),
                type=chr(slot[11]) if len(slot) > 11 else "?",
                length=slot[16] if len(slot) > 16 else 0,
                descriptor=slot,
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

    def _memo_from(self, buf: bytes | None, size: int | None, block: int) -> bytes:
        # Block numbers are stored binary little-endian in VFP tables, not as ASCII digits.
        if not block or not buf or not size:
            return b""
        pos = block * size
        if pos + 8 > len(buf):
            return b""
        _typ, length = struct.unpack_from(">II", buf, pos)
        return buf[pos + 8: pos + 8 + length]

    def _memo(self, block: int) -> bytes:
        return self._memo_from(self.memo_bytes, self.memo_block_size, block)

    def field_offset(self, name: str) -> tuple[int, int]:
        """(offset, length) of a field inside a record, offset 0 = deleted flag."""
        off = 1
        for f in self.fields:
            if f.name == name:
                return off, f.length
            off += f.length
        raise KeyError(name)

    def records(self):
        for rec in self.record_bytes:
            if len(rec) < self.record_len:
                return
            deleted = rec[:1] == b"*"
            pos = 1
            row = {}
            for f in self.fields:
                raw = rec[pos:pos + f.length]
                pos += f.length
                if f.type == "M":
                    row[f.name] = self._memo(struct.unpack_from("<I", raw)[0]
                                             if len(raw) >= 4 else 0)
                else:
                    row[f.name] = raw
            row["_deleted"] = deleted
            yield row

    def serialize(self) -> tuple[bytes, bytes | None]:
        """Table bytes and memo sidecar bytes (None when the source had no sidecar)."""
        header = bytearray(self.header)
        struct.pack_into("<I", header, 4, len(self.record_bytes))
        body = bytes(header) + b"".join(self.record_bytes) + self.trailer
        return body, self.memo_bytes

    def _patch_record(self, rec_index: int, offset: int, blob: bytes) -> None:
        rec = bytearray(self.record_bytes[rec_index])
        rec[offset:offset + len(blob)] = blob
        self.record_bytes[rec_index] = bytes(rec)

    def _append_memo(self, payload: bytes, typ: int = 1) -> int:
        """Allocate new blocks at next-free. Leaves existing memo bytes in place."""
        bs = self.memo_block_size or 64
        if self.memo_bytes is None:
            hdr = bytearray(bs)
            struct.pack_into(">I", hdr, 0, 1)
            struct.pack_into(">H", hdr, 6, bs)
            self.memo_bytes = bytes(hdr)
            self.memo_block_size = bs
        buf = bytearray(self.memo_bytes)
        next_free = struct.unpack_from(">I", buf, 0)[0] or 1
        pos = next_free * bs
        nblocks = max(1, (8 + len(payload) + bs - 1) // bs)
        needed = pos + nblocks * bs
        if needed > len(buf):
            buf.extend(b"\x00" * (needed - len(buf)))
        struct.pack_into(">I", buf, pos, typ)
        struct.pack_into(">I", buf, pos + 4, len(payload))
        buf[pos + 8:pos + 8 + len(payload)] = payload
        struct.pack_into(">I", buf, 0, next_free + nblocks)
        self.memo_bytes = bytes(buf)
        self.memo = (self.memo_bytes, bs)
        return next_free

    def set_field(self, rec_index: int, name: str, value) -> None:
        """Overwrite one field in rec_index. Memo values allocate new blocks; empty memo → pointer 0."""
        off, ln = self.field_offset(name)
        f = next(x for x in self.fields if x.name == name)
        if f.type == "M":
            if value in (None, b"", ""):
                self._patch_record(rec_index, off, struct.pack("<I", 0)[:ln].ljust(ln, b"\x00"))
                return
            payload = value if isinstance(value, bytes) else str(value).encode("latin1")
            ptr = self._append_memo(payload, typ=1)
            self._patch_record(rec_index, off, struct.pack("<I", ptr)[:ln])
            return
        if f.type == "L":
            ch = b"T" if value else b"F"
            self._patch_record(rec_index, off, ch[:ln].ljust(ln, b" "))
            return
        if f.type == "N":
            if value in (None, ""):
                blob = b" " * ln
            else:
                blob = str(value).rjust(ln)[:ln].encode("ascii")
            self._patch_record(rec_index, off, blob)
            return
        raw = value if isinstance(value, bytes) else str(value).encode("latin1")
        self._patch_record(rec_index, off, raw[:ln].ljust(ln, b" "))

    def _memo_ptr_in(self, rec: bytes, name: str) -> int:
        off, ln = self.field_offset(name)
        if ln < 4:
            return 0
        return struct.unpack_from("<I", rec, off)[0]

    def _memo_type(self, block: int) -> int:
        if not block or not self.memo_bytes or not self.memo_block_size:
            return 1
        pos = block * self.memo_block_size
        if pos + 8 > len(self.memo_bytes):
            return 1
        return struct.unpack_from(">I", self.memo_bytes, pos)[0]

    def append_clone(self, rec_index: int, **fields) -> int:
        """Duplicate rec_index with a fresh memo block per memo field, then overlay.

        Carrying the source pointers aliases NAME/SYMBOLS/OBJECT; BUILD APP then
        rejects the .pjt. Payload bytes are copied into a new block. Overlay
        still goes through set_field.
        """
        if rec_index < 0 or rec_index >= len(self.record_bytes):
            raise IndexError(rec_index)
        src = self.record_bytes[rec_index]
        self.record_bytes.append(bytes(src))
        idx = len(self.record_bytes) - 1
        for f in self.fields:
            if f.type != "M":
                continue
            ptr = self._memo_ptr_in(src, f.name)
            if not ptr:
                continue
            payload = self._memo(ptr)
            new_ptr = self._append_memo(payload, typ=self._memo_type(ptr))
            off, ln = self.field_offset(f.name)
            packed = struct.pack("<I", new_ptr)[:ln].ljust(ln, b"\x00")
            self._patch_record(idx, off, packed)
        for name, value in fields.items():
            self.set_field(idx, name, value)
        return idx

    def _overwrite_memo_same_length(self, block: int, payload: bytes) -> bool:
        if not self.memo_bytes or not self.memo_block_size or not block:
            return False
        pos = block * self.memo_block_size
        buf = self.memo_bytes
        if pos + 8 > len(buf):
            return False
        _typ, length = struct.unpack_from(">II", buf, pos)
        if length != len(payload):
            return False
        out = bytearray(buf)
        out[pos + 8:pos + 8 + length] = payload
        self.memo_bytes = bytes(out)
        self.memo = (self.memo_bytes, self.memo_block_size)
        return True

    def reconstruct_methods(self, rec_index: int, methods: bytes,
                            clear_objcode: bool = True) -> list[dict]:
        """Replace METHODS for one record; optionally zero the OBJCODE pointer.

        Same-length METHODS overwrite the payload in place. A length change
        appends new memo blocks and retargets the pointer; the old block stays.
        OBJCODE is cleared by writing a zero pointer — the old OBJCODE block
        is left in the sidecar. Returned intents name every mutated range.
        """
        intents: list[dict] = []
        before_dbf, before_memo = self.serialize()
        m_off, m_len = self.field_offset("METHODS")
        rec = self.record_bytes[rec_index]
        old_ptr = struct.unpack_from("<I", rec, m_off)[0] if m_len >= 4 else 0
        if not self._overwrite_memo_same_length(old_ptr, methods):
            new_ptr = self._append_memo(methods, typ=1)
            self._patch_record(rec_index, m_off, struct.pack("<I", new_ptr))
        if clear_objcode:
            o_off, o_len = self.field_offset("OBJCODE")
            if o_len >= 4:
                self._patch_record(rec_index, o_off, struct.pack("<I", 0))
        after_dbf, after_memo = self.serialize()
        for start, end in changed_ranges(before_dbf, after_dbf):
            intents.append({"file": "table", "start": start, "end": end,
                            "intent": "METHODS/OBJCODE pointer"})
        if before_memo is not None and after_memo is not None:
            for start, end in changed_ranges(before_memo, after_memo):
                intents.append({"file": "memo", "start": start, "end": end,
                                "intent": "METHODS payload or next-free"})
        elif before_memo != after_memo:
            intents.append({"file": "memo", "start": 0,
                            "end": len(after_memo or b""),
                            "intent": "METHODS payload or next-free"})
        return intents


def write_table(table: Table, path: Path) -> None:
    """Serialize table + memo sidecar. Refuses destinations under the corpus root."""
    path = Path(path)
    refuse_corpus_dest(path)
    dbf, memo = table.serialize()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dbf)
    if memo is None:
        return
    ext = MEMO_EXT.get(path.suffix.lower())
    if not ext:
        return
    side = path.with_suffix(ext)
    refuse_corpus_dest(side)
    side.write_bytes(memo)


def table_codec(path: Path) -> str | None:
    """Code-page codec for a DBF-family table, or None when the mark is unmapped.

    Round-42 I6: symbol-table name bytes follow this mark (0x7a→GBK, 0x03→cp1252).
    Unmapped marks stay None so container.parse keeps latin-1 (byte-preserving).
    """
    t = Table(path)
    return CODE_PAGE_MARKS.get(t.code_page_mark)


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
