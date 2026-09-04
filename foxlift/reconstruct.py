# ABOUTME: Reconstruct .scx/.vcx tables by replacing METHODS with lifted source and clearing OBJCODE.
# ABOUTME: Unresolvable IncludeFile memos are zeroed; FFC wincrypt/_reports headers are copied at compile.

from __future__ import annotations

import struct
from pathlib import Path

from foxlift import codepage, container, lifter
from foxlift.dbf import Table, changed_ranges, table_codec, write_table

# VFP FFC headers the compile driver copies beside the class (r44-includes).
# Not in the corpus; never invent any other .h bytes.
FFC_INCLUDE_HEADERS = frozenset({"wincrypt.h", "_reports.h"})


def methods_bytes_from_objcode(code: bytes, codec: str | None = None) -> bytes:
    """Lift one OBJCODE module to METHODS memo bytes (CRLF).

    ASCII and latin-1-carrier lines go through prg_bytes. CJK identifiers
    decode via the table mark to Unicode; r44-codepage measured they compile
    on ACP-936 as GBK source bytes, so a latin-1 encode miss falls back to
    GBK rather than dropping the record.

    A record whose lifted source needs BOTH — a latin-1-carried binary payload
    beside a CJK identifier — has no single encoding that carries it, and
    there is nothing to write. That is a NAMED refusal like any other, not a
    UnicodeEncodeError escaping into the caller: `reconstruct_table` records it
    as a lift failure and leaves the record alone (r54-declarelib exposed it on
    a record whose lift the same round unblocked).
    """
    m = container.parse(code, codec=codec)
    lines = lifter.lift_program(m)
    try:
        raw = codepage.prg_bytes(lines)
    except UnicodeEncodeError:
        try:
            raw = ("\n".join(lines) + "\n").encode("gbk")
        except UnicodeEncodeError as exc:
            raise lifter.Unsupported(
                "METHODS source not encodable in one codepage (%s)"
                % exc.reason) from None
    return raw.replace(b"\n", b"\r\n")


def reconstruct_table(path: Path) -> tuple[Table, list[dict]]:
    """In-memory reconstruction of a form/class library table.

    Each record with OBJCODE gets METHODS replaced by lift_program emission
    and OBJCODE pointer zeroed. Unresolvable IncludeFile (RESERVED8) is
    zeroed. FFC headers stay for the compile driver to copy.
    """
    path = Path(path)
    table = Table(path)
    codec = table_codec(path)
    notes = []
    names = {f.name for f in table.fields}
    if not {"METHODS", "OBJCODE"} <= names:
        return table, [{"error": "not a METHODS/OBJCODE table"}]
    for i, row in enumerate(table.records()):
        code = row.get("OBJCODE", b"") or b""
        if not code:
            notes.append({"index": i, "action": "skip_empty_objcode"})
            continue
        try:
            methods = methods_bytes_from_objcode(code, codec=codec)
        except (lifter.Unsupported, ValueError) as exc:
            notes.append({"index": i, "action": "lift_fail",
                          "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        intents = table.reconstruct_methods(i, methods, clear_objcode=True)
        notes.append({"index": i, "action": "reconstructed",
                      "methods_len": len(methods), "intents": len(intents)})
    notes.extend(clear_unresolvable_include(table, path))
    return table, notes


def clear_unresolvable_include(table: Table, src: Path) -> list[dict]:
    """Zero IncludeFile (RESERVED8) when the named .h is not resolvable.

    wincrypt.h / _reports.h stay: the compile driver copies them from VFP FFC
    beside the class. A header sitting next to the source table stays (copytree
    already ships it). xfrxlib.h is in neither place — r44-includes measured
    COMPILE CLASSLIB clean after RESERVED8 was cleared; do not invent the file.
    """
    names = {f.name for f in table.fields}
    if "RESERVED8" not in names:
        return []
    src = Path(src)
    off, _ln = table.field_offset("RESERVED8")
    notes = []
    for i, row in enumerate(table.records()):
        raw = (row.get("RESERVED8") or b"").strip()
        if not raw:
            continue
        header = raw.decode("latin-1", "replace").split("\x00")[0].strip()
        if not header:
            continue
        beside = src.parent / header
        if beside.is_file() or header.lower() in FFC_INCLUDE_HEADERS:
            continue
        table._patch_record(i, off, struct.pack("<I", 0))
        notes.append({"index": i, "action": "clear_includefile",
                      "header": header, "intent": "unresolvable IncludeFile"})
    return notes


def write_reconstructed(src: Path, dest: Path) -> list[dict]:
    table, notes = reconstruct_table(src)
    write_table(table, dest)
    return notes


def header_and_noncode_diffs(before: Table, after: Table) -> dict:
    """Byte ranges that moved outside METHODS/OBJCODE — the rewrite surface."""
    b_dbf, b_memo = before.serialize()
    a_dbf, a_memo = after.serialize()
    skip = {"METHODS", "OBJCODE"}
    field_hits: dict[str, int] = {}
    n = min(len(before.record_bytes), len(after.record_bytes))
    for i in range(n):
        rb, ra = before.record_bytes[i], after.record_bytes[i]
        if rb == ra:
            continue
        off = 1
        if rb[:1] != ra[:1]:
            field_hits["_deleted"] = field_hits.get("_deleted", 0) + 1
        for f in before.fields:
            if rb[off:off + f.length] != ra[off:off + f.length]:
                if f.name not in skip:
                    field_hits[f.name] = field_hits.get(f.name, 0) + 1
            off += f.length
    header_ranges = changed_ranges(b_dbf[:before.header_len], a_dbf[:after.header_len])
    return {
        "header_ranges": header_ranges,
        "non_methods_objcode_fields": field_hits,
        "table_len_before": len(b_dbf),
        "table_len_after": len(a_dbf),
        "memo_len_before": len(b_memo or b""),
        "memo_len_after": len(a_memo or b""),
    }
