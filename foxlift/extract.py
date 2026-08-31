#!/usr/bin/env python3
# ABOUTME: Extract an APP/EXE container to a named project tree from the directory alone.
# ABOUTME: Dispatch by measured payload kind; compiled members restore 4-byte magic then lift.

"""Container path in, project tree out. No per-file branches, name hints, or offsets."""

from __future__ import annotations

from pathlib import Path

from foxlift import appcontainer, codepage, container, lifter
from foxlift.appcontainer import MAGIC
from foxlift.dbf import refuse_corpus_dest, write_table
from foxlift.reconstruct import reconstruct_table

COMPILED_SUFFIX = {
    ".fxp": ".prg",
    ".mpx": ".mpr",
    ".qpx": ".prg",
    ".spx": ".prg",
}
TABLE_SUFFIX = {".scx", ".vcx", ".frx", ".mnx", ".dbf", ".lbx"}


def payload_kind(payload: bytes, name: str = "") -> str:
    """Measured framing class. Name is the directory-bound entry name, used only
    for compiled/memo suffix when the bytes are otherwise ambiguous."""
    ext = ""
    if name and "." in name:
        ext = "." + name.rsplit(".", 1)[-1].lower()
    if not payload:
        return "empty"
    if payload.startswith(b"\xfe\xf2\xee"):
        return "encrypted"
    if payload[:4] in (
        b"\xfe\xf2\xff\x20",
        b"\xfe\xf2\xff\x22",
        b"\xfe\xf2\xff\x1f",
    ):
        return "standalone_module_magic"
    if ext in COMPILED_SUFFIX:
        return "compiled_without_module_magic"
    if ext in {".sct", ".vct", ".frt", ".mnt", ".fpt", ".pjt"}:
        return "memo_sidecar"
    if payload[:2] == b"BM":
        return "bmp"
    if payload[:1] == b"\x30":
        return "dbf_header"
    sample = payload[: min(64, len(payload))]
    if sample and all(32 <= b <= 126 or b in (9, 10, 13) for b in sample):
        return "text"
    if payload[:1] == b"\xfc":
        return "compiled_section_no_magic"
    return "other"


def restore_compiled(payload: bytes) -> bytes:
    """APP-stored compiled members omit the 4-byte module magic (D-family census)."""
    blob = MAGIC + payload
    container.parse(blob)
    return blob


def is_startup_fxp(payload: bytes, name: str) -> bool:
    """D-family measured: the startup .fxp payload begins with u32 0; others with 1."""
    if payload_kind(payload, name) != "compiled_without_module_magic":
        return False
    if not name.lower().endswith(".fxp"):
        return False
    return payload[:4] == b"\x00\x00\x00\x00"


def output_name(entry_name: str, kind: str) -> str:
    """Project-tree name for one directory entry. Compiled .fxp/.mpx become source."""
    base = entry_name.replace("\\", "/").split("/")[-1]
    if not base:
        raise ValueError("directory entry has empty name")
    ext = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""
    stem = base[: -len(ext)] if ext else base
    if kind == "compiled_without_module_magic":
        return stem + COMPILED_SUFFIX.get(ext, ".prg")
    return base


def _write(dest: Path, data: bytes) -> None:
    refuse_corpus_dest(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def extract_container(path: Path, dest: Path) -> dict:
    """Write every directory entry under dest. dest is created; corpus paths refused.

    Compiled entries: restore magic, lift, write .prg/.mpr. Form/class tables:
    write table+memo then reconstruct METHODS=lift, OBJCODE cleared. Raw/text/dbf:
    payload bytes as named.
    """
    path = Path(path)
    dest = Path(dest)
    refuse_corpus_dest(dest)
    dest.mkdir(parents=True, exist_ok=True)
    buf = path.read_bytes()
    app = appcontainer.load(buf, path=str(path))
    rows = []
    misses = []
    for e in app.entries:
        payload = app.extract(buf, e)
        kind = payload_kind(payload, e.name)
        try:
            out_name = output_name(e.name, kind)
        except ValueError as exc:
            misses.append({"name": e.name, "order": e.order, "miss": str(exc)})
            continue
        out_path = dest / out_name
        miss = None
        try:
            if kind == "compiled_without_module_magic":
                restored = restore_compiled(payload)
                m = container.parse(restored)
                src = codepage.prg_bytes(lifter.lift_program(m))
                _write(out_path, src)
            elif kind == "encrypted":
                miss = "encrypted fe f2 ee payload refused"
            else:
                _write(out_path, payload)
        except (lifter.Unsupported, ValueError, OSError) as exc:
            miss = "%s: %s" % (type(exc).__name__, exc)
        row = {
            "order": e.order,
            "entry_name": e.name,
            "kind": kind,
            "out_name": out_name,
            "size": len(payload),
            "col_x": e.col_x,
            "landed": miss is None and out_path.is_file(),
            "miss": miss,
        }
        rows.append(row)
        if miss:
            misses.append({"name": e.name, "order": e.order, "miss": miss})

    reconstruct_notes = []
    for table_path in sorted(dest.glob("*")):
        if table_path.suffix.lower() not in {".scx", ".vcx"}:
            continue
        try:
            table, notes = reconstruct_table(table_path)
            if any(n.get("error") == "not a METHODS/OBJCODE table" for n in notes):
                continue
            write_table(table, table_path)
            reconstruct_notes.append({"path": table_path.name, "notes": notes})
        except (OSError, ValueError) as exc:
            misses.append({
                "name": table_path.name,
                "order": None,
                "miss": "reconstruct: %s: %s" % (type(exc).__name__, exc),
            })

    startup = None
    for e in app.entries:
        payload = app.extract(buf, e)
        if is_startup_fxp(payload, e.name):
            startup = output_name(e.name, "compiled_without_module_magic")
            break

    landed = sum(1 for r in rows if r["landed"])
    return {
        "container": str(path),
        "dest": str(dest),
        "accepted": app.accepted,
        "n_entries": len(app.entries),
        "landed": landed,
        "misses": misses,
        "entries": rows,
        "reconstruct": reconstruct_notes,
        "startup_prg": startup,
    }
