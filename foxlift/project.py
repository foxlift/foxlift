#!/usr/bin/env python3
# ABOUTME: Assemble a VFP project table from an extracted tree using the builder template.
# ABOUTME: TIMESTAMP is builder-pinned; MAINPROG is the measured startup program; extras via append_clone.

from __future__ import annotations

from pathlib import Path

from foxlift.dbf import Table, refuse_corpus_dest, write_table

# TYPE codes from docs/FORMAT.md plus D-family native APPEND (M menu, D table).
SUFFIX_TYPE = {
    ".prg": "P",
    ".mpr": "P",
    ".scx": "K",
    ".vcx": "V",
    ".mnx": "M",
    ".frx": "R",
    ".h": "T",
    ".dbf": "D",
    ".bmp": "x",
}
SKIP_SUFFIX = {
    ".pjx", ".pjt", ".app", ".exe", ".fxp", ".mpx", ".err",
    ".sct", ".vct", ".frt", ".mnt", ".fpt", ".cdx",
}


def _row_name(row: dict) -> str:
    raw = row.get("NAME") or b""
    if isinstance(raw, bytes):
        return raw.split(b"\x00")[0].decode("latin1")
    return str(raw).split("\x00")[0]


def _row_type(row: dict) -> str:
    raw = row.get("TYPE") or b""
    if isinstance(raw, bytes):
        return raw.decode("latin1").strip(" \0")
    return str(raw).strip()


def _row_key(row: dict) -> str:
    raw = row.get("KEY") or b""
    if isinstance(raw, bytes):
        return raw.decode("latin1").strip(" \0")
    return str(raw).strip()


def members_from_tree(tree: Path) -> list[dict]:
    """Project members in the extracted tree. Memo sidecars and binaries skipped."""
    tree = Path(tree)
    rows = []
    for p in sorted(tree.iterdir()):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in SKIP_SUFFIX or ext not in SUFFIX_TYPE:
            continue
        rows.append({
            "filename": p.name,
            "type": SUFFIX_TYPE[ext],
            "key": p.stem.upper()[:32],
            "path": p,
        })
    return rows


def write_generated_pjx(
    dest: Path,
    template: Path,
    tree: Path,
    timestamp: int,
    startup_prg: str,
) -> Path:
    """Copy the FROM-prg builder template and append non-program members.

    Programs already in the template keep their rows; MAINPROG is set on
    startup_prg's KEY. TIMESTAMP is the builder pin for every non-H row.
    """
    refuse_corpus_dest(dest)
    t = Table(template)
    p_idx = next(i for i, r in enumerate(t.records()) if _row_type(r) == "P")
    present = {Path(_row_name(r)).name.lower() for r in t.records()}
    startup_key = Path(startup_prg).stem.upper()
    for mem in members_from_tree(tree):
        if mem["filename"].lower() in present:
            continue
        if mem["type"] == "P" and mem["filename"].lower().endswith(".prg"):
            continue
        obj = b""
        if mem["filename"].lower().endswith(".mpr"):
            sib = mem["path"].with_suffix(".mpx")
            if sib.is_file():
                obj = sib.read_bytes()
        t.append_clone(
            p_idx,
            NAME=(mem["filename"] + "\x00").encode("ascii"),
            TYPE=mem["type"],
            KEY=mem["key"],
            MAINPROG=False,
            OBJECT=obj,
            TIMESTAMP=timestamp,
        )
    for i, row in enumerate(list(t.records())):
        if _row_type(row) == "H":
            continue
        t.set_field(i, "TIMESTAMP", timestamp)
        if _row_type(row) == "P":
            t.set_field(i, "MAINPROG", _row_key(row).upper() == startup_key)
    write_table(t, dest)
    return dest
