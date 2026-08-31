# ABOUTME: CLI entry point for foxlift — inspect and decompile VFP binaries.
# ABOUTME: Oracle strictly optional; inspect and decompile work entirely offline.

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path

from foxlift import container
from foxlift import dbf as foxdbf
from foxlift import lifter
from foxlift import codepage

MAGICS = {b"\xfe\xf2\xff\x20", b"\xfe\xf2\xff\x22", b"\xfe\xf2\xff\x1f"}


def _package_version():
    try:
        return metadata.version("foxlift")
    except metadata.PackageNotFoundError:
        return "uninstalled"


# --- input dispatch -------------------------------------------------------------------

def _detect_format(path):
    ext = path.suffix.lower()
    buf = path.read_bytes()
    if ext == ".fxp" or buf[:4] in MAGICS:
        return "fxp", buf
    if ext in (".scx", ".vcx"):
        return "table", buf
    if ext in (".exe", ".app"):
        return "binary", buf
    raise ValueError(f"unsupported input format: {path} (extension={ext})")


def _iter_modules(buf):
    """Yield (offset, parsed_module) for every recognised magic hit."""
    for off in container.find_modules(buf):
        try:
            yield off, container.parse(buf, off)
        except ValueError:
            pass


# --- shared helpers -----------------------------------------------------------------

def _module_summary(off, m):
    return {
        "offset": off,
        "statements": len(m.statements),
        "known": sum(1 for s in m.statements if s.known),
        "verbatim_text": sum(1 for s in m.statements if s.text is not None),
        "symbols_parsed": m.symbols_parsed,
        "symbol_count": len(m.symbols),
    }


def _emit(data, as_json):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(json.dumps(data, indent=2, default=str))  # human-readable is JSON for now


# --- inspect -------------------------------------------------------------------------

def cmd_inspect(args):
    path = Path(args.input)
    fmt, buf = _detect_format(path)
    result = {"file": str(path), "format": fmt, "size": len(buf)}

    if fmt == "fxp":
        mods = list(_iter_modules(buf))
        result["module_count"] = len(mods)
        result["modules"] = [_module_summary(off, m) for off, m in mods]

    elif fmt == "table":
        t = foxdbf.Table(path)
        cpm = t.data[29] if len(t.data) > 29 else 0
        result["record_count"] = t.record_count
        result["code_page_mark"] = hex(cpm)
        recs = []
        codec = foxdbf.CODE_PAGE_MARKS.get(cpm)
        for name, src, code in foxdbf.objcode_records(path):
            r = {"name": name, "objcode_size": len(code) if code else 0}
            if code and len(code) >= 8:
                try:
                    m = container.parse(code, codec=codec)
                    r["statements"] = len(m.statements)
                    r["known"] = sum(1 for s in m.statements if s.known)
                    r["verbatim"] = sum(1 for s in m.statements if s.text is not None)
                except ValueError:
                    r["parse_error"] = True
            recs.append(r)
        result["records"] = recs

    elif fmt == "binary":
        hits = container.find_modules(buf)
        result["magic_hits"] = len(hits)
        parsed, total_stmts = 0, 0
        for off in hits:
            try:
                m = container.parse(buf, off)
                parsed += 1
                total_stmts += len(m.statements)
            except ValueError:
                pass
        result["parsed"] = parsed
        result["total_statements"] = total_stmts

    _emit(result, args.json)


# --- decompile ------------------------------------------------------------------------

def _lift_module(m, mod_dir, meta) -> tuple[bool, list[str]]:
    """Write one parsed module's source tree into mod_dir. True iff every section lifted."""
    mod_dir.mkdir(parents=True, exist_ok=True)
    ok = True
    reasons: list[str] = []

    meta = dict(meta)
    meta["statement_count"] = len(m.statements)
    src_lines = []
    sections_meta = []

    # Per-section lifting: a section inside the supported slice returns canonical VFP
    # lines; one outside falls back to per-statement accounting (verbatim text kept,
    # compiled statements as placeholders) and fails verification for the run. A
    # section that cannot be lifted is REPORTED, never dropped silently.
    if not m.sections:
        ok = False
    for si, sec in enumerate(m.sections):
        smeta = {"index": si, "statements": len(sec.statements)}
        try:
            lines = lifter.lift_section(sec)
        except lifter.Unsupported as e:
            smeta["lifted"] = False
            smeta["reason"] = str(e)
            reasons.append(str(e).split("\n", 1)[0])
            ok = False
            label = "section %d (%d statement(s) beyond the supported slice: %s)" % (
                si, len(sec.statements), e)
            src_lines.append("* --- %s ---" % label)
            detail = []
            for i, stmt in enumerate(sec.statements):
                dsi = {"index": i, "known": stmt.known}
                if stmt.text is not None:
                    dsi["kind"] = "verbatim"
                    dsi["text_len"] = len(stmt.text)
                    src_lines.append(stmt.text)
                else:
                    dsi["kind"] = "compiled"
                    dsi["stream_len"] = len(stmt.stream)
                    if not stmt.known:
                        dsi["warning"] = "unknown statement shape"
                    src_lines.append("* [compiled statement %d, %d bytes]" % (i, len(stmt.stream)))
                detail.append(dsi)
            smeta["statements_detail"] = detail
        else:
            smeta["lifted"] = True
            src_lines.append("* --- section %d%s ---" % (si, " (empty)" if sec.is_empty else ""))
            src_lines.extend(lines)
        sections_meta.append(smeta)

    if ok:
        try:
            src_lines = lifter.lift_program(m)
        except lifter.Unsupported:
            pass

    meta["lifted_sections"] = sum(1 for s in sections_meta if s.get("lifted"))
    meta["sections"] = sections_meta

    if m.symbols:
        meta["symbols"] = m.symbols
        (mod_dir / "symbols.txt").write_text(chr(10).join(m.symbols))

    (mod_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    # VFP-facing artifact: written through the ONE explicit byte-producing path so
    # stored GBK bytes reach disk unchanged regardless of any input code-page mark
    # (docs/VERBATIM.md Option A). Never a default-encoding write_text.
    (mod_dir / "source.prg").write_bytes(codepage.prg_bytes(src_lines))
    return ok, reasons


def _record_dirname(index: int, name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "_-." else "_" for c in name)[:40]
    return "record_%04d_%s" % (index, safe) if safe else "record_%04d" % index


def cmd_decompile(args):
    path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    fmt, buf = _detect_format(path)
    verified = True
    module_count = 0
    records_without_code = 0
    record_parse_failures = 0
    reasons: list[str] = []

    if fmt == "table":
        # .scx/.vcx tables carry bytecode per record in the memo side-file: modules come
        # from OBJCODE records, never from magic-scanning the table bytes (which hold no
        # modules and would report a false "nothing here").
        codec = foxdbf.table_codec(path)
        for ri, (name, _src, code) in enumerate(foxdbf.objcode_records(path)):
            if not code:
                records_without_code += 1
                continue
            mod_dir = outdir / _record_dirname(ri, name)
            try:
                m = container.parse(code, codec=codec)
            except ValueError as e:
                # A record whose OBJCODE does not parse is REPORTED, never dropped.
                verified = False
                record_parse_failures += 1
                mod_dir.mkdir(parents=True, exist_ok=True)
                (mod_dir / "meta.json").write_text(json.dumps(
                    {"record": name, "parse_error": str(e)}, indent=2))
                continue
            module_count += 1
            ok, why = _lift_module(m, mod_dir, {"record": name})
            if not ok:
                verified = False
                reasons.extend(why)
    else:
        for off, m in _iter_modules(buf):
            module_count += 1
            ok, why = _lift_module(m, outdir / ("module_%06x" % off), {"offset": off})
            if not ok:
                verified = False
                reasons.extend(why)

    # Zero modules is a RED result, not a quiet success: an input with no parseable VFP
    # module must not ship as exit 0 + verified=True (the shipped "exit 0 on a red run"
    # defect class).
    if module_count == 0:
        verified = False
    result = {"outdir": str(outdir), "modules": module_count, "verified": verified}
    if records_without_code:
        result["records_without_code"] = records_without_code
    if record_parse_failures:
        result["record_parse_failures"] = record_parse_failures
    if reasons:
        result["reasons"] = reasons
        result["reason"] = reasons[0]
    if module_count == 0:
        result["reason"] = ("no record's OBJCODE parsed" if record_parse_failures
                            else "no VFP modules found in input")
    _emit(result, args.json)
    sys.exit(0 if verified else 2)


def cmd_extract(args):
    from foxlift.extract import extract_container

    path = Path(args.input)
    outdir = Path(args.outdir)
    result = extract_container(path, outdir)
    _emit(result, args.json)
    sys.exit(0 if result["landed"] == result["n_entries"] and not result["misses"] else 2)


# --- main --------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="foxlift",
        description="Visual FoxPro decompiler — compiled binary in, buildable project out"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )
    sub = parser.add_subparsers(dest="command")

    p_i = sub.add_parser("inspect", help="structural dump of a VFP binary")
    p_i.add_argument("input", help="input file (.fxp, .scx, .vcx, .exe, .app)")
    p_i.add_argument("--json", action="store_true", help="machine-readable JSON output")

    p_d = sub.add_parser("decompile", help="decompile binary to source tree")
    p_d.add_argument("input", help="input file")
    p_d.add_argument("-o", "--outdir", required=True, help="output directory")
    p_d.add_argument("--json", action="store_true", help="JSON output")

    p_e = sub.add_parser(
        "extract",
        help="extract an APP/EXE container to a named project tree",
    )
    p_e.add_argument("input", help="input .app or .exe")
    p_e.add_argument("-o", "--outdir", required=True, help="output directory")
    p_e.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()
    dispatch = {
        "inspect": cmd_inspect,
        "decompile": cmd_decompile,
        "extract": cmd_extract,
    }
    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        sys.exit(1)
    try:
        fn(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        # missing/unreadable input, unwritable outdir — a clean message, not a traceback
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
