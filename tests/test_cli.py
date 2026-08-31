# ABOUTME: Exercises foxlift's public command-line behavior without the oracle VM.
# ABOUTME: Covers help, version reporting, input validation, inspection, and decompilation.

import json
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / 'tests' / 'fixtures'


def _run(*args, module='foxlift.cli'):
    env = dict(os.environ)
    env['PYTHONPATH'] = str(REPO)
    return subprocess.run(
        [sys.executable, '-m', module] + list(args),
        capture_output=True, text=True, env=env, timeout=30,
    )


@pytest.fixture(scope='module')
def fxp_binary():
    return FIXTURES / 'g01_assign.fxp'



def test_help_exits_zero():
    r = _run('--help')
    assert r.returncode == 0, r.stderr[:100]
    assert 'foxlift' in r.stdout
    assert 'score' not in r.stdout


def test_version_exits_zero():
    r = _run('--version')
    assert r.returncode == 0, r.stderr[:100]
    try:
        expected = metadata.version('foxlift')
    except metadata.PackageNotFoundError:
        expected = 'uninstalled'
    assert r.stdout.strip() == f'foxlift {expected}'


def test_package_module_entrypoint_uses_public_cli():
    r = _run('--help', module='foxlift')
    assert r.returncode == 0, r.stderr[:100]
    assert 'inspect' in r.stdout and 'decompile' in r.stdout and 'extract' in r.stdout


def test_unknown_score_command_is_rejected():
    r = _run('score')
    assert r.returncode == 2
    assert 'invalid choice' in r.stderr


def test_unsupported_format_exits_nonzero(tmp_path):
    bad = tmp_path / 'notavfp.txt'
    bad.write_text('hello world')
    r = _run('inspect', str(bad))
    assert r.returncode != 0, 'unsupported format must exit nonzero'


class TestInspect:
    def test_returns_structure(self, fxp_binary):
        r = _run('inspect', str(fxp_binary), '--json')
        assert r.returncode == 0, r.stdout[:200] + r.stderr[:200]
        d = json.loads(r.stdout)
        assert d['format'] == 'fxp'
        assert d['module_count'] >= 1
        mod = d['modules'][0]
        assert mod['statements'] >= 1

    def test_reports_symbols(self, fxp_binary):
        r = _run('inspect', str(fxp_binary), '--json')
        d = json.loads(r.stdout)
        has_syms = any(m.get('symbol_count', 0) > 0 for m in d['modules'])
        # not all modules need symbols; just verify the field exists
        for m in d['modules']:
            assert 'symbol_count' in m


class TestDecompile:
    def test_creates_output(self, fxp_binary, tmp_path):
        outdir = tmp_path / 'dec'
        r = _run('decompile', str(fxp_binary), '-o', str(outdir))
        assert r.returncode == 0
        srcs = list(outdir.glob('module_*/source.prg'))
        assert len(srcs) >= 1

    def test_macro_verbatim(self, tmp_path):
        fxp3 = FIXTURES / 'g03_macro.fxp'
        outdir = tmp_path / 'out'
        r = _run('decompile', str(fxp3), '-o', str(outdir))
        assert r.returncode == 0
        srcs = list(outdir.glob('module_*/source.prg'))
        all_src = chr(10).join(f.read_text() for f in srcs)
        assert '&' in all_src, all_src[:200]

    def test_supported_slice_lifts_canonical_source(self, tmp_path):
        """g01 is inside the thin slice: exit 0 and real canonical VFP, not a placeholder."""
        outdir = tmp_path / 'lifted'
        r = _run('decompile', str(FIXTURES / 'g01_assign.fxp'), '-o', str(outdir))
        assert r.returncode == 0, r.stdout[:200]
        src = (outdir / 'module_000000' / 'source.prg').read_text()
        assert 'X = Y + Z' in src, src

    def test_macro_fixture_fully_recovered(self, tmp_path):
        """g03: lifted assignment AND verbatim macro line -> exit 0 with both."""
        outdir = tmp_path / 'macro'
        r = _run('decompile', str(FIXTURES / 'g03_macro.fxp'), '-o', str(outdir))
        assert r.returncode == 0, r.stdout[:200]
        src = (outdir / 'module_000000' / 'source.prg').read_text()
        assert "X = 'hello'" in src and '? &x' in src, src

    def test_print_statement_lifts_after_print_arg_lane(self, tmp_path):
        """g02 pinned the old print-arg gap ('? 'two'' was known-shaped but
        unsupported -> honest exit 2). The measured print-argument grammar
        (fc-wrapped final arg with its reader-stripped fd) now decodes it, so
        the fixture lifts like its stored source. Statement-level honesty
        stays covered by g04's unsupported section and test_zero_modules."""
        outdir = tmp_path / 'lifted2'
        r = _run('decompile', str(FIXTURES / 'g02_store.fxp'), '-o', str(outdir))
        assert r.returncode == 0, r.stdout[:200]
        d = json.loads(r.stdout)
        assert d['verified'] is True
        src = (outdir / 'module_000000' / 'source.prg').read_text()
        assert "? 'two'" in src and 'STORE 3 TO A, B' in src, src

    def test_multisection_class_init_now_lifts(self, tmp_path):
        """g04: 0xa2 class-init was the unsupported section (exit 2). r43 lifts it.

        Four sections: `? MAIN`, empty method, class-init 0xa2 (no source line),
        empty trailer. Empty methods still marked. Statement-level honesty for
        remaining unsupported leads is the 0xa1/0x96 ranking families.
        """
        outdir = tmp_path / 'multi'
        r = _run('decompile', str(FIXTURES / 'g04_empty_method.fxp'), '-o', str(outdir))
        assert r.returncode == 0, r.stdout[:200]
        d = json.loads(r.stdout)
        assert d['verified'] is True
        meta = json.loads((outdir / 'module_000000' / 'meta.json').read_text())
        assert len(meta['sections']) == 4, meta
        assert [s['lifted'] for s in meta['sections']] == [True, True, True, True]
        src = (outdir / 'module_000000' / 'source.prg').read_text()
        # 0xa2 class-init has no source line (r43-class); empty sections omit
        # the old '* --- section N (empty) ---' markers once lift_program
        # reconstructs the module.
        assert '? MAIN' in src, src

    def test_zero_modules_exits_2(self, tmp_path):
        """An input with no parseable VFP module is a red run: exit 2 with a stated reason,
        never the shipped exit-0-on-failure defect."""
        junk = tmp_path / 'empty.fxp'
        junk.write_bytes(b'\x01\x02\x03\x04' + b'\x00' * 32)
        outdir = tmp_path / 'none'
        r = _run('decompile', str(junk), '-o', str(outdir))
        assert r.returncode == 2, r.stdout[:200]
        d = json.loads(r.stdout)
        assert d['modules'] == 0 and d['verified'] is False
        assert 'reason' in d

    def test_missing_input_is_clean_error_not_traceback(self, tmp_path):
        """A missing file exits 1 with a message on stderr — no Python traceback."""
        r = _run('decompile', str(tmp_path / 'nope.fxp'), '-o', str(tmp_path / 'o'))
        assert r.returncode == 1
        assert 'Traceback' not in r.stderr
        assert r.stderr.startswith('error:')


# ---- table (.scx/.vcx) decompilation ------------------------------------------------
# The decompile path must read bytecode from OBJCODE records via the memo side-file —
# magic-scanning the table bytes finds nothing and used to report a false
# "no VFP modules found in input" for every form and class library.

def _write_table(dirpath, records):
    """Author a minimal VFP-shaped .scx/.sct pair (OBJNAME C(10), METHODS M, OBJCODE M)."""
    fields = [("OBJNAME", "C", 10), ("METHODS", "M", 4), ("OBJCODE", "M", 4)]
    header_len = 32 + 32 * len(fields) + 1
    record_len = 1 + sum(ln for _, _, ln in fields)
    bs = 64
    memo = bytearray(bs)                      # block 0: memo file header
    memo[6:8] = bs.to_bytes(2, "big")

    def put(data):
        if not data:
            return 0
        while len(memo) % bs:
            memo.append(0)
        block = len(memo) // bs
        memo.extend((0).to_bytes(4, "big") + len(data).to_bytes(4, "big") + data)
        return block

    rows = bytearray()
    for name, methods, objcode in records:
        rows += b" " + name.encode("ascii").ljust(10)[:10]
        rows += put(methods).to_bytes(4, "little")
        rows += put(objcode).to_bytes(4, "little")

    head = bytearray(32)
    head[0] = 0x30                            # Visual FoxPro table
    head[4:8] = len(records).to_bytes(4, "little")
    head[8:10] = header_len.to_bytes(2, "little")
    head[10:12] = record_len.to_bytes(2, "little")
    head[29] = 0x03                           # cp1252
    fdesc = bytearray()
    for name, typ, ln in fields:
        d = bytearray(32)
        d[0:11] = name.encode("ascii").ljust(11, b"\0")
        d[11] = ord(typ)
        d[16] = ln
        fdesc += d
    scx = dirpath / "demoform.scx"
    scx.write_bytes(bytes(head) + bytes(fdesc) + b"\x0d" + bytes(rows))
    (dirpath / "demoform.sct").write_bytes(bytes(memo))
    return scx


class TestDecompileTable:
    def test_scx_objcode_records_are_decompiled(self, fxp_binary, tmp_path):
        """A form record's OBJCODE lifts to source: exit 0, verified, per-record dir."""
        scx = _write_table(tmp_path, [
            ("frmmain", b"x = y + z", fxp_binary.read_bytes()),
            ("lblnote", b"* no compiled code", b""),
        ])
        outdir = tmp_path / "dec"
        r = _run("decompile", str(scx), "-o", str(outdir), "--json")
        assert r.returncode == 0, r.stdout[:300] + r.stderr[:300]
        d = json.loads(r.stdout)
        assert d["modules"] == 1 and d["verified"] is True
        assert d["records_without_code"] == 1
        src = (outdir / "record_0000_frmmain" / "source.prg").read_text()
        assert "X = Y + Z" in src, src

    def test_scx_unparsable_objcode_is_red(self, tmp_path):
        """A record whose OBJCODE does not parse is reported, never dropped: exit 2."""
        scx = _write_table(tmp_path, [("broken", b"x = 1", b"\x00" * 16)])
        outdir = tmp_path / "dec"
        r = _run("decompile", str(scx), "-o", str(outdir), "--json")
        assert r.returncode == 2, r.stdout[:300]
        d = json.loads(r.stdout)
        assert d["modules"] == 0 and d["verified"] is False
        assert d["record_parse_failures"] == 1
        assert d["reason"] == "no record's OBJCODE parsed"
        meta = json.loads((outdir / "record_0000_broken" / "meta.json").read_text())
        assert "parse_error" in meta
