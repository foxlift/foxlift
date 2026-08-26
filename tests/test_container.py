#!/usr/bin/env python3
# VM-free regression tests for the container/dbf readers.
# Runs without the oracle or corpus: python3 tests/test_container.py
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from foxlift import container, dbf

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MAGIC = b"\xfe\xf2\xff\x20"


def _stmt(body):
    """A statement frame from raw body bytes (which must end in fe)."""
    return struct.pack('<H', len(body) + 2) + body


def _module(sections, magic=MAGIC, header_pad=8):
    """Synthetic module under the measured rule: N = marker + statements + terminator."""
    out = bytearray(magic)
    out += bytes(header_pad)
    for marker, wide, stmt_bodies in sections:
        stmts = b''
        for b in stmt_bodies:
            stmts += _stmt(b)
        n = 1 + len(stmts) + 2
        out += bytes([marker])
        out += struct.pack('<I' if wide else '<H', n)
        out += stmts
        out += b'\x03\x00'
    return bytes(out)


def test_golden_fixtures():
    """Every committed oracle-captured fixture parses fully."""
    hexes = sorted(FIXTURES.glob("*.fxp.hex"))
    assert len(hexes) == 4, hexes
    for hx in hexes:
        fxp = bytes.fromhex(hx.read_text().strip())
        m = container.parse(fxp)
        assert m.sections, hx.name
        for sec in m.sections:
            for s in sec.statements:
                assert s.known, (hx.name, s.offset)


def test_golden_macro_verbatim():
    """The macro statement comes back as the verbatim source line."""
    fxp = bytes.fromhex((FIXTURES / "g03_macro.fxp.hex").read_text().strip())
    m = container.parse(fxp)
    texts = [s.text for s in m.statements if s.text is not None]
    assert any("&x" in t for t in texts), texts


def test_golden_empty_method_section():
    """DEFINE CLASS with an empty PROCEDURE yields a kept empty section."""
    fxp = bytes.fromhex((FIXTURES / "g04_empty_method.fxp.hex").read_text().strip())
    m = container.parse(fxp)
    assert any(sec.is_empty for sec in m.sections), (
        [(s.framing, s.declared, len(s.statements)) for s in m.sections])


def test_synthetic_empty_frame_and_symbols():
    """fc 03 00 03 00 plus a symbol table parses to one empty named section."""
    buf = _module([(0xFC, False, [])]) + b'\x55\x01\x00\x02\x00' + b'ok'
    m = container.parse(buf)
    assert len(m.sections) == 1 and m.sections[0].is_empty
    assert m.symbols == ["ok"] and m.symbols_parsed


def test_u32_framing_synthetic():
    """A u32-length-field section parses and reports its framing."""
    body = bytes([0x02, 0xF8, 0x03, 0x01]) + b'\xfe'
    buf = _module([(0x00, True, [body])])
    m = container.parse(buf)
    assert len(m.sections) == 1
    assert m.sections[0].framing == "u32"
    assert len(m.sections[0].statements) == 1


def test_all_unknown_section_rejected():
    """Metadata that tiles but has no statement shape must not pass as code (STATUS #11)."""
    junk_body = bytes([0x01, 0x44, 0x00, 0x41])  # not macro-shaped, does not end in fe
    stmts = struct.pack('<H', len(junk_body) + 2) + junk_body
    n = 1 + len(stmts) + 2
    buf = MAGIC + bytes(8) + bytes([0xFC]) + struct.pack('<H', n) + stmts + bytes([3, 0])
    hits = container.classify_hits(buf)
    assert len(hits) == 1 and hits[0].status == 'rejected', hits[0].status


def test_false_magic_hit_rejected():
    """An embedded DBF header beginning with the magic is not a module (application-executable carrier, offset 0x38cc)."""
    fake = MAGIC + b'\x02\xcd\x00\x12\x00' + b'PLATFORM' * 4 + bytes(64)
    hits = container.classify_hits(fake)
    assert len(hits) == 1
    assert hits[0].status == 'rejected'


def test_oversized_macro_statement():
    """Statements past the old 4,096 cap parse (buyskpiprint Command2 was 8,004)."""
    payload = bytes([0x01]) + b'? ' + b'x' * 8989 + bytes([0x0A])
    assert len(payload) + 2 > 8004
    buf = _module([(0xFC, False, [payload])])
    m = container.parse(buf)
    assert len(m.statements) == 1 and m.statements[0].text is not None


def test_adjacent_modules_do_not_bleed():
    """Symbol tables stop at the next module boundary."""
    def build(symname):
        inner = bytes([0x54])
        stmt = struct.pack('<H', len(inner) + 3) + inner + b'\xfe'
        table = bytes([0x55, 1, 0]) + struct.pack('<H', len(symname)) + symname
        return _module([(0xFC, False, [stmt])]) + table
    both = build(b'AAAA') + build(b'BBBB')
    ma = container.parse(both, 0)
    assert ma.symbols == ["AAAA"], ma.symbols


def test_error_line_verbatim_b4():
    """Lines the compiler rejected store verbatim under marker b4 (oracle-measured)."""
    line = b'SELECT * FROM c WHERE ????????<>0 INTO CURSOR d'
    payload = bytes([0xB4]) + line + b'\x0a'
    buf = _module([(0xFC, False, [payload])])
    m = container.parse(buf)
    assert len(m.statements) == 1
    s = m.statements[0]
    assert s.known and s.text is not None and s.text == line.decode('latin1'), repr(s.text)


def test_decode_text_code_pages():
    """Known marks decode; unknown marks fall back byte-preserving."""
    assert dbf.decode_text(b"abc", 0x03) == "abc"
    chinese = bytes([0xB2, 0xC6, 0xCE, 0xF1])
    assert dbf.decode_text(chinese, 0x7A) == chinese.decode("gbk")
    raw = bytes([0xC4, 0x85])
    assert dbf.decode_text(raw, 0x99) == raw.decode("latin1")


def main():
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except AssertionError as e:
                print("FAIL", name, repr(e))
                fails.append(name)
    print(len(fails), 'failures')
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())