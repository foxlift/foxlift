# ABOUTME: VM-free tests for the outer EXE/APP container reader (foxlift.appcontainer).
# ABOUTME: Containers are SYNTHESIZED here from the measured schema -- no corpus bytes committed.
#
# Schema under test (measured, probes/exe_container/): base 0 for .app / PE-overlay-end for
# EXE wrappers; header magic+version block with pool_end@+9 pool_start@+13; NUL-terminated
# name pool closed by a double-NUL; stride-25 records [u8 seq][u32 start][u32 end][u32 flags]
# [u32 size][u64 pad] whose first seq byte doubles as the terminator's second NUL; entry
# payloads tile contiguously between the header and the name pool.

import struct
from pathlib import Path

from foxlift import appcontainer
from foxlift.appcontainer import ContainerError


def build_container(entries, base=0):
    """entries: [(name, payload_bytes, col_x)] laid out as header | payloads | pool | records.

    Each record's col_y is the POOL-RELATIVE OFFSET OF ITS OWN NAME (the measured binding),
    so this builder also proves binding is by reference, not by position.
    Returns (buf, ranges)."""
    names = [n for n, _, _ in entries]
    payloads = b"".join(p for _, p, _ in entries)

    data_start = base + 21
    pool_start = data_start + len(payloads)
    pool = b"".join(n.encode() + b"\x00" for n in names) + b"\x00"
    pool_end = pool_start + len(pool)

    ranges, off = [], data_start
    for _, p, _ in entries:
        ranges.append((off, off + len(p)))
        off += len(p)

    name_off = {}
    o = 0
    for n in names:
        name_off[n] = o
        o += len(n) + 1

    total = pool_end + 25 * len(entries) + 8
    buf = bytearray(total)
    buf[base:base + 4] = b"\xfe\xf2\xff\x20"
    buf[base + 4:base + 9] = b"\x02\x01\x00\x00\x00"
    struct.pack_into("<I", buf, base + 9, pool_end - base)
    struct.pack_into("<I", buf, base + 13, pool_start - base)
    struct.pack_into("<I", buf, base + 17, len(names) + 7)
    buf[data_start:data_start + len(payloads)] = payloads
    buf[pool_start:pool_end] = pool

    term2 = pool_end                            # records start right after the pool
    for k, ((nm, _, cx), (st, en)) in enumerate(zip(entries, ranges)):
        r = term2 + 25 * k
        struct.pack_into("<IIII", buf, r + 1, st - base, en - base, cx, name_off[nm])
    return bytes(buf), ranges


def build_container_raw(names, ranges, flags=None, y=0):
    """Structural-abuse variant: arbitrary ranges, buffer sized to cover them."""
    flags = flags if flags is not None else [0x0E] * len(ranges)
    pool = b"".join(n.encode() + b"\x00" for n in names) + b"\x00"
    pool_start = 21
    pool_end = pool_start + len(pool)
    total = max(pool_end + 25 * len(ranges) + 8, max(e for _, e in ranges) + 1)
    buf = bytearray(total)
    buf[0:4] = b"\xfe\xf2\xff\x20"
    buf[4:9] = b"\x02\x01\x00\x00\x00"
    struct.pack_into("<I", buf, 9, pool_end)
    struct.pack_into("<I", buf, 13, pool_start)
    struct.pack_into("<I", buf, 17, len(names) + 7)
    buf[pool_start:pool_end] = pool
    term2 = pool_end
    for k, ((s, e), fl) in enumerate(zip(ranges, flags)):
        r = term2 + 25 * k
        struct.pack_into("<IIII", buf, r + 1, s, e, fl, y)
    return bytes(buf)


def fake_module() -> bytes:
    """Module-shaped bytes: magic + version block; enough for ownership classification."""
    return b"\xfe\xf2\xff\x20" + b"\x02\x01\x00\x00\x00" + b"\x00" * 8


def real_module() -> bytes:
    """A module the container reader fully parses: our own golden compiled fixture."""
    return (Path(__file__).resolve().parent / "fixtures" / "g01_assign.fxp").read_bytes()


def test_entries_recovered_with_name_type_offset_length_order():
    payload_a = b"PRGDATA" * 10
    payload_b = b"F" * 40
    raw = b"BMPBYTES!" * 5
    blob, ranges = build_container([
        ("aa_main.prg", payload_a, 0x0E),
        ("aa_form.scx", payload_b, 0x1D),
        ("aa_pic.bmp", raw, 0x3F),
    ])
    app = appcontainer.load(blob)

    assert app.accepted, app.problems
    assert [e.name for e in app.entries] == ["aa_main.prg", "aa_form.scx", "aa_pic.bmp"]
    assert [e.order for e in app.entries] == [0, 1, 2]
    assert [(e.start, e.end) for e in app.entries] == ranges
    assert [e.col_x for e in app.entries] == [0x0E, 0x1D, 0x3F]
    assert [(e.end - e.start) for e in app.entries] == [len(payload_a), len(payload_b), len(raw)]
    assert app.problems == []


def test_raw_resource_extract_is_byte_identical():
    raw = bytes(range(256)) * 3
    blob, ranges = build_container([("x.prg", b"\x01" * 16, 0x0E),
                                    ("y.bmp", raw, 0x3F)])
    app = appcontainer.load(blob)
    ent = app.entries[1]
    assert app.extract(blob, ent) == raw


def test_overlapping_ranges_flagged_and_rejected():
    buf = build_container_raw(["a.prg", "b.prg"], [(0x29, 0x100), (0x80, 0x140)])
    app = appcontainer.load(buf)
    assert len(app.entries) == 2                       # both records enumerated
    assert any("overlaps" in p for p in app.problems)
    assert not app.accepted


def test_records_without_y_reference_bind_empty_and_names_become_metadata():
    # raw variant writes col_y=0 (no pool reference): binding must degrade honestly
    buf = build_container_raw(["a.prg", "b.prg", "c.prg"],
                              [(0x29, 0x60), (0x60, 0x90)], y=0xFFFF)
    app = appcontainer.load(buf)
    assert len(app.entries) == 2
    assert all(e.name == "" for e in app.entries)
    assert any("outside the pool" in p for p in app.problems)
    assert any("metadata" in n for n in app.notes)


def test_pe_wrapper_base_derived_scan_free():
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe = bytearray(24 + 0xE0)                  # COFF header + claimed optional size
    pe[:4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, 6, 1)           # one section
    struct.pack_into("<H", pe, 20, 0xE0)       # SizeOfOptionalHeader
    struct.pack_into("<H", pe, 20, 0xE0)       # optional header size
    sect = bytearray(40)
    struct.pack_into("<I", sect, 16, 0x200)    # raw size
    struct.pack_into("<I", sect, 20, 0x1A0)    # raw pointer (real in-file data)
    image = bytes(dos) + bytes(pe) + bytes(sect) + b"\x00" * 0x200
    overlay_start = len(image)

    container_bytes = build_container([("m.prg", b"M" * 32, 0x0E)], base=overlay_start)[0]
    # the builder writes the header at index base; keep everything from there on
    blob = image + container_bytes[overlay_start:]

    app = appcontainer.load(blob)
    assert app.base == overlay_start
    assert app.entries[0].name == "m.prg"
    assert app.accepted


def test_unowned_magic_reported_as_structural_failure():
    # a module-shaped run sits in the gap between the last entry and the pool
    mod = fake_module()
    a0, a1 = 21, 21 + 16
    gap0 = a1
    names = ["a.prg"]
    pool = b"a.prg\x00\x00"
    pool_start = gap0 + len(mod) + 64
    pool_end = pool_start + len(pool)

    buf = bytearray(pool_end + 25 + 8)
    buf[0:4] = b"\xfe\xf2\xff\x20"
    buf[4:9] = b"\x02\x01\x00\x00\x00"
    struct.pack_into("<I", buf, 9, pool_end)
    struct.pack_into("<I", buf, 13, pool_start)
    struct.pack_into("<I", buf, 17, 8)
    buf[pool_start:pool_end] = pool
    buf[a0:a1] = b"\x07" * (a1 - a0)
    buf[gap0:gap0 + len(mod)] = mod
    term2 = pool_end - 1
    buf[term2] = 0
    struct.pack_into("<IIII", buf, term2 + 1, a0, a1, 0x0E, a1 - a0)

    app = appcontainer.load(bytes(buf))
    hits = appcontainer.classify_modules(bytes(buf), app)
    unowned = [h for h in hits if h.verdict == "unowned"]
    assert unowned, "module-shaped bytes outside every owned range must be flagged"
    assert all(h.owner == "" for h in unowned)


def test_owned_module_classified_through_its_entry():
    mod = real_module()
    blob, ranges = build_container([("m.prg", mod, 0x0E)])
    app = appcontainer.load(blob)
    hits = appcontainer.classify_modules(blob, app)
    owned = [h for h in hits if h.verdict in ("module", "empty")]
    assert owned and all(h.owner == "m.prg" for h in owned)
    assert not [h for h in hits if h.verdict == "unowned"]


def test_chain_gap_over_limit_stops_cleanly():
    a0, a1 = 0x29, 0x60
    far0 = a1 + appcontainer.MAX_GAP + 0x10
    far1 = far0 + 0x20
    names = ["a.prg", "b.prg"]
    pool = b"".join(n.encode() + b"\x00" for n in names) + b"\x00"
    pool_start = far1 + 16
    pool_end = pool_start + len(pool)
    buf = bytearray(pool_end + 25 * 2 + 8)
    buf[0:4] = b"\xfe\xf2\xff\x20"
    buf[4:9] = b"\x02\x01\x00\x00\x00"
    struct.pack_into("<I", buf, 9, pool_end)
    struct.pack_into("<I", buf, 13, pool_start)
    struct.pack_into("<I", buf, 17, 9)
    buf[pool_start:pool_end] = pool
    term2 = pool_end - 1
    for k, (s, e) in enumerate([(a0, a1), (far0, far1)]):
        r = term2 + 25 * k
        buf[r] = k
        struct.pack_into("<IIII", buf, r + 1, s, e, 0x0E, e - s)

    app = appcontainer.load(bytes(buf))
    # records stay enumerated (individually plausible); the unbounded gap and the
    # resulting overlap are flagged as validation problems, never silently dropped
    assert len(app.entries) == 2
    assert any("overlaps" in p for p in app.problems)
    assert any("tile only" in p for p in app.problems)
    assert not app.accepted


def test_plain_app_base_is_zero_and_garbage_rejected():
    blob, _ = build_container([("x.prg", b"P" * 16, 0x0E)])
    app = appcontainer.load(blob)
    assert app.base == 0
    try:
        appcontainer.load(b"\x00" * 64)
        raise AssertionError("expected ContainerError")
    except ContainerError:
        pass
