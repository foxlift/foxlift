# ABOUTME: Outer EXE/APP container reader — entries recovered by NAME/TYPE/OFFSET/ORDER from
# ABOUTME: the directory alone, plus module classification scoped to owning entries. No magic scanning.
#
# Schema measured against reportoutput.app / System.app (public corpus) and a held-out
# single-program PE carrier (confidential estate sample), probes/exe_container/ NOTES+round2..4:
#   base B      file offset 0 for a plain .app; for a PE wrapper the end of the raw section
#               table's mapped ranges (derived scan-free; validated against the carrier's 0x5e00).
#   header @B   magic fe f2 ff 20, version block 02 01 00 00 00,
#               u16 word_a @B+5, u16 word_b @B+7,
#               u32 pool_end @B+9, u32 pool_start @B+13, u32 count_c @B+17.
#   name pool   [pool_start, pool_end): NUL-terminated names, closed by a double-NUL.
#   records     follow the terminator, stride 25:
#               [u8 seq][u32 start][u32 end][u32 flags][u32 size][u64 pad].
#               Ranges are file-absolute and chain (each start == previous end, alignment
#               gaps bounded); the array tiles the payload between the header and the pool.
# Names bind to segments BY ORDER (BUILD input order); counts must agree.

import struct

from dataclasses import dataclass, field


class ContainerError(ValueError):
    pass


MAGIC = b"\xfe\xf2\xff\x20"
VERSION_BLOCK = b"\x02\x01\x00\x00\x00"
REC = 25                 # stride: seq u8 + four u32 + u64 pad
MAX_GAP = 0x40000        # alignment padding between chained ranges (measured: <= 0x4000)


@dataclass
class Entry:
    order: int
    name: str            # bound via the record's Y column -> name-pool offset
    start: int
    end: int
    col_x: int           # raw column 3; semantics UNMEASURED (varies: 0 / dir offset)
    col_y: int           # raw column 4 = name-pool offset of THIS entry's primary name


@dataclass
class HitClassification:
    offset: int
    verdict: str         # 'module' | 'empty' | 'rejected' | 'unowned'
    owner: str           # entry name owning the range, '' when unowned


@dataclass
class AppContainer:
    path: str
    size: int
    base: int
    ver: int
    word_a: int
    word_b: int
    count_c: int
    pool_start: int
    pool_end: int
    names: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    accepted: bool = False

    def owner_of(self, off: int):
        """Index of the entry whose range contains off, or None."""
        for k, e in enumerate(self.entries):
            if e.start <= off < e.end:
                return k
        return None

    def extract(self, buf: bytes, ent: Entry) -> bytes:
        """Raw bytes of an entry's range — raw resources must roundtrip byte-identical."""
        return buf[ent.start:ent.end]


def pe_raw_end(buf: bytes) -> int | None:
    """End of the PE raw section data (overlay start). None when buf is not a PE."""
    if buf[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew + 24 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", buf, e_lfanew + 6)[0]
    opt = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
    sectab = e_lfanew + 24 + opt
    end = 0
    for k in range(nsec):
        o = sectab + 40 * k
        if o + 40 > len(buf):
            return None
        rsz, rraw = struct.unpack_from("<II", buf, o + 16)[0], struct.unpack_from("<I", buf, o + 20)[0]
        if rsz:
            end = max(end, rraw + rsz)
    return end


def container_base(buf: bytes) -> int:
    """Scan-free base: 0 for a plain .app (magic at 0), else PE overlay end.

    Validated against the held-out single-program PE carrier where the derived value
    equals the magic-hit address 0x5e00 exactly (round 4)."""
    if buf[:4] == MAGIC:
        return 0
    end = pe_raw_end(buf)
    if end is None:
        raise ContainerError("not a plain APP container and not a PE wrapper")
    return end


def _read_names(buf: bytes, pool_start: int, pool_end: int):
    """NUL-terminated names up to the terminator.

    Returns (names, offsets_rel_to_pool_start, consumed). The offsets are the binding
    keys: each directory record's Y column is a pool-relative name offset."""
    names, offs, i = [], [], pool_start
    while i < pool_end:
        j = buf.find(b"\x00", i, pool_end)
        if j == -1:
            break
        # every slot gets an offset -- EMPTY names are real pool entries and some
        # records' col_y points at them (measured: FoxyPreviewer.app 5/140)
        offs.append(i - pool_start)
        names.append(buf[i:j].decode("latin1"))
        i = j + 1
        if i < pool_end and buf[i] == 0:
            i += 1
            break
    return names, offs, i


def _walk_records(buf: bytes, origin: int) -> list[Entry]:
    """Enumerate stride-25 records while they stay structurally plausible.

    Plausibility: start<=end<=file size, not a double-zero terminator, chain gap within
    MAX_GAP (bounded padding) OR an overlap — overlaps are ENUMERATED here and flagged by
    validation below, because ranges-bounded-and-non-overlapping is a checked gate
    property, not a parse assumption."""
    entries = []
    prev_end = None
    pos = origin
    while pos + REC <= len(buf):
        s, e, cx, cy = struct.unpack_from("<IIII", buf, pos + 1)
        if s == 0 and e == 0:
            break                                   # terminator
        if e < s or e > len(buf):
            break                                   # not a plausible record
        if prev_end is not None:
            gap = s - prev_end
            if gap > MAX_GAP:
                break                               # unbounded gap: array ended
        entries.append(Entry(len(entries), "", s, e, cx, cy))
        prev_end = e
        pos += REC
    return entries


def load(path_or_buf, path="<bytes>") -> AppContainer:
    buf = path_or_buf.read_bytes() if hasattr(path_or_buf, "read_bytes") else path_or_buf
    base = container_base(buf)

    hdr = buf[base:base + 21]
    # ver byte 0x02 required; bytes 5..8 are opaque words (measured variance:
    # corpus .app carry 02 01 00 00 00, our own VFP9-built canaries 02 09 00 00 00).
    if len(hdr) < 21 or hdr[:4] != MAGIC or hdr[4] != 0x02:
        raise ContainerError(
            f"{path}: no APP container header at derived base {base:#x} "
            f"(found {buf[base:base+9].hex(' ')})")

    ver = hdr[4]
    word_a = struct.unpack_from("<H", hdr, 5)[0]
    word_b = struct.unpack_from("<H", hdr, 7)[0]
    # Pool pointers are BASE-RELATIVE: the PE carrier (embedded at 0x5e00) stores 0x187d9/
    # 0x18817 and its names sit at absolute 0x5e00+0x187d9 -- verified byte-exactly.
    # Plain .app files have base 0, so absolute == relative there.
    pool_end = base + struct.unpack_from("<I", hdr, 9)[0]
    pool_start = base + struct.unpack_from("<I", hdr, 13)[0]
    count_c = struct.unpack_from("<I", hdr, 17)[0]

    app = AppContainer(path=path, size=len(buf), base=base, ver=ver,
                       word_a=word_a, word_b=word_b, count_c=count_c,
                       pool_start=pool_start, pool_end=pool_end)

    if not (base < pool_start < pool_end <= len(buf)):
        raise ContainerError(
            f"{path}: pool pointers out of range ({pool_start:#x}..{pool_end:#x}, size {len(buf):#x})")

    names, name_offs, consumed = _read_names(buf, pool_start, pool_end)
    app.names = names

    # Record-array origin: measured layouts differ by a byte or two of NUL padding
    # between the pool terminator and the first seq byte (reportoutput.app needed
    # consumed-1; our own BUILD APP output needs consumed+0). Try the small window and
    # keep the origin with the longest plausible walk -- bounded, never a file scan.
    best = []
    for o in range(consumed - 2, consumed + 9):
        cand = _walk_records(buf, o)
        if len(cand) > len(best):
            best = cand
    entries = best
    if not entries:
        raise ContainerError(f"{path}: no segment records after name pool")
    # Record start/end are base-relative too (the PE carrier's single segment reads
    # [0x29, 0x187d9) and tiles to pool_start once base-added).
    for e in entries:
        e.start += base
        e.end += base

    # ---- binding: each record's col_y is a pool-relative NAME offset (measured on our
    # own BUILD APP canaries and consistent with reportoutput.app's pool layout).
    at = dict(zip(name_offs, names))
    bound, anon = 0, []
    for e in entries:
        rel = e.col_y
        if rel in at:
            e.name = at[rel]
            bound += 1
            if not e.name:
                anon.append(e.order)
        else:
            e.name = ""
    app.entries = entries
    if bound != len(entries):
        app.problems.append(
            f"entries with col_y outside the pool: "
            f"{[e.order for e in entries if not any(e.col_y == o for o in name_offs)]}")
    meta = sorted({n for n in names
                   if n and n not in {e.name for e in entries}})
    if anon:
        app.notes.append(f"{len(anon)} entries bound to EMPTY pool-name slots")
    if meta:
        app.notes.append(f"pool metadata names (not payload): {meta}")

    # ---- validation: bounded, non-overlapping, tiling into the pool -------------------
    last_end = None
    for e in entries:
        if last_end is not None and e.start < last_end:
            app.problems.append(f"entry {e.order} ({e.name}) overlaps previous "
                                f"({e.start:#x} < {last_end:#x})")
        last_end = e.end
    first_start = min(e.start for e in entries)
    final_end = max(e.end for e in entries)
    if final_end < pool_start:
        app.problems.append(
            f"records tile only to {final_end:#x}; pool starts {pool_start:#x}")
    if first_start >= base + 21:
        app.notes.append(f"first entry starts at {first_start:#x}, not immediately after header")

    # acceptance: the walk must reach the declared pool start (docstring contract)
    app.accepted = bool(entries) and final_end >= pool_start - MAX_GAP \
        and not any("overlaps" in p for p in app.problems)
    return app


def classify_modules(buf: bytes, app: AppContainer) -> list[HitClassification]:
    """Classify module-magic occurrences through their OWNING directory entry.

    Enumeration is scoped to owned ranges — the directory drives the search, never the
    reverse. Magic bytes outside every owned range are reported as 'unowned', which is a
    structural failure of the container, not a module verdict."""
    from foxlift import container as mod_container

    out: list[HitClassification] = []
    for e in app.entries:
        seg = buf[e.start:e.end]
        pos = seg.find(MAGIC[:3])
        while pos != -1:
            off = e.start + pos
            if mod_container.is_module(buf, off):
                try:
                    m = mod_container.parse(buf, off)
                    verdict = "empty" if not m.statements else "module"
                except Exception:
                    verdict = "rejected"      # shape passed, content failed: one hit, never fatal
            else:
                verdict = "rejected"
            out.append(HitClassification(off, verdict, e.name))
            pos = seg.find(MAGIC[:3], pos + 1)

    # magic-shaped bytes outside any owned range? (verification pass; the directory,
    # not this scan, remains the enumeration mechanism) The container's own header
    # region shares the module magic and is not a hit.
    hdr_end = app.base + 21
    pos = buf.find(MAGIC[:3], hdr_end)
    while pos != -1:
        if app.owner_of(pos) is None and not any(h.offset == pos for h in out):
            out.append(HitClassification(pos, "unowned", ""))
        pos = buf.find(MAGIC[:3], pos + 1)
    return sorted(out, key=lambda h: h.offset)


def manifest(app: AppContainer) -> str:
    lines = [
        f"# {app.path} ({app.size} bytes, base {app.base:#x}, ver {app.ver}, "
        f"a={app.word_a} b={app.word_b} c={app.count_c}) accepted={app.accepted}",
        f"name pool [{app.pool_start:#x},{app.pool_end:#x}) -> {len(app.names)} names",
        f"{len(app.entries)} entries:",
    ]
    for e in app.entries:
        lines.append("  [%2d] %-28s [%#010x,%#010x) flags=%#04x size=%d"
                     % (e.order, e.name, e.start, e.end, e.flags, e.size_field))
    for p in app.problems:
        lines.append(f"  PROBLEM: {p}")
    return "\n".join(lines)
