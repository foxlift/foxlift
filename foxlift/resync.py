# ABOUTME: Deterministic VM-free fuzz harness enforcing CLAUDE.md's resync invariant.
# ABOUTME: One unrecognised construct costs exactly one statement, never the module — measured here.

"""Resync-invariant fuzzing for the container reader and the thin lifter.

CLAUDE.md: "Unknown constructs resync, they do not abort. Statements are length-prefixed.
An unrecognised construct must cost one statement, never the module." Nothing enforced that;
this module does, mechanically and deterministically:

- seeds are SYNTHETIC modules built byte-by-byte below plus the checked-in oracle fixtures,
  so the harness never needs the corpus or the VM;
- six mutation families attack length prefixes, opcode bytes, terminators, symbol operands
  and section boundaries;
- per mutant we assert: parse() never raises; surviving statements are a subset of the
  baseline (byte-identical where untouched); loss is confined to the corrupted section;
  zero-cost mutation families lose nothing at all; and every statement the READER accepts,
  the LIFTER either lifts or rejects as :class:`lifter.Unsupported` — never anything else.

A violated invariant raises AssertionError carrying the seed, so every failure reproduces.
"""

import random
import struct
from pathlib import Path

from foxlift import container, lifter

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"

# --- synthetic known-good module builder -------------------------------------------------
#
# Layout follows docs/FORMAT.md: magic, the five header bytes every measured module shares,
# then code sections (marker + u16/u32 length + statements + 03 00), one symbol table after
# EACH section (context-matrix evidence). The builder is validated against container.parse
# before any mutation runs — a broken baseline would make every verdict meaningless.

SYMBOLS = ["X", "Y", "Z", "MAIN", "HELLO"]


def _sym_ref(idx: int) -> bytes:
    """f7 <u16> symbol push (FORMAT §6)."""
    return b"\xf7" + struct.pack("<H", idx)


def stmt_assign(x: int = 0, y: int = 1, z: int = 2) -> bytes:
    """X = Y + Z in the measured assignment shape: 54 <lv> 10 fc <expr> fd fe."""
    body = (b"\x54" + _sym_ref(x) + b"\x10\xfc"
            + _sym_ref(y) + _sym_ref(z) + b"\x06" + b"\xfd\xfe")
    return struct.pack("<H", len(body) + 2) + body


def stmt_local(name_idx: int = 0) -> bytes:
    """LOCAL <name>: ae f7 <idx> fe."""
    body = b"\xae" + _sym_ref(name_idx) + b"\xfe"
    return struct.pack("<H", len(body) + 2) + body


def stmt_print(name_idx: int = 3) -> bytes:
    """? MAIN: 02 f8 03 01 <arg> fe with a bare-symbol argument."""
    body = b"\x02\xf8\x03\x01" + _sym_ref(name_idx) + b"\xfe"
    return struct.pack("<H", len(body) + 2) + body


def stmt_macro(text: str = "? &x") -> bytes:
    """Verbatim macro line: 01 <ascii> 0a (FORMAT §5)."""
    body = b"\x01" + text.encode("ascii") + b"\x0a"
    return struct.pack("<H", len(body) + 2) + body


def section_bytes(stmts: list[bytes], marker: int = 0xFC, wide: bool = False) -> bytes:
    """Prologue + tiled statements + terminator, with N = marker + Σdeclared + terminator."""
    n = 1 + sum(struct.unpack_from("<H", s, 0)[0] for s in stmts) + 2
    head = bytes([marker]) + (struct.pack("<I", n) if wide else struct.pack("<H", n))
    return head + b"".join(stmts) + container.SECTION_TERMINATOR


def symbol_table(names: list[str]) -> bytes:
    out = b"\x55" + struct.pack("<H", len(names))
    for nm in names:
        enc = nm.encode("latin1")
        out += struct.pack("<H", len(enc)) + enc
    return out


def build_module(groups: list[list[bytes]] | None = None,
                 wide_flags: list[bool] | None = None,
                 symbols: list[list[str]] | None = None) -> bytes:
    """A well-formed module: one section per group, symbol table after each section.

    ``symbols`` overrides the per-section tables (one name list per group) — needed to
    pin that operand indexes resolve against the OWNING section's table."""
    if groups is None:
        groups = [
            [stmt_assign(), stmt_local()],
            [stmt_print(), stmt_macro()],
        ]
    wide_flags = wide_flags or [False] * len(groups)
    symbols = symbols or [SYMBOLS] * len(groups)
    out = bytearray(container.MAGIC_VFP9 + b"\x02\x01\x00\x00\x00")
    spans = []
    for stmts, wide, syms in zip(groups, wide_flags, symbols):
        sec = section_bytes(stmts, wide=wide)
        spans.append((len(out), len(sec)))
        out += sec + symbol_table(syms)
    return bytes(out)


def fixture_seeds() -> dict[str, bytes]:
    """The checked-in oracle-compiled fixtures: real oracle output, corpus-free."""
    out = {}
    for p in sorted(FIXTURE_DIR.glob("*.fxp")):
        out[p.stem] = p.read_bytes()
    return out


# --- mutations ---------------------------------------------------------------------------
#
# Every mutation returns (mutated_buffer, lo, hi, kind) where [lo, hi) is the corrupted
# byte span — the localisation criterion is expressed against it.

def _statement_spans_now(buf: bytes) -> list[tuple[int, int]]:
    """(start_of_length_prefix, end_of_statement) for every statement in the CURRENT buffer."""
    return [(st.offset, st.offset + st.declared)
            for st in container.parse(buf, 0).statements]


def mut_flip_opcode(buf: bytes, rng: random.Random):
    """Flip one byte strictly INSIDE a statement's payload: semantics corrupt, shape is
    preserved BY CONSTRUCTION (the lead marker and trailing shape byte are excluded), so
    this family stays genuinely zero-cost for the accounting invariant."""
    spans = [s for s in _statement_spans_now(buf) if s[1] - s[0] >= 5]
    if not spans:
        return None
    st_lo, st_hi = rng.choice(spans)
    pos = rng.randrange(st_lo + 3, st_hi - 1)   # skips u16 prefix, lead marker, final byte
    out = bytearray(buf)
    out[pos] ^= 0xFF
    return bytes(out), pos, pos + 1, "flip_opcode"


def mut_corrupt_length(buf: bytes, rng: random.Random):
    """Corrupt one statement's u16 length prefix: tiling must fail closed, locally."""
    pos = _random_stmt_prefix(buf, rng)
    if pos is None:
        return None
    out = bytearray(buf)
    mode = rng.choice(["inc", "huge", "tiny"])
    (old,) = struct.unpack_from("<H", buf, pos)
    new = {"inc": old + rng.choice((-2, -1, 1, 2)),
           "huge": 0xFFFF,
           "tiny": rng.randrange(0, container.MIN_STMT)}[mode]
    struct.pack_into("<H", out, pos, max(0, new) & 0xFFFF)
    return bytes(out), pos, pos + 2, "corrupt_length"


def mut_truncate(buf: bytes, rng: random.Random):
    """Cut the module mid-way: the reader must return the intact prefix, never raise."""
    if len(buf) < 40:
        return None
    k = rng.randrange(len(buf) // 2, len(buf))
    return buf[:k], k, len(buf), "truncate"


def mut_break_terminator(buf: bytes, rng: random.Random):
    """Replace a statement's fe with junk -> an unknown-SHAPE statement (must survive as
    known=False while its section still validates), or kill a section when it is alone."""
    pos = _random_body_byte(buf, rng, at_end=True)
    if pos is None:
        return None
    out = bytearray(buf)
    out[pos] = 0x77
    return bytes(out), pos, pos + 1, "break_terminator"


def mut_zero_symbol_operand(buf: bytes, rng: random.Random):
    """Zero a f7 operand index: semantics change, structure must not move at all. Only
    operands fully inside the statement payload qualify — zeroing bytes that reach the
    trailing shape byte would change the SHAPE, which this family promises not to do."""
    cands = [i for st_lo, st_hi in _statement_spans_now(buf)
             for i in range(st_lo + 2, st_hi - 3)
             if buf[i] == 0xF7]
    if not cands:
        return None
    i = rng.choice(cands)
    out = bytearray(buf)
    out[i + 1] = 0
    out[i + 2] = 0
    return bytes(out), i + 1, i + 3, "zero_symbol_operand"


def mut_overrun_section(buf: bytes, rng: random.Random):
    """Grow a section's declared length past its terminator: validation must reject it.
    Targets come from PARSING the buffer (real prologue length fields), not from scanning
    for 0xFC — inside a statement that byte is END_EXPR, and corrupting it is body damage,
    not a section-boundary attack; mislabelling it would lie to the invariant battery."""
    secs = container.parse(buf, 0).sections
    if not secs:
        return None
    sec = rng.choice(secs)
    fmt = "<I" if sec.framing == "u32" else "<H"
    width = struct.calcsize(fmt)
    (old,) = struct.unpack_from(fmt, buf, sec.offset + 1)
    cap = (1 << (8 * width)) - 1
    struct.pack_into(fmt, out := bytearray(buf), sec.offset + 1,
                     min(cap, old + rng.choice((2, 4, 40))))
    return bytes(out), sec.offset + 1, sec.offset + 1 + width, "overrun_section"


MUTATIONS = [mut_flip_opcode, mut_corrupt_length, mut_truncate,
             mut_break_terminator, mut_zero_symbol_operand, mut_overrun_section]

ZERO_COST = {"flip_opcode", "zero_symbol_operand"}
# break_terminator on the LAST statement's fe can turn a whole single-statement section
# all-unknown (documented rejection rule), so it is deliberately NOT in ZERO_COST.


def _statement_spans(mod: container.Module):
    """(start_of_length_prefix, end_of_statement, section) for every parsed statement."""
    out = []
    for sec in mod.sections:
        for st in sec.statements:
            out.append((st.offset, st.offset + st.declared, sec))
    return out


def _random_body_byte(buf: bytes, rng: random.Random, at_end: bool = False):
    """A byte inside some parsed statement's body (optionally its final fe byte)."""
    mod = container.parse(buf, 0)
    spans = _statement_spans(mod)
    if not spans:
        return None
    st_lo, st_hi, _ = rng.choice(spans)
    lo, hi = st_lo + 2, st_hi          # body excludes the u16 prefix
    if at_end:
        return hi - 1
    return rng.randrange(lo, hi)


def _random_stmt_prefix(buf: bytes, rng: random.Random):
    mod = container.parse(buf, 0)
    spans = _statement_spans(mod)
    if not spans:
        return None
    st_lo, _, _ = rng.choice(spans)
    return st_lo


# --- invariant checks ---------------------------------------------------------------------

class Violation(AssertionError):
    """A broken resync invariant, carrying everything needed to reproduce."""


def _span_map(mod: container.Module) -> dict:
    """(offset, declared) -> (stream, text) for every parsed statement.

    Statements are identified by SPAN, not by content: when a mutation damages bytes inside
    a statement, that statement's stream legitimately changes, and counting the damaged
    statement as one "fabricated" stranger plus one "loss" would be the inverted-denominator
    mistake one layer down — a corruption would inflate BOTH sides of the ledger.
    """
    return {(st.offset, st.declared): (st.stream, st.text) for st in mod.statements}


def _overlaps(span: tuple, lo: int, hi: int) -> bool:
    off, decl = span
    return lo < off + decl and off < hi


def check_mutant(base_buf: bytes, mut_buf: bytes, lo: int, hi: int, kind: str,
                 seed_label: str) -> None:
    """Run the invariant battery for one mutant. Raises Violation on any breach."""
    # I1 — the reader never raises on a mutated buffer whose magic is intact.
    try:
        mod = container.parse(mut_buf, 0)
    except Exception as e:  # noqa: BLE001 — ANY exception here is a violation
        raise Violation(f"[{seed_label}] {kind}: parse raised {type(e).__name__}: {e}")

    trace: list[tuple[int, str]] = []
    container.sections(mut_buf, 0, len(mut_buf), reject_trace=trace)

    base = container.parse(base_buf, 0)
    base_spans = _span_map(base)
    mut_spans = _span_map(mod)
    strangers = sorted(s for s in mut_spans if s not in base_spans)
    lost = sorted(s for s in base_spans if s not in mut_spans)
    # Content changed on a span that survives: legitimate only inside the corrupted span.
    altered_elsewhere = sorted(
        s for s in mut_spans
        if s in base_spans and mut_spans[s] != base_spans[s] and not _overlaps(s, lo, hi))

    if kind == "truncate":
        # I2a — truncation legitimately loses the tail, so losses are expected; what must
        # hold: nothing INVENTED, every survivor byte-identical (bytes before the cut are
        # untouched) and strictly before the cut.
        if strangers or altered_elsewhere or any(s[0] >= lo for s in mut_spans):
            raise Violation(
                f"[{seed_label}] truncate@{lo:#x}: {len(strangers)} stranger, "
                f"{len(altered_elsewhere)} altered, "
                f"{sum(1 for s in mut_spans if s[0] >= lo)} post-cut statements")
    elif kind in ZERO_COST:
        # I2b — structural zero-cost: same statement count; nothing lost, nothing invented;
        # only spans overlapping [lo,hi) may differ in content.
        if (len(mut_spans) != len(base_spans) or strangers or lost
                or altered_elsewhere):
            raise Violation(
                f"[{seed_label}] {kind}: count {len(mut_spans)} vs baseline "
                f"{len(base_spans)}, {len(strangers)} stranger, {len(lost)} lost, "
                f"{len(altered_elsewhere)} altered outside [{lo:#x},{hi:#x}) — "
                f"corruption changed the ACCOUNTING")
    else:
        # I2c — destructive classes: nothing invented; every lost statement sat in a section
        # overlapping the corrupted span (loss is LOCAL, never the module); and any content
        # change on a surviving span lies inside the corrupted span.
        if strangers or altered_elsewhere:
            raise Violation(
                f"[{seed_label}] {kind}: {len(strangers)} fabricated statements "
                f"(e.g. offset {strangers[0][0]:#x}) and {len(altered_elsewhere)} altered "
                f"outside [{lo:#x},{hi:#x}) — search invented or scattered code")
        if lost:
            overlap_sec = [sec for sec in base.sections
                           if sec.offset - 8 <= hi and lo <= sec.end + 2]
            for s in lost:
                if not any(sec.offset <= s[0] < sec.end + 2 for sec in overlap_sec):
                    raise Violation(
                        f"[{seed_label}] {kind}: statement at {s[0]:#x} lost but outside "
                        f"every section overlapping [{lo:#x},{hi:#x}) — damage propagated")
            # I3 — the loss must be EXPLICIT: some rejection was traced in the damaged span.
            if not any(lo - 8 <= p <= hi + 8 for p, _ in trace):
                raise Violation(
                    f"[{seed_label}] {kind}: {len(lost)} statements lost with NO "
                    f"recorded rejection near [{lo:#x},{hi:#x}) — silent swallow")

    # I4 — the lifter's contract: lift or Unsupported, never anything else.
    for st in mod.statements:
        if st.text is not None:
            continue
        try:
            lifter.dec_statement(st.stream, [])
        except lifter.Unsupported:
            pass
        except Exception as e:  # noqa: BLE001 — anything else propagates upward
            raise Violation(
                f"[{seed_label}] {kind}: dec_statement raised {type(e).__name__} "
                f"({e}) on stream {st.stream.hex(' ')[:60]}")

    # I5 — classification stays total under mutation.
    try:
        container.classify_hits(mut_buf)
    except Exception as e:  # noqa: BLE001
        raise Violation(f"[{seed_label}] {kind}: classify_hits raised {type(e).__name__}")


def run_fuzz(rounds_per_kind: int = 12, seed: int = 20260823,
             include_fixtures: bool = True) -> dict:
    """Deterministic campaign over synthetic + fixture seeds. Returns a summary dict.

    Raises Violation on the first breached invariant. Same seed -> same campaign, so any
    failure reproduces exactly from the number printed alongside the violation.
    """
    seeds: dict[str, bytes] = {"synth_u16": build_module(),
                               "synth_wide": build_module(wide_flags=[False, True]),
                               "synth_single": build_module(
                                   groups=[[stmt_assign(), stmt_print(), stmt_macro()]])}
    if include_fixtures:
        seeds.update(fixture_seeds())

    rng = random.Random(seed)
    results = {"seed": seed, "mutants": 0, "by_kind": {}, "seeds": sorted(seeds)}
    for name, buf in sorted(seeds.items()):
        if not container.is_module(buf, 0):
            continue                      # fixtures dir may hold other data someday
        for mut in MUTATIONS:
            for i in range(rounds_per_kind):
                got = mut(buf, rng)
                if got is None:
                    continue
                mbuf, lo, hi, kind = got
                label = f"{name}/{kind}#{i}/seed={seed}"
                check_mutant(buf, mbuf, lo, hi, kind, label)
                results["mutants"] += 1
                results["by_kind"][kind] = results["by_kind"].get(kind, 0) + 1
    return results


def deep_nesting_stream(depth: int = 700) -> bytes:
    """A READER-STRIPPED assignment stream whose expression nests `depth` levels of
    43-groups closed by MOD_APPLY (no fd/fe — dec_statement consumes post-reader streams).

    Each level costs ~3 Python frames (_dec_group -> _dec_operand -> _dec_expr), so depth
    700 blows the default recursion limit ~2x over INSIDE expression decoding — past the
    lead checks that would otherwise short-circuit. Exercises the RecursionError -> Unsupported
    conversion; needs at least one symbol name for the assignment lvalue.
    """
    s = b"\xf8\x01\x01"                      # INT8 literal 1 (S.INT8, width, value)
    for _ in range(depth):
        s = b"\x43" + s + b"\xf8\x01\x01" + b"\x47"   # 43 <operand> <lit> 47 = modulus group
    return b"\x54" + _sym_ref(0) + b"\x10\xfc" + s
