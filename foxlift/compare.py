# ABOUTME: Canonical comparator for compiled VFP method sections — the phase-2 pass criterion.
# ABOUTME: Deliberately conservative: equality is frames byte-equal AND symbol tables equal.

from dataclasses import dataclass, field

from foxlift import container


class Comparison:
    """Result of comparing two compiled sections.

    equal=True means: same number of statements, every statement frame byte-identical after
    excluding nothing, and both sides' symbol tables identical modulo identifier case.

    Deliberate strictness (v1): symbol indexes are NOT rewritten to a common numbering yet.
    Both sides of every comparison in phase 2 come from the SAME VFP9 compiling equivalent
    source, so faithful emission reproduces table order; a benign-ordering false-fail is
    acceptable and visible, while a loose comparator can silently validate a broken emitter.
    Name-resolved canonicalization lands with fuller operand schemas (phase 4).
    """

    def __init__(self, equal: bool, reason: str = "", detail: dict | None = None):
        self.equal = equal
        self.reason = reason
        self.detail = detail or {}

    def __repr__(self):
        return f"Comparison(equal={self.equal}, reason={self.reason!r})"


def _section_frames(sec) -> list[bytes]:
    """Comparable frame per statement: the reader-exposed stream itself.

    Verbatim statements keep their stored bytes (marker + payload + 0a, resp. +
    f9 05 <u16> for a framed block opener), so arbitrary code pages survive
    byte-exactly — Statement.stream IS the original byte sequence. Compiled
    statements contribute their opcode stream (prefix excluded, terminators
    stripped by the reader already)."""
    return [s.stream for s in sec.statements]


def _symbols_key(names: list[str]):
    return [n.casefold() for n in names]


def compare_sections(a, b) -> Comparison:
    """Compare two Section objects."""
    fa, fb = _section_frames(a), _section_frames(b)
    if len(fa) != len(fb):
        return Comparison(False, f"statement count {len(fa)} != {len(fb)}",
                          {"a_count": len(fa), "b_count": len(fb)})
    for i, (x, y) in enumerate(zip(fa, fb)):
        if x != y:
            return Comparison(False, f"frame {i} differs",
                              {"index": i, "a": x.hex(" "), "b": y.hex(" ")})
    ka, kb = _symbols_key(a.symbols), _symbols_key(b.symbols)
    if ka != kb:
        return Comparison(False, "symbol tables differ",
                          {"a_symbols": a.symbols, "b_symbols": b.symbols})
    return Comparison(True, "identical")


def compare_module_frames(orig_objcode: bytes, recompiled_fxp: bytes) -> Comparison:
    """Compare an original OBJCODE blob against a wrapper-recompiled program.

    The recompiled program's section layout includes wrapper scaffolding (empty lead,
    class-init) around the method sections, so pairing is: every original section must be
    matched by SOME recompiled section, in order, with no original left over. Recompiled
    sections no original matches are scaffold and ignored — matching a wrong-but-identical
    section is impossible by construction, since equality here IS the criterion.
    """
    try:
        mo = container.parse(orig_objcode)
    except ValueError as e:
        return Comparison(False, f"original unparsable: {e}")
    try:
        mr = container.parse(recompiled_fxp)
    except ValueError as e:
        return Comparison(False, f"recompile unparsable: {e}")
    return _match_ordered(mo, mr)


def compare_compiled(fxp_a: bytes, fxp_b: bytes) -> Comparison:
    """Compare two standalone compiled programs section-for-section (ordered match)."""
    try:
        ma = container.parse(fxp_a)
    except ValueError as e:
        return Comparison(False, f"a unparsable: {e}")
    try:
        mb = container.parse(fxp_b)
    except ValueError as e:
        return Comparison(False, f"b unparsable: {e}")
    return _match_ordered(ma, mb)


def _match_ordered(ma, mb) -> Comparison:
    orig_secs = [s for s in ma.sections if not s.is_empty]
    if not orig_secs:
        return Comparison(False, "original has no non-empty sections")

    cand = [(sec, _section_frames(sec)) for sec in mb.sections]
    cursor = 0  # originals must match in order — preserves structure sensitivity
    last_reason = "no recompiled sections"
    for want in orig_secs:
        wf = _section_frames(want)
        matched = False
        while cursor < len(cand):
            sec, cf = cand[cursor]
            cursor += 1
            c = _compare_frames_lists(wf, cf, want.symbols, sec.symbols)
            if c.equal:
                matched = True
                break
            last_reason = c.reason
        if not matched:
            return Comparison(False, f"original section {cursor}: {last_reason}")
    return Comparison(True, "all original sections matched in order")


def _compare_frames_lists(fa, fb, syma, symb) -> Comparison:
    if len(fa) != len(fb):
        return Comparison(False, f"statement count {len(fa)} != {len(fb)}")
    for i, (x, y) in enumerate(zip(fa, fb)):
        if x != y:
            return Comparison(False, f"frame {i} differs",
                              {"index": i, "a": x.hex(" "), "b": y.hex(" ")})
    if _symbols_key(syma) != _symbols_key(symb):
        return Comparison(False, "symbol tables differ",
                          {"a": syma, "b": symb})
    return Comparison(True, "identical")
