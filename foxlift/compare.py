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


def certify_compiled(fxp_a: bytes, fxp_b: bytes) -> Comparison:
    """Certify two standalone compiled programs: the sections are a bijection.

    `compare_compiled` matches the first program's sections IN ORDER against the
    second's, advancing a cursor past candidates that do not match, and never
    looks at what the cursor leaves behind. A second program carrying EXTRA
    sections therefore compares equal, and so does one whose sections are the
    first's with anything at all interleaved: the criterion there is "every
    section of A is matched, in order", which is a subsequence test, not an
    equality.

    That is deliberate where it is used for wrapper scaffolding
    (`compare_module_frames`), and it is the hole everywhere else. This function
    closes it: equal only when the two non-empty section lists have the same
    length and pair up position for position — every section of A matched, every
    section of B matched exactly once, nothing left over, same order — under the
    same frame and symbol-table equality `compare_sections` applies.

    Empty sections are excluded on both sides, exactly as the ordered match
    excludes them on the original's side; their counts are reported in `detail`
    so a phantom empty section stays visible without deciding the verdict. It is
    a container artifact (r46-classinit), not a section a lift lost.

    Additive: nothing in this module changes behaviour because this exists.
    `compare_compiled` remains the campaign's scorer until a closer rules on
    switching, and this is reported beside it.
    """
    try:
        ma = container.parse(fxp_a)
    except ValueError as e:
        return Comparison(False, f"a unparsable: {e}")
    try:
        mb = container.parse(fxp_b)
    except ValueError as e:
        return Comparison(False, f"b unparsable: {e}")
    return _certify_bijection(ma, mb)


def _certify_bijection(ma, mb) -> Comparison:
    a = [s for s in ma.sections if not s.is_empty]
    b = [s for s in mb.sections if not s.is_empty]
    empties = {"a_sections": len(a), "b_sections": len(b),
               "a_empty": len(ma.sections) - len(a),
               "b_empty": len(mb.sections) - len(b)}
    if not a:
        return Comparison(False, "original has no non-empty sections", empties)
    if len(a) != len(b):
        return Comparison(
            False, f"section count {len(a)} != {len(b)}",
            dict(empties, extra_sections=len(b) - len(a)))
    for i, (x, y) in enumerate(zip(a, b)):
        c = _compare_frames_lists(_section_frames(x), _section_frames(y),
                                  x.symbols, y.symbols)
        if not c.equal:
            return Comparison(False, f"section {i}: {c.reason}",
                              dict(empties, section=i, **c.detail))
    return Comparison(True, "sections are a bijection in order", empties)
