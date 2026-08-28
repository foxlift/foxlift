# ABOUTME: Reader for the VFP compiled-module container (.fxp, and the OBJCODE memo of .scx/.vcx).
# ABOUTME: Accepts measured magic variants and both framings; preserves section structure and symbols.

import struct
from dataclasses import dataclass, field

# Magic variants measured in the public corpus (docs/FORMAT.md §1):
#
#   fe f2 ff 20   dominant module, VFP8 and VFP9 alike            (24,518 OBJCODE records)
#   fe f2 ff 22   normal module using u32 section framing (§3)     (16 records)
#   fe f2 ff 1f   older variant; otherwise reads the same          (9 records)
#
# fe f2 ee XX is VFP's build-time encryption of redistributable APPs (§8) — deliberately NOT
# accepted: decrypting them is out of scope and they must never be mistaken for plain modules.
MAGIC_VFP9 = b"\xfe\xf2\xff\x20"
MAGIC_U32 = b"\xfe\xf2\xff\x22"
MAGIC_OLD = b"\xfe\xf2\xff\x1f"
ACCEPTED_MAGICS = (MAGIC_VFP9, MAGIC_U32, MAGIC_OLD)
ENCRYPTED_PREFIX = b"\xfe\xf2\xee"

# Backwards-compat alias for callers written against the single-magic reader.
MAGIC = MAGIC_VFP9

# Code-section framing, established by differentially probing 1-, 2- and 3-statement programs
# against the oracle and cross-checked on listener.vcx (magic fe f2 ff 22):
#
#   <marker byte> <length field>               prologue; u16 field normally, u32 in some modules
#     <statement>...                           statements tile the section exactly
#   03 00                                      section terminator
#
# The length value N counts MARKER + STATEMENTS + TERMINATOR — everything except the length
# field itself. Fresh oracle compiles of 1/2/3-statement programs gave N = 18 / 33 / 50 =
# 3 + 15, 3 + 30, 3 + 47; fxabstract's single 87-byte method gives N = 1 + 87 + 2 = 90.
#
# The historical reading ("N counts the marker byte onward, terminator not counted") produced
# the same numbers for u16 fields purely by accident: with a 2-byte field, fc + N lands exactly
# on the terminator because the field's own 2 bytes cancel the terminator's 2. With a u32 field
# they do not cancel, which is why the first u32 implementation found nothing. The marker byte
# varies (0xFC standalone, other values incl. 0x00 inside form/class methods), so sections are
# located by validation, never by matching the marker.
SECTION_START = 0xFC              # observed marker in standalone programs; do not match on it
END_EXPR = 0xFD
END_STMT = 0xFE
ESCAPE = 0xEA                     # escape prefix introducing VFP's second function range
PROLOGUE_U16 = 3
PROLOGUE_U32 = 5
SECTION_TERMINATOR = b"\x03\x00"

# Two kinds of statement are stored as VERBATIM SOURCE rather than compiled, sharing one
# envelope — <u16 len> <marker> <ascii source text> 0a:
#
#   01  macro-substitution lines (&var): not compiled BY DESIGN; VFP cannot know their content
#       until runtime. Easiest construct in the language for a decompiler (verbatim recovery,
#       comments included); hardest for a migrator (nothing static to translate).
#   b4  lines the COMPILER REJECTED (measured 2026-08-23: a PRG whose SELECT contains a syntax
#       error still emits an .fxp — the .err records the error and the offending line is stored
#       verbatim). Confirmed against corpus form mainmenur.scx, whose shipped source genuinely
#       contains literal '????????' runs: the bytecode preserves them exactly while the .err
#       echo strips them to spaces.
#
# A THIRD measured shape exists for lead 01 only (docs/VERBATIM.md, n=35 dev-draw
# statements): a verbatim line that OPENS A BLOCK keeps the standard statement
# terminator and carries the standard frame-jump token before it —
#
#     <u16 len> 01 <source-line bytes> f9 05 <u16 target> fe
#
# The u16 anchors to the matching depth-0 ELSE or bare 1e ENDIF exactly like a compiled
# 25-opener (23 ENDIF-paired + 4 ELSE-paired occurrences measured across the 21 blocked
# methods). Plain lines have NO trailing fe (marker + line + 0a tiles their length);
# framed openers are ordinary statements in that respect. Round 30 corpus-carried the
# framed shape for b4 too (mainmenur.scx::grdmain stmt[107] stores the compiler-rejected
# line 'IF  .NOT. ISNULL(??????)' WITH the f9 05 trailer; its u16 anchors to the matching
# depth-0 ELSE exactly like the 01 openers — target = ELSE offset − code base), so the
# framed branch admits BOTH markers.
TEXT_STMT = 0x01
ERROR_STMT = 0xB4
TEXT_END = 0x0A
TEXT_MARKERS = (TEXT_STMT, ERROR_STMT)
FRAME_JUMP = b"\xf9\x05"          # frame-jump token closing a framed verbatim opener
FRAME_JUMP_LEN = 4                # f9 05 <u16>
FRAMED_MIN_BODY = 1 + 1 + FRAME_JUMP_LEN + 1   # marker + >=1 line byte + f9 05 uu + fe

# Statements declare their own u16 length, so the hard ceiling is 65,535 by construction. The
# old 4,096 plausibility cap silently discarded valid methods — corpus carrier 07f600ed0475f481
# (object Command2) carries macro statements of 8,004 and 5,759 bytes. MIN_STMT stays as a cheap
# disambiguation floor: no statement shorter than 4 bytes has ever been observed in oracle
# output or the corpus (UNVERIFIED below that bound, hence kept).
MIN_STMT = 4


@dataclass
class Statement:
    offset: int          # absolute offset in the module buffer
    declared: int        # the u16 length prefix, inclusive of itself
    stream: bytes        # opcode bytes, excluding the length prefix and the fe/fd-fe terminator
    text: str | None = None   # verbatim source line, for uncompiled macro-substitution statements
    known: bool = True        # False when the statement shape is not understood
    raw_text: bytes | None = None
    # ^ verbatim SOURCE BYTES with all delimiters excluded (the 0a newline, resp. the
    #   f9 05 <u16> block-opener trailer). The byte-faithful representation: .text is a
    #   latin-1-carried VIEW of exactly these bytes, kept for display and back-compat.
    jump_rel: int | None = None
    # ^ framed verbatim block opener only (lead 01, or b4 since the round-30
    #   carrier, + f9 05 trailer): the trailer's u16, anchored to the post-prologue
    #   code base like every compiled frame target. None for plain lines.


@dataclass
class Section:
    """One code section: a method body, a procedure, or the program's main section.

    Sections are kept distinct — never flattened into one statement list — because method
    ownership, symbol scope and branch domains all live at this level. Empty sections are real:
    a valid empty method compiles to just a prologue and terminator (fc 03 00 03 00 observed),
    and they matter for method alignment downstream.
    """
    offset: int          # prologue start
    declared: int        # the prologue length value; counts the marker byte onward
    framing: str         # "u16" or "u32"
    statements: list[Statement] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)   # table following this section, if parsed
    symbols_parsed: bool = False
    codec: str | None = None   # table code-page for symbol names AND string payloads (I6/I11)

    @property
    def end(self) -> int:
        """Offset of the section's 03 00 terminator (start of it, not past it).

        For a u16 field this equals offset+declared because the field's own 2 bytes cancel
        the terminator's 2 in the N arithmetic; the u32 field does not cancel, hence +2.
        """
        extra = 2 if self.framing == "u32" else 0
        return self.offset + self.declared + extra

    @property
    def is_empty(self) -> bool:
        return not self.statements

    @property
    def all_unknown(self) -> bool:
        return bool(self.statements) and all(not s.known for s in self.statements)


@dataclass
class HitClassification:
    """The outcome of trying to read one raw magic occurrence as a module."""
    offset: int
    magic: bytes
    status: str          # "parsed" | "empty" | "rejected"
    reason: str
    module: "Module | None" = None


@dataclass
class ClassIdentity:
    """DEFINE CLASS name / AS base / OLEPUBLIC from the post-section directory.

    r43-fxphdr: these identities are not in the FORMAT.md §2 front header.
    After the last section terminator and its 55-table (count may be 0):
        <u16 nlen> <name> <u16 blen> <base> <u16 unk0> <u16 unk1> <u16 ole>
    ``ole`` is 1 for OLEPUBLIC, 0 otherwise. Name and base keep stored case.
    ``methods`` is the name list riding ahead of the class-init section
    (``<u16 nlen> <name> <u32> <u32>``, last u32 overlaps the next marker).
    Names may be ``object.event`` (ADD OBJECT methods). ``method_vis`` is
    parallel: empty for public (0xa2), ``PROTECTED`` (0xa3), ``HIDDEN`` (0x9e).
    The 0xa2/0xa3/0x9e INT32 is a 1-based index into that name list.
    """
    name: str
    as_base: str
    olepublic: bool
    methods: list[str] = field(default_factory=list)
    method_vis: list[str] = field(default_factory=list)


def _u16le(buf: bytes, i: int) -> int:
    return int.from_bytes(buf[i:i + 2], "little")


# Class-init method-index leads (docs/FORMAT.md §2): public / PROTECTED / HIDDEN.
_METHOD_INDEX_LEADS = (0xA2, 0xA3, 0x9E)


def _ident_bytes(raw: bytes, *, dotted: bool = False) -> str | None:
    """Stored identifier as a latin-1 carrier. ASCII letter/_ or a DBCS lead
    may start a name; digits follow. ``dotted`` allows ``object.event``
    (ADD OBJECT methods in the method directory)."""
    if not raw:
        return None
    first = raw[0]
    if not (65 <= first <= 90 or 97 <= first <= 122 or first == 95
            or first >= 0x80):
        return None
    for b in raw[1:]:
        if (65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57 or b == 95
                or b >= 0x80):
            continue
        if dotted and b == 46:
            continue
        return None
    return raw.decode("latin1")


def _skip_symbol_table(buf: bytes, pos: int, end: int) -> int:
    """Advance past a 55-table, including the count-0 form the section reader rejects."""
    if pos + 3 > end or buf[pos] != 0x55:
        return pos
    count = _u16le(buf, pos + 1)
    cur = pos + 3
    for _ in range(count):
        if cur + 2 > end:
            return pos
        nlen = _u16le(buf, cur)
        cur += 2 + nlen
        if cur > end:
            return pos
    return cur


def _method_names(buf: bytes, start: int, stop: int) -> list[str]:
    pos = _skip_symbol_table(buf, start, stop)
    names: list[str] = []
    while pos + 3 <= stop:
        nlen = _u16le(buf, pos)
        if not (1 <= nlen <= 128) or pos + 2 + nlen > stop:
            break
        ident = _ident_bytes(buf[pos + 2:pos + 2 + nlen], dotted=True)
        if ident is None:
            break
        names.append(ident)
        pos += 2 + nlen
        pos = min(pos + 8, stop)
    return names


def class_identities(buf: bytes, off: int = 0,
                     end: int | None = None) -> list[ClassIdentity]:
    """Read DEFINE CLASS identities from the post-section directory. No VM."""
    if end is None:
        end = len(buf)
    try:
        mod = parse(buf, off)
    except ValueError:
        return []
    if not mod.sections:
        return []
    pos = _skip_symbol_table(buf, mod.sections[-1].end + 2, end)
    recs: list[ClassIdentity] = []
    while pos + 6 <= end:
        nlen = _u16le(buf, pos)
        if not (1 <= nlen <= 128) or pos + 2 + nlen + 2 > end:
            break
        name = _ident_bytes(buf[pos + 2:pos + 2 + nlen])
        if name is None:
            break
        j = pos + 2 + nlen
        blen = _u16le(buf, j)
        if not (1 <= blen <= 128) or j + 2 + blen + 6 > end:
            break
        base = _ident_bytes(buf[j + 2:j + 2 + blen])
        if base is None:
            break
        k = j + 2 + blen
        ole = _u16le(buf, k + 4)
        recs.append(ClassIdentity(name=name, as_base=base, olepublic=ole == 1))
        pos = k + 6
    if not recs:
        return []
    # Method names sit in one directory immediately before the first
    # class-init section. Each 0xa2/0xa3/0x9e INT32 is a 1-based index
    # into that list (public / PROTECTED / HIDDEN). Names not referenced
    # by any index are leftover module-level procedures, not class members.
    nclass = len(recs)
    secs = mod.sections
    if len(secs) >= nclass + 1:
        inits = secs[-nclass:]
        prev = secs[-nclass - 1] if len(secs) > nclass else None
        if prev is not None:
            names = _method_names(buf, prev.end + 2, inits[0].offset)
            for rec, sec in zip(recs, inits):
                rec.methods = []
                rec.method_vis = []
                for st in sec.statements:
                    if not st.stream or st.stream[0] not in _METHOD_INDEX_LEADS:
                        continue
                    if len(st.stream) < 7:
                        continue
                    idx = int.from_bytes(st.stream[3:7], "little")
                    if 1 <= idx <= len(names):
                        rec.methods.append(names[idx - 1])
                    else:
                        rec.methods.append("_m%d" % idx)
                    rec.method_vis.append(
                        {0xA3: "PROTECTED", 0x9E: "HIDDEN"}.get(
                            st.stream[0], ""))
    return recs


def procedure_names(buf: bytes, off: int = 0,
                    end: int | None = None) -> list[str]:
    """Procedure names after the last 55-table of a non-class module.

    r43 G3: generated menus compile an unnamed main section plus
    ``<u16 nlen> <name> <u32> <u16 0> <u16 0xffff>`` records. Class
    files use :func:`class_identities` instead (their next record is
    AS-base, not a 0xffff trailer).
    """
    if end is None:
        end = len(buf)
    if class_identities(buf, off, end):
        return []
    try:
        mod = parse(buf, off)
    except ValueError:
        return []
    if not mod.sections:
        return []
    pos = _skip_symbol_table(buf, mod.sections[-1].end + 2, end)
    names: list[str] = []
    while pos + 10 <= end:
        nlen = _u16le(buf, pos)
        if not (1 <= nlen <= 128) or pos + 2 + nlen + 8 > end:
            break
        ident = _ident_bytes(buf[pos + 2:pos + 2 + nlen])
        if ident is None:
            break
        trailer = buf[pos + 2 + nlen:pos + 2 + nlen + 8]
        if trailer[6:8] != b"\xff\xff":
            break
        names.append(ident)
        pos += 2 + nlen + 8
    return names


@dataclass
class Module:
    data: bytes
    offset: int
    magic: bytes = MAGIC_VFP9
    extent: int = 0            # byte after the last byte belonging to this module's search span
    sections: list[Section] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)   # union of all parsed section tables
    symbols_parsed: bool = False

    # --- backwards-compatible views over the nested structure ---------------------------------
    @property
    def code_start(self) -> int:
        """Offset of the first code-section prologue, or -1 when none was found."""
        return self.sections[0].offset if self.sections else -1

    @property
    def statements(self) -> list[Statement]:
        return [s for sec in self.sections for s in sec.statements]

    @property
    def recognised(self) -> int:
        """Statements whose shape is understood (macro-text statements included)."""
        return sum(1 for s in self.statements if s.known)

    @property
    def opcodes(self) -> list[int]:
        """LEAD LIST ONLY — operand bytes are still counted here because no harvested operand
        schema exists yet in this reader, so entries like lit_int_big = 0x2c (the low byte of
        300) are known misattributions. Never cite this as an opcode reference; the harvested
        schema table under probes/ is the authority."""
        out, stream = [], bytes(
            b for s in self.statements if s.text is None and s.known for b in s.stream
        )
        i = 0
        while i < len(stream):
            if stream[i] == ESCAPE and i + 1 < len(stream):
                out.append(0xEA00 | stream[i + 1])
                i += 2
            else:
                out.append(stream[i])
                i += 1
        return out


def is_module(buf: bytes, off: int = 0) -> bool:
    """True when an accepted magic variant sits at off."""
    return buf[off:off + 4] in ACCEPTED_MAGICS


def find_modules(buf: bytes) -> list[int]:
    """Offsets of every accepted-magic occurrence.

    These are HITS, not proven modules — an embedded DBF header inside an .exe can begin with
    the magic bytes (one held-out estate .exe does at offset 0x38cc). Classify them with classify_hits()
    instead of treating every hit as readable code.
    """
    out, pos = [], 0
    while (pos := _find_any_magic(buf, pos)) != -1:
        out.append(pos)
        pos += 4
    return out


def _find_any_magic(buf: bytes, pos: int) -> int:
    best = -1
    for magic in ACCEPTED_MAGICS:
        hit = buf.find(magic, pos)
        if hit != -1 and (best == -1 or hit < best):
            best = hit
    return best


def _next_magic(buf: bytes, pos: int) -> int:
    """First accepted-magic occurrence at or after pos, or len(buf)."""
    hit = _find_any_magic(buf, pos)
    return len(buf) if hit == -1 else hit


def classify_hits(buf: bytes) -> list[HitClassification]:
    """Classify every raw magic hit: parsed (code sections recovered), empty (valid module
    whose sections are all empty frames) or rejected (no section validates anywhere in the
    hit's span — embedded data that merely begins with the magic bytes). Every hit gets an
    explicit verdict; none disappear into exceptions."""
    out: list[HitClassification] = []
    for off in find_modules(buf):
        mod = parse(buf, off)
        if any(not s.is_empty for s in mod.sections):
            out.append(HitClassification(off, mod.magic, "parsed",
                                         f"{len(mod.sections)} section(s)", mod))
        elif mod.sections:
            out.append(HitClassification(off, mod.magic, "empty",
                                         f"{len(mod.sections)} empty section(s)", mod))
        else:
            out.append(HitClassification(off, mod.magic, "rejected",
                                         "no section validates in span"))
    return out


def _try_read_section(buf: bytes, fc: int, wide: bool,
                      ) -> tuple["Section | None", str | None]:
    """Read the section whose prologue sits at fc. Returns (section, None) on success or
    (None, reason) when it does not validate exactly.

    Validation is all-or-nothing: the declared span must be terminated by 03 00 and its
    statements must tile it with no bytes left over. A wrong candidate offset almost always
    fails this, which is what makes search viable without a mapped header. Two extra rules
    prune garbage, both earned from real failures: a candidate whose statements are ALL
    unknown-shaped is rejected (metadata that tiles by coincidence must not pass as code —
    frxbuilder2.vcx panelmultirotate had such a case), while a genuinely EMPTY section
    (prologue + terminator, zero statements) stays valid.
    """
    plen = PROLOGUE_U32 if wide else PROLOGUE_U16
    fmt = "<I" if wide else "<H"
    if fc + plen > len(buf):
        return None, "prologue past end"
    (declared,) = struct.unpack_from(fmt, buf, fc + 1)
    # N = marker + statements + terminator. Statements begin after the full prologue and must
    # tile exactly up to the terminator.
    if declared < 3:
        return None, "declared length < 3"
    stmts_stop = fc + plen + (declared - 3)
    if stmts_stop + 2 > len(buf):
        return None, "span past end of buffer"
    if buf[stmts_stop:stmts_stop + 2] != SECTION_TERMINATOR:
        return None, "no 03 00 at computed terminator"
    end = stmts_stop

    stmts, pos = [], fc + plen
    while pos < end:
        if pos + 2 > end:
            return None, "truncated length prefix"
        (slen,) = struct.unpack_from("<H", buf, pos)
        if not (MIN_STMT <= slen <= 0xFFFF):
            return None, f"statement length {slen} out of range"
        if pos + slen > end:
            return None, "statement overruns section span"
        body = buf[pos + 2: pos + slen]
        if body[:1] in [bytes([m]) for m in TEXT_MARKERS] \
                and body.endswith(bytes([TEXT_END])):
            # plain verbatim line: marker + source bytes + 0a
            raw = body[1:-1]
            stmts.append(Statement(offset=pos, declared=slen, stream=body,
                                   text=raw.decode("latin1"), raw_text=raw))
        elif body[:1] in [bytes([m]) for m in TEXT_MARKERS] \
                and len(body) >= FRAMED_MIN_BODY \
                and body[-1] == END_STMT \
                and body[-5:-3] == FRAME_JUMP:
            # framed verbatim block opener (lead 01 measured n=35; b4 corpus-carried
            # round-30): marker + line + f9 05 <u16> + fe. The plain envelope is
            # checked FIRST, so a line ending in its own 0a can never be mistaken
            # for a trailer. Anything marker-led that matches NEITHER measured
            # shape falls through to the unknown-shape branch below and costs
            # one Unsupported statement downstream — malformed input is rejected,
            # never crashed on and never guessed into a shape it does not have.
            raw = body[1:-5]
            stmts.append(Statement(offset=pos, declared=slen, stream=body,
                                   text=raw.decode("latin1"), raw_text=raw,
                                   jump_rel=int.from_bytes(body[-3:-1], "little")))
        elif body.endswith(bytes([END_STMT])):
            stream = body[:-1]
            if stream.endswith(bytes([END_EXPR])):
                stream = stream[:-1]
            stmts.append(Statement(offset=pos, declared=slen, stream=stream))
        else:
            # Unrecognised shape. The length prefix is still trustworthy, so skip exactly one
            # statement and resynchronise — an unknown construct costs one statement, never
            # the module. Whether the SECTION survives is decided by the all-unknown rule.
            stmts.append(Statement(offset=pos, declared=slen, stream=body, known=False))
        pos += slen

    if pos != end:
        return None, "statements do not tile the span"
    section = Section(offset=fc, declared=declared, framing="u32" if wide else "u16",
                      statements=stmts)
    if section.all_unknown:
        return None, "all statements unknown-shaped"
    return section, None


def _symbol_table_span(buf: bytes, tail: int, end: int) -> int | None:
    """Byte length L of the clean strict symbol table at tail, else None.

    Used only by :func:`sections` to know how far the window of the previously
    accepted section's table reaches. FORMAT.md §7: one table follows each
    section terminator, so a *code section* starting inside that table
    contradicts the measured layout.
    """
    names, ok = parse_symbol_table(buf, tail, end)
    if not ok:
        return None
    cur = tail + 3
    for _ in range(len(names)):
        (nlen,) = struct.unpack_from("<H", buf, cur)
        cur += 2 + nlen
    return cur - tail


def _prologue_is_ascii_carve(buf: bytes, pos: int, framing: str) -> bool:
    """True when the candidate's prologue reads as name LETTERS, not binary.

    A genuine prologue is a marker byte plus a little-endian length field;
    its high byte is printable only for declared lengths >= 8224, and a
    marker+length made entirely of printable ASCII (0x21..0x7E) is exactly
    what a length field carved out of an uppercase symbol name looks like
    ('F'|'PS' in CVFPSPROTOCOL, 'T'|'VI' in _SETVISIBLE — the two measured
    Round-35 false anchors).
    """
    plen = PROLOGUE_U32 if framing == "u32" else PROLOGUE_U16
    chunk = buf[pos:pos + plen]
    if len(chunk) < plen:
        return False
    return all(0x21 <= b <= 0x7E for b in chunk)


def sections(buf: bytes, off: int = 0, end: int | None = None,
             reject_trace: list | None = None) -> list[Section]:
    """Every code section in [off, end), found by validation rather than by signature.

    ``reject_trace``: optional list collecting ``(candidate_offset, reason)`` for every
    candidate that failed validation. OPT-IN and off by default — the corpus sweeps parse
    tens of thousands of modules and per-candidate bookkeeping there would be pure memory
    cost; harnesses and tooling that need to account for LOST spans pass a list explicitly
    (see foxlift/resync.py). Nothing is ever silently swallowed where a trace is provided.

    Anchor plausibility (Round 37, from r35-container-analysis): a candidate that VALIDATES
    but sits strictly inside the previous accepted section's symbol-table window AND carries
    a printable-ASCII prologue is rejected as an implausible anchor. Both clauses are forced
    by measurement — (i) by the §7 one-table-per-terminator alternation plus real anchors
    sitting systematically at T-1 (hence the open bound), which is why the window excludes
    T-1; (ii) because only letter-carved length fields are the observed pathology, so every
    binary-prologue candidate (including the '55 03 00 03 00' empty-frame/table-header
    ambiguity class) stays untouched. Earlier designs without clause (ii), or authenticating
    the window at T-1, reclassified 17 genuine corpus records — 19 counting the two artifact
    candidates themselves — and were discarded by the
    census gate; content thresholds were rejected outright — STATUS #3 documents that any
    plausibility cap silently discards valid methods (8,004-byte macro statements exist).
    Excluded candidates are reported through ``reject_trace``, never dropped silently.
    """
    end = len(buf) if end is None else end
    found, pos = [], off + 8
    excl_hi = -1          # exclusive upper bound of the active symbol-table window
    while pos < end - 4:
        sec, reason16 = _try_read_section(buf, pos, wide=False)
        if sec is None and reject_trace is not None:
            reject_trace.append((pos, reason16))
        if sec is None:
            sec, reason32 = _try_read_section(buf, pos, wide=True)
            if sec is None and reject_trace is not None:
                reject_trace.append((pos, "u32: " + reason32))
        if sec is not None and sec.end + 2 <= end:
            if pos < excl_hi and _prologue_is_ascii_carve(buf, pos, sec.framing):
                # THE DISCRIMINATOR: an ASCII-carved anchor inside the preceding
                # section's symbol table is not a plausible section start.
                if reject_trace is not None:
                    reject_trace.append(
                        (pos, "implausible anchor: printable prologue carved "
                              "inside previous section's symbol table"))
                pos += 1
                continue
            found.append(sec)
            pos = sec.end + 2
            span = _symbol_table_span(buf, pos, end)
            excl_hi = (pos + span - 1) if span is not None else -1
            continue
        pos += 1
    return found


def parse_symbol_table(buf: bytes, pos: int, end: int,
                       codec: str | None = None) -> tuple[list[str], bool]:
    """Try to read the symbol table documented in FORMAT.md §7 at pos:

        55 <u16 count> then count entries of <u16 len> <name bytes>

    Strictly: the marker must be 0x55, every entry must fit in [pos, end), lengths must be
    sane. Returns (names, True) only on a clean parse — anything else returns ([], False) and
    the caller treats symbols as unparsed rather than guessing. Confirmed against lans.scx;
    whether a table ALWAYS follows the last section is UNVERIFIED, so failure here is
    reported, never fatal.

    ``codec`` is the table code-page (``dbf.CODE_PAGE_MARKS.get(mark)``). None, an unmapped
    mark, or a codec that cannot decode a slot stays latin-1 — byte-preserving, the
    standalone .fxp default. Callers that have the table mark pass it; compare.py does not.
    """
    if pos + 3 > end or buf[pos] != 0x55:
        return [], False
    (count,) = struct.unpack_from("<H", buf, pos + 1)
    if count == 0 or count > 65535:
        return [], False
    names, cur = [], pos + 3
    for _ in range(count):
        if cur + 2 > end:
            return [], False
        (nlen,) = struct.unpack_from("<H", buf, cur)
        if not (1 <= nlen <= 4096) or cur + 2 + nlen > end:
            return [], False
        raw = buf[cur + 2:cur + 2 + nlen]
        try:
            names.append(raw.decode(codec or "latin1"))
        except (UnicodeDecodeError, LookupError):
            names.append(raw.decode("latin1"))
        cur += 2 + nlen
    return names, True


def parse(buf: bytes, off: int = 0,
          reject_trace: list | None = None,
          codec: str | None = None) -> Module:
    """Parse one module beginning at off. Raises ValueError if no accepted magic is there.

    The search span stops at the next accepted magic occurrence, so an embedded module's
    symbol table and strings can never bleed into the following one. A module may hold several
    code sections — a main body plus one per procedure — kept nested under Module.sections in
    file order. ``reject_trace`` is the opt-in candidate-rejection ledger documented on
    :func:`sections`. ``codec`` is forwarded to :func:`parse_symbol_table`; omit it for
    standalone .fxp (latin-1).
    """
    magic = buf[off:off + 4]
    if magic not in ACCEPTED_MAGICS:
        raise ValueError(f"no accepted module magic at 0x{off:x} "
                         f"(found {magic.hex(' ') if magic else '<eof>'})")

    nxt = _next_magic(buf, off + 4)
    secs = sections(buf, off, nxt, reject_trace=reject_trace)

    mod = Module(data=buf, offset=off, magic=magic, extent=nxt, sections=secs)
    # Context-matrix evidence (probes/context_matrix): multi-section modules carry ONE symbol
    # table after EACH section terminator, not only after the last one. Parse every table;
    # a section followed directly by another section simply has none.
    for sec in secs:
        tail = sec.end + 2
        names, ok = parse_symbol_table(buf, tail, nxt, codec=codec)
        if ok:
            sec.symbols, sec.symbols_parsed = names, True
            mod.symbols.extend(names)
            mod.symbols_parsed = True
        sec.codec = codec
    return mod
