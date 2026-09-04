# ABOUTME: The thin lifter: schema-driven RPN -> AST -> canonical VFP text, exact inverse shapes.
# ABOUTME: Verbatim families (01 macro / b4 rejected line) pass through as their stored text.

import contextlib as _contextlib
import struct as _struct
import math as _math
import re as _re
from dataclasses import dataclass, field
from datetime import date as _date

from foxlift import schemas as S
from foxlift.container import (
    PROLOGUE_BASE, PROLOGUE_U16, PROLOGUE_U32, class_identities,
    class_init_offsets, procedure_directory, procedure_names, _method_names,
)

S.FC = 0xFC
S.FD = 0xFD

# Round-42: fb/d9 (and other) string payloads follow the table code-page mark,
# the same codec as symbol-table names (I6). Default latin-1 is the standalone
# .fxp / statement_source path. lift_section installs sec.codec around the walk.
_PAYLOAD_CODEC = "latin1"


def _payload_text(raw):
    codec = _PAYLOAD_CODEC or "latin1"
    try:
        return raw.decode(codec)
    except (UnicodeDecodeError, LookupError):
        return raw.decode("latin1")


class Unsupported(Exception):
    pass


class _GroupDone(Exception):
    """Internal control flow (never escapes the lifter): a completed 43-group
    value CLOSES ITS OWN GROUP implicitly — originally the round-27
    args-before-receiver call chain (oracle round27_streams.json:
    c79070…:39 `…e50700f70800 | f70300 14 fd` resumes the ENCLOSING expression
    right after the terminal property read; r5's inner group ends at e50200 with
    the outer f60400 following), and since the round39 W15-close residual also
    the completed element-read property-tail packet (`_dec_w15_elem_prop_tail`
    plain path, same resume contract). _dec_group catches this around its
    segment parse; no other site may observe it."""

    def __init__(self, node, pos):
        super().__init__(node, pos)
        self.node = node          # the completed MidCall / packet value
        self.pos = pos            # first byte AFTER the completed chain


class _ChainOpen(Exception):
    """Internal control flow (never escapes the lifter): an args-before call
    chain whose value is complete but whose NEXT link needs the ENCLOSING 43
    frame's operands as that link's argument list.

    Round-40 group43 grammar (`_dec_chain_continue`): each nested `43` frame
    supplies the arguments of the next `e5` link, innermost frame first —
    'loNodes.Item(lnNode).ChildNodes.Item(0).Attributes.Item(0).NodeTypedValue'
    (VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx readstylesxml L2465) compiles as
    `43 f8<0> 43 f8<0> 43 00 f7<lnNode> f4<loNodes> e5<Item> f4<ChildNodes>
    e5<Item> f4<Attributes> e5<Item> f7<NodeTypedValue>`. The chain value
    therefore leaves its own group and is completed one frame out; `hops` are
    the member names read between the last call and the pending token, which
    belong to the NEXT link's RECEIVER, not to the value.

    Raised only at `_GROUP_DEPTH >= 2` (an enclosing 43 frame provably exists)
    and caught only by `_dec_expr`'s CALL_OPEN arm — `_dec_group` has exactly
    one call site, so this exception cannot escape a statement."""

    def __init__(self, node, hops, pos):
        super().__init__(node, hops, pos)
        self.node = node          # completed chain value so far
        self.hops = hops          # member hops belonging to the next receiver
        self.pos = pos            # the pending f6 / e5 token


class _MemArrayClose(Exception):
    """Internal control flow (raised from _dec_expr, caught only by _dec_group's
    segment dispatch): a memvar-array element READ closes its enclosing 43
    group — 'm.laPoints(1)' compiles args-first like every closer namespace,
    with the ARRAY REF itself as the closer spelling:

        43 <args> f5 0d f6 <arr>   ->   m.<arr>(<args>)

    Corpus alignment foxcharts.vcx::foxcharts _drawaxis
    stmts#95..97 'm.laPointsB(1) = m.laPoints(1)' =
    54 f50df64700 fcf80101fd03 10 fc 43 f80101 f50df64400. The close fires when
    the ref ends its group window: TERMINALLY (i+5==end) as measured in
    Round-30, and — Round-31 group-boundary extension, same stability contract —
    when the ONLY remaining byte is the parent group's bare closer 0xBC with >=1
    accumulated subscript (four-twin alignment foxcharts sec30 stmts#14/#15 =
    'Proper(m.laProperties(m.lnI,1))', stored L1736/L1737; such tails had no
    legal stock parse because bc's registry arity 1 rejected the swallowed
    closer). Every other mid-group position still reads the ref as plain
    MemvarRef. That terminal gate is a STABILITY choice: it
    keeps every Round-29 emitted text byte-for-byte and so satisfies this
    campaign's zero-drift gate. It does NOT measure the mid-group reading it
    suppresses as plain MemvarRef — the opposite is recorded in gold: on three
    cited carriers the suppressed array-element interpretation MATCHES the
    stored sources while the pinned stock text does not (3f133997f6b20709:54
    stmt#24 and twin 78429a71ad111792:54 compile
    'THIS._spellproperty(m.laMembers(lnI,1))' per foxchartsbeta.vcx::foxcharts
    L7020; 5126c7d3c0da377d:6 stmt#4 compiles 'ALLTRIM(UPPER(m.laLines[liLine]))'
    per _reportlistener.vcx::fxmemberdatascript L239). Flipping the mid-group
    reading would deliberately change already-lifted methods' text, so that
    correction is deferred until the authority/text-correction procedure is
    approved; until then this guard holds Round-29 output stable."""

    def __init__(self, name, pos, partial=None):
        super().__init__(name)
        self.name = name          # array symbol name (no m. prefix)
        self.pos = pos            # first byte AFTER the closing ref
        self.partial = partial or []   # operands pushed before the ref in ITS segment


# ---------- AST ---------------------------------------------------------------------------------
@dataclass
class Sym:
    name: str


@dataclass
class ByrefSym(Sym):
    """r38 M1/M2: a variable argument whose push rode the measured 0x18 flag
    slot (direct-call 43-group family, flag immediately before the f7 push;
    c0001/c0005 single-byte delta, a0002 positions 1&5, a0003 RHS form, stored
    frame27). Renders '@NAME'. The paren form '@(' and bare '@' outside an
    argument list are compiler-rejected (a0005/a0006), so no wire can demand
    them and the emitter never synthesizes them."""


@dataclass
class ArrayRef:
    name: str
    subs: list
    # Round-28: the closing byte of the measured subscript list records the
    # SOURCE's own spelling ('laX(1)' -> 03, 'laX[1]' -> 16), same provenance
    # as the LOCAL dimension closer. Default False keeps every historical
    # constructor and pinned emission on the paren form.
    bracket: bool = False


@dataclass
class MemberRef:
    name: str


@dataclass
class WithRef:
    name: str


@dataclass
class Num:
    spelling: str
    # r38 M4: numeric literals decoded from f8/f9 keep (op, width, value)
    # verbatim — the second byte is source-spelling provenance (decimal family
    # rides len(str(v)) incl sign/zeros; padded/unpadded hex and the b0008
    # negative shape ride their measured widths). None keeps every other
    # constructor (e9 hex arms, folded spellings) byte-compatible.
    op: int | None = None
    width: int | None = None
    # r67-lineno: stored u32 of a folded LINENO() / LINENO(1). None for every
    # other spelling. Emission still uses `spelling`; the layout pass reads this.
    lineno: int | None = None


@dataclass
class Flt:
    spelling: str
    # r41-C: the fa header's two bytes are source-spelling provenance, exactly as
    # schemas.FLOAT already documents them — width = the literal's full character
    # count, decimals = the digits after the point. Keeping them lets the emitter
    # restore the written spelling ('0.00', '00000.00', '2147483648') instead of
    # the value's shortest repr. None keeps every other constructor unchanged.
    width: int | None = None
    decimals: int | None = None
    # r48-foldmark: the 0xCC byte after the double marks a value that is not a
    # BARE token. A parenthesised literal carries it exactly as arithmetic
    # does, and leaves the header the bare token's own — so where the header's
    # rendering fits, the marker is recovered by re-parenthesising.
    marked: bool = False


@dataclass
class Str:
    text: str
    dq: bool = False     # True = was DOUBLE-quoted (d9); canonical emission preserves style


@dataclass
class Bool:
    value: bool


@dataclass
class Null:
    pass


@dataclass
class BinHexLit:
    """ff <type=01> <u16 len LE> <payload> — the 0h binary literal (round-27
    oracle-forced, probes/oracle_harvest round27 b1-b6: 0hEFBB -> ff010200efbb,
    odd-nibble 0hA pads high-nibble-first to ff0101000a, empty 0h -> ff010000).
    Emission re-pads to whole bytes and uppercases; both recompile byte-equal."""
    payload: bytes


@dataclass
class DateLit:
    """ee <8B> — strict date constant. The payload is an IEEE-754 double whose
    value is the Julian Day Number at midnight (LE byte order); measured points:
    {^2024-01-31} -> JDN 2460341 exactly (round-27 b9), corpus replicas
    {^2009.12.31}/{^2009.01.01}/{^1900.01.01} align on the same arithmetic.
    The all-zero payload is the EMPTY date — {}, {:} and {//} all compile to it
    (b8/b10/b11 byte-identical) and canonical emission picks {}."""
    ymd: tuple | None      # None = empty date {}


@dataclass
class DateTimeLit:
    """e6 <8B> — datetime constant, same JDN double with seconds-of-day as the
    fraction ({^2024-01-31 12:34:56} -> 2460341 + 45296/86400, round-27 b12;
    corpus {^1900.01.01,00:00:00} shows midnight keeps e6 with fraction 0).
    NOT the DATETIME() builtin, which is the ea 86 call and stays there."""
    ymd: tuple
    hms: tuple


@dataclass
class CurrencyLit:
    """de <pfx> 04 <i64LE scaled x10^4> — currency constant. Only the two
    measured triples bind (round-27 b13/b14): prefix 08 + 1005000 = $100.50,
    prefix 06 + 0 = $0; the prefix's meaning is OPEN (two data points), so any
    other shape fails loudly instead of guessing a rendering."""
    spelling: str


@dataclass
class MemberPath:
    """A dotted reference resolved from a run of f4 tokens plus a terminal f7:
    MemberPath(['THISFORM','LstCustomID','LEFT']) emits THISFORM.LstCustomID.LEFT.

    receiver=True marks the OTHER f4-run shape — the one with NO terminal f7,
    whose run ends at the enclosing 43 group's f6 callee. That path is the
    RECEIVER of the call, never a value. The run's TERMINAL TOKEN is the whole
    discriminator, oracle-measured as a minimal pair compiled in one batch
    (probes/oracle_harvest/round41_hoist_streams.json, s0001/s0002):

        apiSetfocus(Thisform.HWnd)   99 fc 43 f4<THISFORM> f7<HWND> f6<APISETFOCUS>
        Thisform.HWnd.apiSetfocus()  99 fc 43 f4<THISFORM> f4<HWND> f6<APISETFOCUS>

    and reproduced on every rooting the corpus carries: bare THIS (s0004/s0005),
    deep paths (s0006/s0007), WITH-scoped e2 (s0008/s0009), the e1 _SCREEN root
    (s0010/s0011), the memvar f5 0d root (s0012/s0013) and a local array whose
    last subscript is a member path (s0014). Both readings can stand in ONE
    statement — s0016 'This.Parent.zzfoo(This.Parent.BackColor)' =
    43 f4 f4 f7 (the ARGUMENT) f4 f4 (the RECEIVER) f6 — so the flag decides,
    never the operand's position on the group stack."""
    names: list
    receiver: bool = False


@dataclass
class MethodCall:
    """A 43-group whose callee is an object path terminating in f6:
    MethodCall(['THIS','Parent','grid1'], 'DoScroll', [args]) -> THIS.Parent.grid1.DoScroll(6).
    recv_with marks a WITH-scoped receiver (leading dot, possibly empty: '.Refresh()').
    bracket applies to the NAMELESS form only — an indexed reference, whose closing
    byte records the source's own spelling (03 '( … )' / 16 '[ … ]'); a named method
    call has no such byte and always renders parens."""
    recv: list
    name: str
    args: list
    recv_with: bool = False
    bracket: bool = False


@dataclass
class MidCall:
    """Round-27 mid-chain method call VALUE (oracle round27_streams.json minimal
    pair s1/s2): the arguments were pushed BEFORE the receiver run inside the
    same 43 group (variable args behind ByVal 00 markers), and e5 <u16> names the
    method because a member access or an enclosing method call follows — the
    terminal-call spelling closes with f6 instead and is a plain MethodCall.
    prop is the terminal property read following the call (s2 `.BAR`,
    w1 `.NAME`, w2 `.CNTPREVIEWER`); prop=None means the call value itself feeds
    an outer f6 receiver (r5 nesting `m.loA.B(m.x).C(m.y)`).
    bracket records that the subscript closed on the `16` bracket marker rather
    than the `03` paren one — the same source-spelling provenance ArrayRef and
    ObjectChain already carry (r54-withindex)."""
    recv: list              # receiver member names; a system-object root rides verbatim
    name: str               # called method symbol
    args: list              # argument ASTs collected from before the receiver
    prop: str | None = None
    bracket: bool = False   # the source spelled its subscript '[ … ]'


@dataclass
class ChainRecv:
    """Round-40 group43: the RECEIVER of a group's terminal f6 call when its
    root is a completed args-before chain VALUE rather than a member run —
    'loNodes.Item(lnNode).ChildNodes.Item(lnCnt)' (VFPxWorkbookXLSX.vcx::
    vfpxworkbookxlsx readstylesxml L2424) leaves `<chain>.ChildNodes` on the
    segment stack for _dec_group_run's NAME arm to pop, so that arm can still
    collect the WHOLE group stack as the call's argument list. Never a value:
    an unconsumed ChainRecv has no emission and rejects."""
    node: object            # completed chain value at the root of the receiver
    hops: list              # member names between that value and the f6 callee


@dataclass
class WithMemberPath:
    """e2 <f4-run> f7 <term> — WITH-scoped dotted reference: emits with a LEADING dot
    (.txtCompany.VALUE), matching canonical VFP inside a WITH block."""
    names: list
    # Round37 P8 (C09/G3): True ONLY for the rooted indexed-mid-call opener
    # `e2 <f4 hop>+ e5 <M>` (managecode::CmdSave '.Tree.Nodes(VAL(.Tree.Tag)).Tag',
    # dashboard::frmcontrol stmts 226/227). The default keeps every historical
    # construction — including the stock round-28 opener `e2 e5 <M>` — byte-exact.
    chain_call: bool = False
    # The WITH-scoped half of MemberPath.receiver — see that class. Oracle pair
    # s0008 'zzfoo(.Parent.BackColor)' = e2 f4<PARENT> f7<BACKCOLOR> f6<ZZFOO>
    # against s0009 '.Parent.BackColor.zzfoo()' = e2 f4<PARENT> f4<BACKCOLOR>
    # f6<ZZFOO>.
    receiver: bool = False


@dataclass
class MemvarRef:
    """f5 0d f7 <sym> — an m.<name> memory-variable reference (forced 235/235)."""
    name: str


@dataclass
class ByrefMemvarRef(MemvarRef):
    """r41 a01/a02: an m.-qualified variable argument whose push rode the
    measured 0x18 flag slot — '18 f5 0d f7 <sym>'. The oracle minimal pair
    differs in exactly that one byte: 'zzfoo(@m.lcbuf)' compiles to
    99fc43 18 f50df70100 f60000 and 'zzfoo(m.lcbuf)' to
    99fc43 00 f50df70100 f60000. a04 measures one flag per argument,
    position-independent, with a byval 00 in the middle; a09/c01/c03 measure
    the same law in the member-call family; a05 in assignment-RHS position;
    a08 inside a nested group. Renders '@m.NAME'."""


@dataclass
class WorkAreaRef:
    """f5 <01-0A> — the A-J workarea alias letters (rare)."""
    letter: str


@dataclass
class QualField:
    """Work-area alias plus field: f5 <01-0A> f7 <sym> is A.F1 (r42-tiera3 JOIN)."""
    letter: str
    name: str


@dataclass
class DoWhile:
    cond: object
    body: list
    rel_target: int = -1    # ENDDO prefix - code_base (forced 19/19)


@dataclass
class DoStmt:
    """DO <program> — file-literal or name-expression form; WITH-args supported.
    form=True marks the DO FORM spelling (18 14, round-28 W4): optional TO
    lvalue target and WITH-args whose items admit bare sym/member paths beside
    fc-groups (dashboardxx foxcharts1 s0 stmts9/27/43; shape CmdTexture s0[3]
    'DO FORM Texture WITH EVL(.TextureTheme,\'\') TO lcNew').
    in_target is the IN clause (r68-dotail): a filename string, an fc-group,
    or "" for a bare 16. The compiler interns IN before WITH. DO FORM IN is
    not in the language. name_target is DO FORM NAME (4a). flags is the
    interned NOREAD (53) / LINKED (be) / NOSHOW (ce) list (r68-formbank)."""
    prog: object            # str | expr
    args: list
    form: bool = False
    to_target: object = None
    in_target: object = None
    name_target: object = None
    flags: list = field(default_factory=list)


@dataclass
class SkipStmt:
    """SKIP — round-28 W4 measured widenings: `48 [fc <expr> [fd]] [16 <area>]`.
    'SKIP -1' <-> 48 fc f9 02 ffff (foxcharts fontname_assign s65 stmts111/155;
    buysweiwai CgView s1[2] 'SKIP-1'; buysmat CgView s1[5]); 'SKIP IN <alias>'
    <-> 48 16 f7<sym>. Plain bare 48 = SKIP (71 sightings)."""
    n: object = None
    in_area: str | None = None


@dataclass
class ScopeRef:
    """df [f4 hop]* e3 <class> (f7 <member> | f6 <method>).

    Property form is `Class::Member` (f7). Method form is `Class::Method(args)`
    (f6); arguments stand on the 43-group stack in front of df. Hops are a
    dotted prefix (`THIS.Custom::Init`).
    """
    cls: str
    member: str
    hops: tuple = ()
    args: list | None = None


@dataclass
class ArrayElement:
    """e0 opens bracket access, cd closes it; subscripts joined by ARGJOIN.
    'this.aObjectRefs[lnCount,1]' aligned (iter. 46)."""
    base: object
    subs: list
    method_receiver: bool = False


@dataclass
class IndexedElemRef:
    """e5 <name> <subscript-units> <closer> [f7 <prop>] in TARGET position —
    an indexed element reference with an optional terminal property read.
    Round-28 corpus alignment ('laArgs[1].Name = "ReadOnly"' family,
    foxchartsbeta.vcx::foxcharts sec11 stmts22-27/52-59/69-70 -> 54 e5 <arr>
    fc <sub> fd <closer> f7 <prop> 10 fc <rhs>; closers arrive as both 03 and
    16 across the carriers, recording the source's own '( … )'/'[ … ]'
    spelling). Value position: since round39 (W15, oracle u22) the SEGMENT
    spelling `<subscript packet> e5 <arr> f7 <prop>` is measured too and rides
    this node via _dec_w15_elem_prop_tail — target-position decoding here is
    unchanged."""
    base: str
    subs: list
    prop: str | None = None
    bracket: bool = False


@dataclass
class CatchWhen:
    """bb [d2 fc <cond> fd | 28 (f7 <sym> | f5 0d f7 <sym>) [d2 fc <cond> fd]]
    f9 05 <target> -- CATCH [TO var] [WHEN cond]. The measured target rides on
    statement decoding; the frame walker consumes it. For CATCH TO the variable
    arrives either as a plain symbol (fxlistener 'CATCH TO err') or in explicit
    memvar space (f5 0d, _reportlistener 'CATCH TO m.oError'); the combined
    TO..WHEN clause form carries both (foxchartsbeta 'Catch To m.loErr When
    m.loErr.ErrorNo=1426')."""
    cond: object = None
    target: int | None = None
    var: str | None = None


@dataclass
class FinallyClause:
    """bc f9 05 <target> -- FINALLY; the measured target rides on statement
    decoding (ENDTRY prefix - code_base); the frame walker consumes it."""
    target: int | None = None


@dataclass
class ReleaseAll:
    """3c 03 — RELEASE ALL (canonical-check flag: LIKE-clause variants unforced)."""
    pass


@dataclass
class ReleaseStmt:
    """RELEASE <name>[, name...] — names as lvalues joined by ARGJOIN."""
    names: list


@dataclass
class PublicStmt:
    """PUBLIC/PRIVATE name[, ...] — same name-list grammar as LOCAL/LPARAMETERS;
    lead 0x35 compiles PRIVATE (iter. 42)."""
    names: list
    private: bool = False

    def __post_init__(self):
        pass


@dataclass
class PrivateAllLike:
    """PRIVATE ALL [LIKE|EXCEPT <skeleton>] — 35 03 [18|bc] fb<string>.

    The LIKE arm is the original measurement; r50-leadsweep compiled the bare
    ALL and the EXCEPT qualifier beside it, and they are the same `03 18` /
    `03 bc` pair SAVE TO's own ALL LIKE / ALL EXCEPT tail carries."""
    skeleton: object = None
    word: str = "LIKE"


@dataclass
class ClearStmt:
    """CLEAR <clause> — EVENTS / DLLS <names> (round-24), plus round-28 W4
    carrier-settled forms: RESOURCES bare or with one grouped operand
    ('CLEAR RESOURCES' vfp_skins s5[3]; 'CLEAR RESOURCES (This._tempfile)'
    foxchartsbeta pattern s3[13] et al.), CLASS <name> ('clea class OO'
    txtcollect frmtxtcollect s0 stmt90 <-> 0e 4f f7<sym>), and TYPEAHEAD
    (_reports.vcx cmdGetReport s0[4] 'CLEAR TYPEAHEAD' <-> bare 0e d4).
    Round-42: WINDOW is 0e2c — WINDOW/WINDOWS/named collapse (r42-clear).
    Round-49 (r49-dllname): each DLLS name carries the opcode its source
    spelling produced, kept in name_ops beside the text."""
    clause: str
    names: list = field(default_factory=list)
    name_ops: list = field(default_factory=list)
    expr: object = None


@dataclass
class CopyStmt:
    """COPY [FILE <from>] TO <to> — lead 0x11. Full form oracle-measured
    (CMD_SWEEP.md row COPY); TO-only form corpus-aligned at frmSysinfo
    ('COPY TO LU3'). name_from is None for the TO-only spelling.
    Round-28 W4 carrier-aligned extensions:
      target/source may be fc-group expressions ('COPY FILE (m.cSkel) TO
      (m.cOut)' foxcharts fontname_assign s17[92..]); structure=True is the
      trailing cc byte ('COPY STRUCTURE TO tmplhd' salesgenyc fixdata s1[4]);
      delimited is None or ('CHARACTER', <char>) / ('TAB',) from the measured
      tail [d4] be d1 bf fb<char> | [d4] be d1 c4 (preorder1 Command3 s0[4]/[11]);
      type_word is that leading d4 — r47-typeword measured it present exactly
      when the source spells TYPE, so it is not noise.
    Round-32 carrier-aligned additions (lane-r32-2), each bound to its stored
    METHODS line and admitted ONLY in the measured operand spelling:
      memo=<field> is 'COPY MEMO <field> TO <target>' (_webview.vcx::
      _webbrowser3 s21 stmt13 <-> 11 1b f7<field> 28 <target-group>; field
      measured only as an f7 symbol, no tail clauses, and the target envelope
      hardened post-review to EXACTLY fc f7<u16> 03 at statement end — the
      runtime-parenthesised symbol target; literal/fc-string/paren-less
      spellings reject);
      to_array+fields is 'COPY TO ARRAY <arr> FIELDS <a,b,…>'.
    r48-valsweep: FIELDS also follows a plain target, and every file type is
    its own byte with no WITH tail (SDF d0, XLS c7, XL5 bb, FOXPLUS bd) — the
    same bank APPEND FROM uses.
      (mainmenu3.scx::msagent s0 stmt6 <-> 11 28 04 f7<arr> 11 f7<a>
      [07 f7<b>]*; array target measured only as an f7 symbol, FIELDS
      required, list runs to end-of-statement)."""
    target: str
    source: str | None = None
    structure: bool = False
    delimited: tuple | None = None
    memo: str | None = None
    to_array: bool = False
    fields: list | None = None
    type_word: bool = False       # d4: the source spelled TYPE
    file_type: str = ""           # r48: SDF/XLS/XL5/FOXPLUS, one byte each


@dataclass
class AtCommand:
    """`@ <row>, <col> [TO <row2>, <col2>] [SAY <expr> [PICTURE <pic>]]` — lead
    0x04 (r49-valsweep). Row and column are two fc groups joined by 07; the box
    form's second corner rides the same 28 TO mark every other command uses,
    and SAY is c4 with PICTURE's c2 behind it — the same picture byte BROWSE's
    :P clause carries. The final group's fd is reader-stripped as usual."""
    row: object
    col: object
    corner: tuple | None = None     # (row2, col2) for the box form
    say: object = None
    picture: object = None


@dataclass
class LocateFor:
    """LOCATE [ALL] FOR <cond> — `2d 13 fc <rpn>`; condition runs to stream end.
    all_scope marks the compiled leading scope byte 03 (`2d 03 13 fc <rpn>`),
    CONTEXT-LOCAL to lead 0x2d and admitted only immediately before the FOR
    group — round-32 forcing pair xfrxlib.vcx::xfrxfrmexportoptions s2 stmt21
    `15002d0313fcf71000f40200f40300f70f0010fdfe` <-> stored L84 'LOCATE ALL FOR
    targetCode = this.ooptions.cTarget' (twin xfcont s57 'LOCATE ALL FOR name =
    luObj'). Same compiled ALL byte DELETE (14 03) and REPLACE carry; an 03
    followed by anything else keeps the unwrapped rejection.
    Round-33 (locate_while lane): the FOR condition window stops at its own
    top-level fd, and an OPTIONAL trailing clause unit `2b fc <rpn2>` decodes
    as WHILE — the FINAL clause carries no fd (the reader strips only the
    statement-end trailer). Measured trio, each bound to its stored METHODS
    line: xfrxlib.vcx::xfrxie s0 stmt30 `2d13fcf71400d9000014fd2bfcf71300f7050014`
    <-> stored L54 'LOCATE WHILE XX000==liPage FOR XX001==""' (pair
    2027b10972a3ffdb; blocked before as 'expression opcode 0xfd') and the
    xfcont twins s15/s46 (stored METHODS L2338/L2363). Authored WHILE..FOR
    order is normalised by the compiler to FOR-clause-first on the wire, so
    emission followed the wire order — but the SYMBOL TABLE still numbers by
    first appearance in the source (r48-clauseorder, r49-clauseorder), and
    `while_first` carries what the table recovers: set only where both clauses
    introduce a name at this statement and the WHILE clause's is lower."""
    cond: object                       # None when the source wrote WHILE alone
    all_scope: bool = False
    while_cond: object | None = None   # `2b fc <rpn>` WHILE clause unit
    while_first: bool = False          # the source wrote WHILE before FOR
    scope_word: str | None = None      # REST (24) or NEXT (1e), r49-valsweep
    scope_expr: object | None = None   # the count NEXT carries


@dataclass
class DeleteFor:
    """DELETE FOR <cond> — 14 13 fc <rpn>; 13=FOR is pinned by the command-sweep
    cross-family rows (LOCATE 2d 13 / JOIN WITH..FOR / COPY '13 fc..fd'); the
    condition runs to stream end like LOCATE FOR (trailing fd reader-stripped).
    all_scope marks the compiled leading scope byte 03 ('DELETE ALL FOR',
    gfxnorender s1 stmt61) — the same statement-final ALL byte REPLACE uses."""
    cond: object
    all_scope: bool = False


@dataclass
class DeleteScopeStmt:
    """Scoped DELETE spellings measured under lead 0x14 beyond bare/FOR:
    kind="FILE": `14 12 <fb/d9 name | fc-expr [03] [fd]>` ('DELETE FILE P_ASS'
      translate_en.scx::Command4 s0[78]; 'DELETE FILE *.pngg' buyswwprint
      CdSend s0[355]; 'DELETE FILE (This._tempfile)' foxchartsbeta pattern
      s3[14]; 'DELETE FILE cfil+".pdf"' buyswwprint CdSend).
    kind="VIEW": `14 c4 fb/d9 <name>` ('DELETE VIEW TmpName' pcph.scx::Grid1
      s0 stmt10).
    kind="NEXT": `14 1e fc <n> [fd]` ('DELETE NEXT 1' utilityreportlistener
      s3 stmts18/20).
    kind="REST" / "RECORD": r54-inalias, `14 24` and `14 23 fc <n>`.
    kind="" — no scope word at all, the clause fields alone.
    The IN work area is `alias`, wired FIRST under the lead exactly like
      REPLACE's measured `3e 16 …` (same file: 'REPLACE .. WITH True IN
      c_cells'). Round-31 carriers are all VFPxWorkbookXLSX.vcx::
      vfpxworkbookxlsx, aligned to their own stored lines: bare 'DELETE IN
      c_sheets' deletesheet s21 stmts10/18, resetcolumnwidth s68 stmt2,
      unmergedcells s105 stmt6; scoped 'DELETE FOR workbook = tnWB .AND.
      sheet = lnSheet IN c_cells' deletesheet s21 stmt24 and 'DELETE FOR
      workbook = tnWB IN <alias>' deleteworkbook s22 stmts5-9. The authored
      order is normalised by the compiler to IN-clause-first; emission
      restores the source order, mirroring ReplaceStmt.
    r54-inalias put the whole bank behind one walk: the alias takes the three
      spellings the shared `16` mark carries, NOOPTIMIZE is a `30` in front of
      the scope word, and WHILE is a `2b` group behind the FOR one. Source
      order is DELETE [<scope>] [FOR] [WHILE] [IN <alias>] [NOOPTIMIZE]."""
    kind: str
    target: object
    cond: object = None       # the FOR condition when wired
    alias: str | None = None  # the IN work area
    while_cond: object = None
    nooptimize: bool = False


@dataclass
class EraseStmt:
    """ERASE — lead 20. Two measured operand spellings: the command-sweep bound
    literal-name form (`20 fb <len> <bytes>`, authored 'ERASE ers1.txt') and the
    corpus-forced expression form `20 fc <expr> [fd c4]` (31 dev methods, every
    stream shape aligned to its own stored METHODS source — decode-site comment).
    recycle=True is the measured `fd c4` tail = RECYCLE; NORECYCLE leaves no
    bytecode trace and so is never emitted."""
    name: object          # literal filename str, or the decoded operand AST node
    recycle: bool = False


@dataclass
class RenameStmt:
    """RENAME <old-file> TO <new-name> — lead 3d, lane r34-B (census
    /tmp/foxlift-r34-census). Two measured shapes, pinned by the stored METHODS
    lines of the two carriers:
      literal new name    purtcmanage.scx::CdSend stmts100/101 <-> L122/L123
        'RENAME 报表打印.frx TO reporttest.frx' / '.frt'
          wire = 3d fb<len><old> 28 fb<len><new>
      expression new name  pidocchk.scx::CdSend stmts131/132 <-> L174/L175
        'RENAME 报表打印.frx TO ALLTRIM(keytxt)+m供应商+''.frx'''
          wire = 3d fb<len><old> 28 fc <new-name expr>
    The old name is a string literal on every measured carrier; the new-name
    slot accepts ONE literal running exactly to end-of-statement OR ONE
    fc-wrapped expression consuming the whole remainder. Anything else —
    truncated length fields, a missing 28 TO marker, trailing bytes, symbol
    or bare-operand spellings in either slot — stays loudly Unsupported.
    Wire strings decode latin1 like every other literal payload."""
    old_name: str         # literal filename str
    new_name: object      # literal filename str, or the decoded operand AST node


@dataclass
class ParametersStmt:
    """PARAMETERS <name-list> — 34 f7 <sym> (HARVEST.md round-3, oracle-measured;
    distinct lead from LPARAMETERS af). List continuation shares the sibling
    declaration grammar (ARGJOIN between names)."""
    names: list


@dataclass
class OnStmt:
    """ON <form> — round-20 FORCED grammar: 31 <selector> [operands..]
    fb<u16-len><command-bytes> (probes/oracle_harvest/round20_*.json). The
    selector bytes are CONTEXT-LOCAL to lead 0x31: bd doubles as the THROW
    statement lead elsewhere, so this table must never go global.
    keyword: 'ERROR' | 'ESCAPE' | 'SHUTDOWN' | 'KEY LABEL'
             | 'SELECTION POPUP' | 'SELECTION MENU' | 'SELECTION BAR' | 'BAR'.
    handler is the stored command text, re-emitted verbatim — except the one
    STRUCTURED action the wire stores as tokens instead of text, ON BAR's
    'ACTIVATE POPUP <name>' (bc c6 f7<sym>), which is rebuilt from them."""
    keyword: str
    handler: str
    label: str | None = None      # KEY LABEL label text
    popup: str | None = None      # SELECTION POPUP/MENU name; BAR's OF popup; PAD name
    bar: object = None            # SELECTION BAR number expression AST
    of_menu: str | None = None    # ON PAD … OF _MSYSMENU (r43-onpad)


@dataclass
class OnBareStmt:
    """Bare ON under lead 0x7b — the SECOND ON lead, deliberately a separate node
    from OnStmt so the two selector maps cannot route through each other (round-20
    found the bytes are context-local per lead). Measured: PAGE carries NO handler
    tail at all (`7b be`, round-13 HARVEST); ERROR/SHUTDOWN carry the empty-handler
    placeholder `fb 00 00` (`7b 10 fb 00 00`, `7b cd fb 00 00`; ORACLE round-25
    o1/o2); KEY LABEL carries selector 17 + mark 32, an fb-string label and the
    same empty-handler placeholder (`7b 17 32 fb<label> fb 00 00`; CORPUS round-30,
    mhxpcontrol.vcx::text / xfrxlib.vcx::xfcont). Further selectors and non-empty
    handlers stay Unsupported — handler-bearing ON belongs to lead 31."""
    keyword: str
    label: str | None = None     # KEY LABEL label text (lead 7b carries no handler)


@dataclass
class RunStmt:
    """RUN / `!` — lead 0x43, the WHOLE command line as ONE verbatim fb string,
    switches and casing preserved ('/N7' corpus vs '/n7' authored both observed;
    ORACLE round-25 r1/r2). The fb length is attacker-shaped data; an overrun
    degrades to Unsupported."""
    text: str


@dataclass
class AppendFromStmt:
    """APPEND FROM — round-25 BOUND grammar: 06 15 fc <from-expr> [03] fd
    [13 fc <FOR> fd] [11 <f7 field syms joined 07>]; even plain-string FROM args
    arrive GROUPED (c5 refuted the ungrouped guess). Round-28 W4: the FROM
    operand also admits fb/d9 literals (CMD_SWEEP row APPEND 'apf1.txt';
    outmat matcalc s1[185] 'TmpLHB'), and the measured clause tail [d4] be d1
    bf {fb <char> | c4} renders DELIMITED WITH CHARACTER '<c>' | TAB
    ('APPEND FROM \'KQ.txt\' TYPE DELIMITED WITH TAB', attendanceforcheck cdget
    s0[40]; d4 is the source's TYPE word — r47-typeword measured it present
    only when the source spells TYPE, on APPEND FROM and COPY TO alike).
    r47-appendfrom: an UNGROUPED fb operand is the bare filename spelling
    (`APPEND FROM lhw`); 'lhw' is fc fb and "lhw" is fc d9 — three frames, the
    same law r46-setproc measured for SET PROCEDURE TO.
    The runtime-paren marker 03 is admitted
    ONLY inside the FROM group here; generalising it stays OPEN for its own lane."""
    source: object
    cond: object = None
    fields: list = field(default_factory=list)
    delimited: tuple | None = None
    bare_name: bool = False       # ungrouped fb/d9: the unquoted filename
    type_word: bool = False       # d4: the source spelled TYPE
    # r48-valsweep: every file type is its own byte and needs no WITH tail —
    # SDF d0, DELIMITED be, XLS c7, XL5 bb, FOXPLUS bd. `delimited` still
    # carries the DELIMITED WITH … tail, which only DELIMITED takes.
    file_type: str = ""


@dataclass
class AppendGeneralStmt:
    """APPEND GENERAL <field> [CLASS <expr>] [DATA <expr>] — round-28 W4,
    carrier-settled: `06 d5 f7<field> [4f fc<class>[03]fd] [c2 fc<data>fd]`
    ('APPEND GENERAL msgraph DATA lcData' stock cboMonth s0 stmt18;
    'APPEND GENERAL GEN1 CLASS "msgraph.chart" DATA m.CGDATA' chart TJTX
    s0 stmt21 — the CLASS/DATA values arrive fc-grouped, paren marker only
    where the source groups)."""
    field_name: str
    class_expr: object = None
    data_expr: object = None


@dataclass
class AppendMemoStmt:
    """APPEND MEMO <field> FROM <file> [OVERWRITE] — round-28 W4,
    carrier-settled: `06 1b f7<field> 15 <fb/d9 | fc-group>` + optional c5
    ('APPEND MEMO Source FROM (lcFileName) OVERWRITE' _webview refreshsource
    s0 stmt21; same shape at _reports.vcx line 743). c5 = OVERWRITE."""
    field_name: str
    source: object
    overwrite: bool = False


@dataclass
class DeclareDllStmt:
    """DECLARE [ret] <func> IN <lib> [AS <alias>] [param-types] — statement lead
    0x7c. All 301 lead-7c statements in the frozen benchmark conform to this one
    shape.

    Parameter NAMES never reach the bytecode, so params re-emit nameless. Round-41
    measured this rather than inferring it (probes/oracle_harvest/round41_
    declareparams_*): named, nameless and RENAMED spellings of one DECLARE compile
    to a single identical stream and symbol table, while two negative controls (a
    changed type, an added parameter) do separate; no name appears in the plain, the
    by-ref @ or the AS-alias subform, the last of which keeps its author-written
    alias right beside the parameter list. Emitting a name here would be invention,
    not recovery: it raises the text-match score and breaks canonical equivalence.

    The library, by contrast, keeps its spelling — see the reader for the fc wrapper."""
    func: str
    lib: str                      # library text as written: a bare name, or a rendered
                                  # IN-expression (quoted literal, parenthesised group)
    ret: str | None = None
    alias: str | None = None
    params: list = field(default_factory=list)   # ['INTEGER', 'SINGLE @', ...]
    trailing_comma: bool = False  # r44-decl7c: wire ARGJOIN with no following type


@dataclass
class ScatterStmt:
    """Lead 0x5e — SCATTER's clause grammar, read by `_dec_scatter_gather`:

        5e [08 BLANK] [1b MEMO] <destination> [11 FIELDS ...]

    Destinations are c2 (MEMVAR), 28 f7 <arr> (TO <array>) and 4a <operand>
    (NAME <object>, whose operand spellings `_name_operand` reads). The two
    modifiers are stored BEFORE the destination in a fixed 08-then-1b order and
    never stand without one (r58-destbank: VFP9 rejects SCATTER MEMO and
    SCATTER BLANK). Round 17 measured 5e 28 f7 <arr> and 5e 1b c2; round 28 W4
    the NAME operands (xfrxlib Xfrxcmd1 s0 stmt21 'SCATTER NAME m.loForm', and
    _reportlistener s54[7] with a FIELDS clause); round 42 I8 the exact-length
    NAME-bare forms; r49-menusweep which byte each FIELDS qualifier rides;
    r58-destbank the destination bank and r58-fieldlist the FIELDS lists."""
    target: str | None = None   # array symbol for the TO form (28 f7)
    memvar: bool = False        # c2 destination (r58-destbank: MEMVAR)
    memo: bool = False          # 1b modifier (r58-destbank: MEMO)
    blank: bool = False         # 08 modifier (r58-destbank: BLANK)
    name_obj: str | None = None # NAME clause operand (4a), rendered
    additive: bool = False      # 01 after a NAME destination (r58-additive)
    fields_names: list | None = None    # FIELDS <list>, f7 items joined by 07
    fields_like: list | None = None     # FIELDS LIKE <skeletons> (11 18)
    fields_except: list | None = None   # FIELDS EXCEPT <skeletons> (11 bc)


@dataclass
class GatherStmt:
    """Lead 0x5f — GATHER's destination bank. Round-17 GATHER FROM <array>
    (5f 15 f7 <arr>); 15 is contextual beneath this lead, never a global token.
    Round-28 W4: 5f 4a <path> = 'GATHER NAME THIS.evaluateContentsValues'
    (_reportlistener s54[12]). r58-destbank: c2 = MEMVAR (5f c2) and 1b = MEMO,
    the modifier stored before the destination (5f 1b c2 = GATHER MEMVAR MEMO,
    5f 1b 4a … = GATHER MEMO NAME)."""
    source: str | None = None   # array symbol for the FROM form (15 f7)
    name_obj: str | None = None # NAME clause operand (4a), rendered
    memvar: bool = False        # c2 destination (r58-destbank: MEMVAR)
    memo: bool = False          # 1b modifier (r58-destbank: MEMO)
    fields_names: list | None = None    # FIELDS <list>, f7 items joined by 07
    fields_like: list | None = None     # FIELDS LIKE <skeletons> (11 18)
    fields_except: list | None = None   # FIELDS EXCEPT <skeletons> (11 bc)


@dataclass
class ErrorStmt:
    """Lead 0xa8 — ERROR <expr>[, <expr>...] (round-18 oracle-measured,
    probes/oracle_harvest/round18_streams.json). Every compiled argument but the
    LAST closes with fd before the 07 joiner; the final expression runs UNCLOSED
    to end of statement. The argument is required — bare ERROR cannot compile."""
    args: list


@dataclass
class ThrowStmt:
    expr: object


@dataclass
class NodefaultStmt:
    """bare NODEFAULT — event-bypass statement in class methods."""
    pass


@dataclass
class ClassMethodIndex:
    """DEFINE CLASS class-init 0xa2: a2 e9 00 <u32le index> (r43-class).

    Compiler-generated method registration. One per PROCEDURE/FUNCTION
    member; empty classes have none. The member body is a separate
    section, so this statement has no source line.
    """
    index: int


@dataclass
class ProtectedProp:
    """PROTECTED / HIDDEN <prop>[, <prop>]* in class-init.

    a1 f7 <u16> for the single PROTECTED name (r43-class); r50-leadsweep
    compiled HIDDEN beside it (9f, the same frame) and both words with a
    07-joined list, which is the shared declaration-list grammar."""
    name: str
    more: list = field(default_factory=list)
    word: str = "PROTECTED"


@dataclass
class CommandLine:
    """A measured command whose whole recovered surface is its own text.

    r50-leadsweep: the sweep's file verbs are leaf statements — one verb, a
    name or file operand and a bank of one-byte clause words. They carry no
    sub-statement and nothing downstream consumes their parts, so the reader
    keeps the rendered line, the way SetStmt does for a FORCED SET variant."""
    text: str


@dataclass
class PrintJobStmt:
    """PRINTJOB … ENDPRINTJOB — 76 f9 05 <u16> … 77 (r50-leadsweep).

    The same jump-tailed opener plus bare sentinel SCAN and FOR EACH carry."""
    body: list = field(default_factory=list)
    rel_target: int = -1


@dataclass
class ImplementsStmt:
    """IMPLEMENTS <interface> IN <library>: b9 fb <iface> 16 fb <lib>.

    r50-leadsweep. The interface is a bare identifier the compiler uppercases;
    the library rides the same 0x16 IN mark FOR EACH's collection uses, with
    its own text intact."""
    name: str
    library: str


@dataclass
class AddObjectStmt:
    """ADD OBJECT <name> AS <class> [WITH prop = expr, ...].

    96 2e f7 <obj> 51 f7 <class> [d1 <f7 prop 10 fc expr>+]. r43-class.
    """
    name: str
    class_name: str
    with_pairs: list = field(default_factory=list)


@dataclass
class BackslashLine:
    """'\\ <text>' merged-output line — lead 0x8d (round-29; CMD_SWEEP.md row
    '\\', census charts.scx::foxcharts1 s2 stmt73 empty form 8dfb0000).

    r50-leadsweep measured its sibling: `\\\\ <text>`, lead 0x8e, is the same
    envelope with no trailing line feed."""
    text: str
    feed: bool = True


@dataclass
class HelpStmt:
    """HELP [ID <expr>] [NOWAIT] <topic> — round-29. Both measured shapes end
    in an fb topic string that is EMPTY on every carrier (oracle bare '24fb0000',
    census cmdHelp '2449 .. 3a fb0000'). r51-helptopic: a NON-empty topic is the
    verbatim source tail, separator space and source quoting included, and is
    emitted as it stands."""
    id_expr: object = None
    nowait: bool = False
    topic: str = ""


@dataclass
class KeyboardStmt:
    """KEYBOARD '<keys>' [PLAIN] — round-29: the 3b tail is source-bound to
    the PLAIN word and always follows an explicit fd; the bare statement-final
    group spelling carries no suffix (managecode '{ctrl+f10}')."""
    keys: object
    plain: bool = False


@dataclass
class ShowWindowStmt:
    """SHOW or HIDE WINDOW <name> [IN WINDOW <parent>].

    Round-29 corpus shape for the IN-WINDOW form: the wire carries the
    IN-WINDOW (16) argument FIRST, both operands fc-groups. r48-valsweep
    measured the rest of the frame — the clause is optional, the name may be a
    bare `f7 <sym>`, HIDE is the same shape under lead 0x87, and the SHOW-only
    modifiers REFRESH/TOP/BOTTOM/SAME sit between the `2c` and the name."""
    name: object
    in_window: object
    verb: str = "SHOW"
    modifier: str = ""


@dataclass
class ActivateWindowStmt:
    """74 2c [ce] 16 <parent-group> <name-group> — ACTIVATE WINDOW <name>
    IN WINDOW <parent> [NOSHOW] (round-33; mhxpcontrol.vcx::extwindow s2
    'ACTIVATE WINDOWS (THISFORM.NAME) IN WINDOWS (PARENTWIN) NOSHOW' <->
    742cce16fcf7010003fdfcf40200f7040003). The wire mirrors SHOW WINDOW
    (lead 0x80): the IN-WINDOW argument arrives FIRST, both operands
    parenthesised fc-groups; ce is this lead's NOSHOW flag only.
    r40-H adds the second measured frame `74 2c cf <name>` — ACTIVATE WINDOW
    <name> SAME, no IN-WINDOW argument (oracle f21, raw-equal to
    _reports.vcx::_output #110 modulo symbol index).
    r42-I7 adds the clause-free frame `74 2c <name>` — bare f7 <sym> or an
    fc-group (paren / member path). TOP=29, BOTTOM=36, and NOSHOW without
    IN stay Unsupported under the same schema id."""
    name: object
    in_window: object
    noshow: bool = False
    same: bool = False


@dataclass
class ZoomWindowStmt:
    """8c 2c <name> <mode> — ZOOM WINDOW <name> MAX|MIN|NORM. The name rides
    either a bare f7 <sym> or a parenthesised fc-group; the mode byte is
    mandatory (the oracle rejects an unrecognised keyword outright, so there is
    no bare frame to admit). r40-H, carrier _reports.vcx::_output #92."""
    name: object
    mode: str


@dataclass
class SeekStmt:
    """SEEK <expr> — fc-wrapped operand runs UNCLOSED to end of statement."""
    key: object


@dataclass
class DebugoutStmt:
    """DEBUGOUT <expr> — aa fc <expr>, no closing fd (CMD_SWEEP.md row)."""
    expr: object


@dataclass
class MouseStmt:
    """MOUSE — round-29 measured one carrier shape, `ad ca 2c <w-group> 05
    <r-group> 07 <c-group>`, and r49-valsweep the whole clause bank in one
    matrix:

        ad [ca PIXELS] [2c <window group>] [c3 CLICK | c5 DBLCLICK | c6]
           [05 AT | 28 TO] <row group> 07 <col group>

    Every clause is optional and the wire order is CANONICAL — `MOUSE WINDOW
    (w) CLICK AT 1, 1` and `MOUSE CLICK AT 1, 1 WINDOW (w)` are one frame — so
    emission writes the documented order. DRAG spells its coordinates TO
    rather than AT (`c6 28`), which is why the coordinate mark is carried."""
    row: object
    col: object
    window: object = None
    pixels: bool = True         # round-29's carrier spelled it
    action: str = ""            # CLICK / DBLCLICK / DRAG
    to_coords: bool = False     # DRAG's TO instead of AT


@dataclass
class CdStmt:
    """CD/CHDIR <path> — fb/d9 literal or one fc-group operand."""
    path: object


@dataclass
class MkdirStmt:
    """MKDIR/RMDIR <dir> (aliases MD/RD share leads 0xb1/0xb2; alias choice is
    compiler-invisible so the corpus-majority spelling is canonical)."""
    path: object
    remove: bool = False


@dataclass
class ListToFileStmt:
    """LIST [MEMORY|STATUS] [LIKE <skeleton>] TO [FILE] <target> [NOCONSOLE].

    Round-29 corpus faa199b32ddf0b1c s15 stmt21 pins the bare spelling
    'LIST TO FILE (...) NOCONSOLE' with NOCONSOLE bound to the exact measured
    tail 39 f80300. Round-35 foxcharts s59 stmt79/stmt83 (aligned statement-exact
    to stored lines L3306/L3310) force three clause bytes: 1b=MEMORY,
    cb=STATUS and 18 <fb-string>=LIKE skeleton; both carriers end bare 39, the
    same NOCONSOLE marker without its operand. Each shape emits its OWN measured
    wording: plain TO under a clause byte, TO FILE on the bare form."""
    target: object
    noconsole: bool = False
    clause: str | None = None        # measured clause word: MEMORY / STATUS
    like_pattern: str | None = None  # LIKE skeleton, emitted as a bare word


@dataclass
class UseStmt:
    """USE — bare closes current table; clause form carries name/IN-area/EXCLUSIVE
    (iter. 36, 'USE LU3 IN 0 EXCLUSIVE' aligned) plus the corpus-aligned mode flags
    SHARED/NOUPDATE, post-name AGAIN and an ALIAS symbol operand
    ('USE (THIS.CommandClauses.File) AGAIN SHARED NOUPDATE ALIAS FRX',
    _reportlistener.vcx::fxlistener s38)."""
    def __init__(self, name=None, in_area=None, exclusive=False,
                 shared=False, noupdate=False, again=False, alias=None,
                 norequery=False, nodata=False, order=None):
        self.name = name
        self.in_area = in_area
        self.exclusive = exclusive
        self.shared = shared
        self.norequery = norequery
        self.nodata = nodata
        self.order = order
        self.noupdate = noupdate
        self.again = again
        self.alias = alias


@dataclass
class ExternalStmt:
    """EXTERNAL <kind> <name> — forced subset: only the CLASS clause byte 0x4f with an
    fb-string operand is admitted ('90 4f fb "…"' <-> 'EXTERNAL CLASS _GDIPLUS.VCX',
    _reportlistener.vcx::fxlistener s0). ARRAY(04)/PROCEDURE(be) stay Unsupported."""
    kind: str
    name: str


@dataclass
class OpenDatabaseStmt:
    """OPEN DATABASE — '95 c2 fb <name> [c2]' (7/7 corpus alignments): leading c2 marks
    the db-name string literal; the TRAILING c2 is present exactly when the stored source
    spells SHARED. Any other shape stays Unsupported."""
    name: str
    shared: bool = False


@dataclass
class ForStmt:
    var: object
    start: object
    end: object
    step: object | None
    body: list
    rel_target: int = -1


@dataclass
class ForEachStmt:
    """b5 <loopvar> 16 <collection> [c2] (f9 05 <u16> | e9 00 <u32>) — FOR EACH
    <var> IN <collection> [FOXOBJECT]. Corpus-forced (fxlistener sec2 x2 +
    _outputdialog sec28); the tail word verified == matching ENDEACH prefix -
    code_base at every occurrence. e9 00 <u32> is the long-jump width of the
    same anchor (round-42 I5). Stored sources spell the loop end NEXT and
    ENDFOR alike — identical bytecode; canonical emission is ENDFOR."""
    var: object            # MemvarRef | Sym
    collection: object     # MemberPath
    foxobject: bool = False
    body: list = field(default_factory=list)
    rel_target: int = -1
    as_class: object = None   # 'AS <class>' on the loop variable (r50-sysapp)
    of_lib: object = None     # its optional 'OF <library>'


@dataclass
class LoopStmt:
    pass


@dataclass
class ExitStmt:
    pass


@dataclass
class OtherwiseClause:
    """OTHERWISE clause of DO CASE; rel_target verified against ENDCASE at walk time.

    Short width: 32 f9 05 <u16>. Long width (same slot, round 42): 32 e9 00 <u32>,
    length exactly 7 — listener.vcx fxmemberdatascript s3/s6 and
    utilityreportlistener s1, plus oracle s0006 sibling-forced module-wide long
    jumps. Walk-time verification is width-independent."""
    rel_target: int = -1


@dataclass
class ScanStmt:
    """SCAN frame; body runs until ENDSCAN at depth 0.

    Round-32 additions, measured on stored carriers only:
      while_cond  -- clause selector 2b under the 7e frame
                     ('Scan While rownum = ln_MaxRow', org_chart.vcx::
                     organizationchart s1 stmt12 -> 7e 2b fc .. fd f9 05 <u16>);
                     the ALL+WHILE and FOR+WHILE combinations are UNMEASURED and
                     stay Unsupported.
      rel_target  -- the trailing locator word's value when one is present
                     (f9 05 <u16>, or its round-28 e9 00 <u32> long spelling).
                     On the measured 2b frames it BINDS as the paired ENDSCAN
                     prefix minus code_base (exact on all four population
                     carriers: 884/1645/3564/4669); _walk_block verifies it and
                     calls a mismatch corruption. Legacy 03/13 frames keep their
                     historical consume-without-verify behavior -- the corpus
                     holds a 13-frame whose word contradicts its distance
                     (968b541af4b5f42d s3), so the binding is NOT extended there
                     without fresh evidence."""
    cond: object = None
    scan_all: bool = False
    while_cond: object = None
    rel_target: object = None
    # r48-valsweep: the scope word and the two condition words are independent
    # bytes, so any scope may precede either condition and both conditions may
    # be present. ALL keeps its own flag because every earlier round's frames
    # and pins are written against it.
    scope_word: str = ""       # REST | NEXT | RECORD ("" when none or ALL)
    scope_expr: object = None  # the count/record number NEXT and RECORD take
    nooptimize: bool = False


@dataclass
class EmptyArg:
    """One OMITTED call-argument slot inside a 43 group: a single db byte,
    position-independent (round-22 oracle-forced, probes/oracle_harvest/
    round22_streams.json d2/d3/d4 vs d1 control; corpus This.Nodes.Add(,,...)
    shape). Renders as an empty string so the joined argument list keeps the
    omitted slots' commas. A group consisting of nothing but empty slots is an
    UNMEASURED input shape (no oracle probe and no corpus occurrence) -- it
    renders like the zero-argument form rather than being invented-rejected."""
    pass


@dataclass
class IndexedMemberRef:
    """f4 <obj> e5 <member> fc <sub> fd 03 f7 <prop> -- INDEXED-MEMBER reference
    <obj>.<member>(<sub>).<prop>, bound byte-exact twice as a PUT target
    (round-22 streams v1 literal subscript / v2 RECNO() subscript == the exact
    corpus 'This.Nodes(RECNO()).Image=nodeicon' form). e5 doubles here as the
    member-naming token of the lvalue form (its other meaning -- array-element
    method receiver closer -- lives inside 43 groups); the 03 joins the property
    component, same contextual-reuse family as the DIM / REPLACE-ALL trailing
    03. Bound as an lvalue ONLY: value-position indexed reads ride the existing
    call-tail machinery (measured v3, already decoding at bind time).

    r54-withindex: the joining byte is `16` when the source spelled its
    subscript '[ … ]' instead, the same source-spelling provenance ArrayRef and
    ObjectChain carry, and the property tail is identical either way."""
    obj: str           # receiver object name (single measured f4 token)
    member: str        # indexed member name
    sub: object        # subscript expression AST
    prop: str          # terminal property name
    bracket: bool = False   # the source spelled its subscript '[ … ]'


@dataclass
class ObjectChain:
    """Corpus-forced member/method chain (population lane PATHS):

        <recv f4-run> . m1(args1) [ . hop ]* [ . m2(args2) ]* [ . prop ]

    where each call is wire-encoded `e5 <method-sym> fc <args fd [07 fc args fd]*> 03`
    and hops are f4/f6/f7 member tokens. Generalises the single-f4 indexed-member
    lvalue above to multi-hop receivers, multi-argument calls and chained calls
    ('Character(AgentID).Play(MyKey(s1))', mainmenu3.scx::Timer1), in lvalue,
    expression-operand and bare-call-statement positions. recv may also end at an
    OBJECT with no terminal property -- exactly the value paths this lane admits.

    call_brackets records, per call link, whether the link's closing byte was the
    bracket marker 16 rather than the paren marker 03 -- the same source-spelling
    provenance ArrayRef/IndexedElemRef already carry. Short or absent (every
    historical constructor passes three positional fields) it reads False, so the
    paren rendering those chains are pinned on is unchanged."""
    recv: list                       # leading receiver member names
    calls: list                      # [(method_name, [arg ASTs]), ...]
    tail: list = field(default_factory=list)   # trailing property/member names
    call_brackets: list = field(default_factory=list)   # per call: '[ … ]' spelling
    # r48-callhops: member names read BETWEEN two calls, per call link. The
    # reader used to append them all to `tail`, which rendered every hop after
    # the last call — 'ListItems.Item(i).ListSubItems.Item(1).Text' came back
    # as 'ListItems.Item(i).Item(1).ListSubItems.Text'. Short or absent it
    # reads empty, so every historical constructor is unchanged.
    link_hops: list = field(default_factory=list)

    def __str__(self) -> str:        # not used by _emit; keeps dataclass repr sane
        return "ObjectChain(%r)" % (self.recv,)


def _chain_bracket(chain, n):
    """True when call link n of an ObjectChain closed on the bracket marker 16,
    i.e. the source spelled its subscripts '[ … ]'. Absent provenance reads
    False so the historical paren rendering stands."""
    return n < len(chain.call_brackets) and chain.call_brackets[n]


@dataclass
class TryStmt:
    """TRY frame; body runs until its CATCH or ENDTRY at depth 0. Targets are the
    measured code-base-relative offsets (the opener's NEXT clause mark: the CATCH
    prefix when one follows, else the FINALLY prefix -- round-35, measured
    pimutilselect cmdPrint / forest FrmSmartSystem -- else the ENDTRY prefix; the
    CATCH's own target is its next clause mark -- the FINALLY prefix when one
    follows, else ENDTRY, measured on _reportlistener) -- verified by the walker,
    never emitted."""
    body: list
    catch_body: list | None = None   # None => no CATCH; [] => empty handler
    catch_cond: object = None
    target: int | None = None
    catch_target: int | None = None
    catch_var: str | None = None     # CATCH TO variable spelling (None = no TO)
    finally_body: list | None = None # None => no FINALLY; [] => empty FINALLY


@dataclass
class CaseClause:
    cond: object
    body: list
    rel_target: int = -1
    # r54-macrocase: a CASE whose condition holds a macro is never compiled —
    # the whole line is stored verbatim under lead 01 and carries the same
    # `f9 05 <u16>` trailer a compiled 0c mark carries. `verbatim` is that
    # stored line and `cond` is None for it; the clause is otherwise identical.
    verbatim: str | None = None


@dataclass
class DoCase:
    clauses: list
    t_first: int = -1     # measured opener targets (verified at walk time)
    t_end: int = -1
    otherwise_body: list | None = None
    # round-35 zero-width region (pidocchk CdQuery L34/L35): an opener whose two
    # words are EQUAL declares no clause region; only complete nested frames sit
    # between it and its own ENDCASE, walked into this body (None = normal form).
    body: list | None = None


@dataclass
class SqlSelectColumns:
    """Column-list SQL-SELECT: 'SELECT e1 AS a1, e2 FROM t INTO CURSOR c' (forced:
    systeminfo::frmSysinfo). Emitted head is pre-rendered by the parser; readwrite
    flags the measured trailing d7 = READWRITE tag (r37 C12/sw9), nofilter the
    trailing cd = NOFILTER tag sharing that slot (round-40 lane F). The emitter owns
    the spelling so each tag is emitted EXACTLY once. tail_text carries whatever
    the source wrote AFTER its INTO clause (r49-clauseorder), so a tag that
    belongs to that clause still lands beside it. r54-selnointo: `display`
    carries the NOCONSOLE / NOWAIT words of the measured trailing bank, which
    the compiler normalises to its own wire order."""
    text: str
    readwrite: bool = False
    nofilter: bool = False
    tail_text: str = ""
    display: tuple = ()


@dataclass
class SqlSelectIntoCursor:
    """6f 15 <FROM-str> c7 [c6 fc <where> fd] c3 fc <order> fd [3c] bc bd <CURSOR-str>
    [d7] — FORCED subset of VFP SQL-SELECT: star projection, optional WHERE, one ORDER
    BY term, INTO CURSOR, optional READWRITE-style trailer."""
    table: str
    order_expr: object | None
    desc: bool
    cursor: str
    where: object | None = None
    readwrite: bool = False


@dataclass
class SetStmt:
    """FORCED SET variant with no arguments."""
    text: str


@dataclass
class SetDatasessionTo:
    """SET DATASESSION TO <expr> — 03 postfix is parenthesised source (r46-datasession)."""
    expr: object
    paren: bool = False


@dataclass
class ReplaceStmt:
    """3e <lv> d1 fc <expr> fd [07 ...]* [03] — REPLACE f WITH e pairs; a trailing
    bare 03 is the compiled ALL clause (FINDINGS iter. 8, forced 9/9). Optional
    trailing FOR clause: 13 fc <cond> fd (iter. 33, mainmenu Command5 aligned)."""
    pairs: list
    all_scope: bool = False
    for_cond: object = None
    in_spec: object = None      # REPLACE ... IN <alias> | IN (<expr>) — clause-
                                # first wire layout 3e 16 … (VFPxWorkbookXLSX,
                                # fxmemberdatascript; population lane PATHS)
    all_first: bool = False     # r49: the source wrote ALL before the fields


@dataclass
class SumStmt:
    """SUM e[,e..] TO t[,t..] — single-pair form forced by mainmenu1::GrdList;
    multi-pair targets-first compiled form iter. 38 (preorder1::CdQuery).
    for_cond: optional leading FOR scope clause, `13 fc <cond> fd` before the TO
    section ('SUM cash*profit/100,cash TO a1,a2 FOR !EMPTY(profit) AND …',
    preorder1.scx::CdQuery stmt 113)."""
    target: object
    expr: object
    for_cond: object = None
    for_first: bool = False     # r49: the source wrote FOR before TO
    while_cond: object = None
    scope: object = None        # (word, count-expr or None), r59-sumscope
    to_array: bool = False      # `28 04`: TO ARRAY

    def __init__(self, target, expr, for_cond=None, for_first=False,
                 while_cond=None, scope=None, to_array=False):
        # accept legacy single pair or parallel lists
        self.target = target if isinstance(target, list) else [target]
        self.expr = expr if isinstance(expr, list) else [expr]
        self.for_cond = for_cond
        self.for_first = for_first
        self.while_cond = while_cond
        self.scope = scope
        self.to_array = to_array


@dataclass
class CountStmt:
    """COUNT [FOR <cond>] TO <memvar> — lead 12; base form `12 28 f7 <sym>`
    (TOKEN_REFERENCE §leads). FOR clause rides before the TO section exactly as in
    SUM: 'COUNT TO X1 FOR ALLTRIM(TA010)<=X AND MD002=Y'
    (picost.scx::Command5 stmt 82). Targets only — no expression list is measured.

    Round-32 additions, measured on stored carriers only:
      count_all   -- explicitly spelled ALL scope word 03 before the clause
                     ('COUNT ALL FOR INLIST(ObjType,… ) AND Double AND Resoid # 1
                     TO m.liTally', _reportlistener.vcx::xmllistener s50 stmt19 ->
                     12 03 13 fc .. fd 28 f5 0d f7 <sym>); mirrors the 7e-frame
                     03=ALL bound in HARVEST round-22. SUM has no measured scope
                     word, so the byte stays closed under lead 4b.
      while_cond  -- clause selector 2b ('COUNT TO lii WHILE XX000==liPage',
                     xfrxlib.vcx::xfrxie s0 stmt26 -> 12 2b fc .. fd 28 f7 <sym>).
                     ALL+WHILE and FOR+WHILE are UNMEASURED -> Unsupported.
      The TO target may ride the explicit memvar-space spelling f5 0d f7 <sym>
      (= m.<name>); the existing lvalue grammar already decodes it."""
    target: object
    for_cond: object = None
    while_cond: object = None
    count_all: bool = False
    to_first: bool = False      # r49: the source wrote TO before FOR/WHILE
    scope: object = None        # (word, count-expr or None), r59-countscope


@dataclass
class GoTop:
    """GO/GOTO movement statement following SELECT — bare 23 29 FORCED 27/27.

    Measured family extension (TOKEN_REFERENCE:73 '23 29/36 GO/GOTO TOP/BOTTOM';
    lane pop-go alignment: 144 order-paired wires across 42 carriers, source word
    GO 135 : GOTO 10 -> canonical spelling 'GO'):
      selector   None = TOP (wire 29) | 'BOTTOM' (wire 36) | an expression node
                 from `fc <expr>` ('GO 1', 'GO mRec', 'GO (liRecno)').
      in_target  optional IN-clause target node from the measured wire order
                 [16 <target> [<rec-expr>] [29|36]] — a bare Sym or the fc-group
                 AST. Internal PAREN (03) nodes are preserved by _dec_expr, so
                 re-emitted parentheses round-trip byte-exactly ('GO mRec' has
                 none, 'GO (liRecno)' does)."""
    selector: object = None
    in_target: object = None


@dataclass
class WaitStmt:
    """WAIT family per the oracle matrix (HARVEST.md): WAIT CLEAR / WAIT <expr> /
    WAIT TIMEOUT <expr> / WAIT WINDOW <expr> [NOCLEAR] [NOWAIT] [AT r,c]
    [TIMEOUT n].

    Clause order is a rendering choice, not recovered data: VFP9 canonicalises the
    clauses to one wire order and the author's own order is unrecoverable (round-41
    lane R41-D; see the decode-site comment and tests/test_round41_waitwin.py)."""
    expr: object | None
    clear: bool = False
    bare_wait: bool = False  # 52 fc .. : no WINDOW keyword measured
    at: tuple | None = None
    timeout: object | None = None
    noclear: bool = False
    nowait: bool = False


@dataclass
class SelectStmt:
    """46 f7 <u16>: SELECT <workarea> — forced 198/198 against stored sources."""
    name: str


@dataclass
class If:
    cond: object
    body: list
    rel_target: int = -1        # measured u16 (meaning depends on ELSE presence, see walk)
    else_body: list = field(default_factory=list)
    else_target: int = -1       # the ELSE statement's measured u16


@dataclass
class Call:
    func: tuple          # ('user', name) | ('bare_builtin'/'builtin'/'x1a_builtin', id)
    args: list


@dataclass
class SqlAgg:
    """SELECT COUNT/SUM/AVG/MIN/MAX. 43 [ea ff] <* 04 | f7 col> ea <id>."""
    name: str
    inner: str


@dataclass
class ByrefCall(Call):
    """r38 M3/a0004: the nested array-element group closed by 18 f6 <name> —
    '@arr(subscript)' compiles as <43> <subscript literal> 18 f6 <array-name>,
    the flag preceding the NAME ref, not the subscript. Renders '@NAME(args)'.
    Measured at one subscript shape (a0004); richer subscripts stay unmeasured."""


@dataclass
class Mod:
    a: object
    b: object


@dataclass
class SqlSubquery:
    """`e8 <u16 n> <n bytes>` — a SQL subquery as one expression operand
    (r54-subquery). `text` is the rendered `(SELECT …)`; `prefix` carries the
    operator whose `ea` pair applies it: EXISTS, ANY, or ALL."""
    text: str
    prefix: str = ""


@dataclass
class Bin:
    op: str
    l: object
    r: object


@dataclass
class ShortCircuit:
    op: str              # 'AND' | 'OR'
    l: object
    r: object


@dataclass
class Neg:
    x: object


@dataclass
class Not:
    x: object


@dataclass
class Paren:
    x: object


# statements
@dataclass
class Assign:
    lv: object
    expr: object


@dataclass
class Store:
    expr: object
    targets: list


@dataclass
class Print:
    ee: bool
    args: list


@dataclass
class Local:
    names: list          # [(name, typename|None)]


@dataclass
class LParams:
    # Entries are plain name strings, or (name, class, library) tuples for typed
    # members ('Lparameters to_Node As ChartNode Of ..\org_chart', round-24 l1).
    names: list


@dataclass
class DefineStmt:
    """Lead 0x73 — ONE construct, keyword byte selects the object (round-24).
    WINDOW: 73 2c f7<name> 15 fc<r>fd 07 fc<c>fd 28 fc<r>fd 07 fc<c>fd
            [0d4e scheme][c1 GROW][be CLOSE]; the COLOR SCHEME group is
            wire-reordered ahead of grow/close regardless of source order.
            r40-H: <name> may equally be an fc <expr> fd PAREN group; the
            position may be spelled `05 <row> 07 <col> d3 <h> 07 <w>` (AT/SIZE);
            and the clause space carries FONT (40), TITLE (27), NAME (4a),
            IN WINDOW (16) plus the 16 measured attribute words. Attribute
            order on the wire is CANONICAL, never the source order.
    POPUP:  73 c6 f7<name> [0d4e COLOR SCHEME][cf SHADOW][c8 MARGIN][16 IN<name>]
            [15 <groups joined 07>] [cc RELATIVE][57 SHORTCUT] — every clause
            optional, the FROM list included (round-40 e01/e09/e10);
            r36-D1a: <name> may be an fc <expr> fd PAREN group — the wire
            distinguishes it from the bare f7 spelling, so the parens are
            kept in emission ('DEFINE POPUP (m.lcMenuName) …').
    BAR:    73 06 fc<n>fd c3 f7<popup> [22 PROMPT][41 STYLE][1d MESSAGE]
            [17 KEY][c9 13 SKIP FOR][c2 PICTURE][5f PICTRES] in canonical
            wire order even when source spells them reversed (g4; round-40
            e02/e03/e11; r43-pictres last); r36-D1b: <popup> may equally be
            an fc paren group ('OF (m.x)'); the bar NUMBER slot may hold a
            system-menu constant (fc ec<id> fd). PICTRES is 5f fc ec <id>
            (fd stripped when last) or 5f fc <expr>.
    PAD:    73 bc f7<name> c3 ec 02 [22 PROMPT][c9 13 SKIP FOR]
            [0d 4e COLOR SCHEME][17 KEY][05 AT][40 FONT][41 STYLE]
            [1d MESSAGE][c7 MARK][be BEFORE][54 58 NEGOTIATE LEFT]
            (r43-pad). OF _MSYSMENU is the only measured menu id
            (PUSH_POP_MENU_IDS 0x02)."""
    kind: str                       # "WINDOW" | "POPUP" | "BAR"
    name: str = ""
    frm: list = field(default_factory=list)
    flags: list = field(default_factory=list)   # clause words in measured wire order
    scheme: object = None
    at: list = field(default_factory=list)      # WINDOW: AT row, col
    size: list = field(default_factory=list)    # WINDOW: SIZE height, width
    font: list = field(default_factory=list)    # WINDOW: FONT name[, size]
    title: object = None            # WINDOW: TITLE expression
    obj_name: object = None         # WINDOW: NAME expression
    in_window: object = None        # WINDOW: IN WINDOW expression
    bar_num: str = ""               # ordinal, Paren-unwrapped ('Define Bar 1 Of …')
    of_popup: str = ""
    prompt: object = None
    skip_for: object = None
    picture: object = None
    style: object = None
    message: object = None
    key: object = None              # (key text, label expression or None)
    pictres: object = None          # PICTRES system-bar name or expression
    neighbour: object = None        # BEFORE/AFTER neighbour bar (r49-residual)
    neighbour_word: str | None = None
    mark: object = None             # PAD: MARK <expr> (r43-pad)
    before_name: str = ""           # PAD: BEFORE <pad>
    negotiate: str = ""             # PAD: NEGOTIATE LEFT


@dataclass
class ActivatePopup:
    """74 c6 f7<sym> — ACTIVATE POPUP (round-24 g5). Round-33 adds the one
    measured clause tail: `05 <row-group> 07 <col-group>` = AT <row>, <col>
    (mhxpcontrol.vcx::edit s1 'ACTIVATE POPUP MHGLMENUS AT MROW(),MCOL()'
    <-> 74c6f7000005fc43c7fd07fc43c5fd); every other clause byte stays
    Unsupported. r36-D1c: the plain frame also accepts an fc <expr> fd PAREN
    name ('ACTIVATE POPUP (m.lcMenuName)', systray L629) — parens preserved;
    the paren frame with any trailing clause remains Unsupported."""
    name: str
    at: object = None              # (row, col) expressions when the 05 tail rode the wire


@dataclass
class DeactivatePopup:
    """75 c6 f7<sym> — DEACTIVATE POPUP <name> (round-37 D5 paren spelling,
    round-40 e06 the bare one the corpus carries)."""
    name: str


@dataclass
class MovePopup:
    """7a c6 f7<sym> 28 fc<row>fd 07 fc<col> — MOVE POPUP <name> TO <row>, <col>
    (round-37 D5, round-40 e06). The TO byte is the shared TO_MARK and the
    coordinate pair joins on ARGJOIN, exactly like ACTIVATE POPUP's AT tail."""
    name: str
    row: object
    col: object


@dataclass
class ActivateScreen:
    """74 26 — ACTIVATE SCREEN (audit-B order-4).

    Corpus alignment: carrier 180d05f27ef676c3 (Olecontrol1) stmt[4] is exactly
    the two bytes 74 26 against stored METHODS line 'ACTIVATE SCREEN' (29 further
    carriers identical). No clause form of ACTIVATE SCREEN exists in the corpus,
    so anything after byte 0x26 stays Unsupported — the acceptance envelope
    widens only along the measured axis."""


@dataclass
class CreateCursor:
    """68 {bd|31} <name> [c0] 02 <fields> 03 — CREATE CURSOR (bd) or CREATE
    TABLE (31). Round-42 clause batch: CREATE CURSOR foo (id C(10)) is 68 bd;
    CREATE TABLE foo (id C(10)) is 68 31 — the rest of the field list is
    identical. Round-26 c1/c2 and round-28 W4 widenings cover the shared
    envelope. name is an fb/d9 literal or an fc-group; c0 is an optional
    name/list separator measured under both second-byte spellings.
    fields: [(name, typechar-upper, width|None, decimals|None, autoinc|None,
    nullable)]; width = nested '02 fc<n>fd', decimals joined by 07; size-less
    types (M, L, I) and AUTOINC fields carry NO per-field closer 03. autoinc =
    NEXTVALUE expression from the measured 'd8 d4 fc<n>fd' pair
    (VFPxWorkbookXLSX 'CREATE CURSOR c_workbooks (workbook I AUTOINC NEXTVALUE
    1, ...)' s13[0]). nullable = the column nullability clause, one slot behind
    the type — behind the per-field closer 03 when the field is sized, directly
    behind the type letter when it is not, and before the 07 join / list closer.
    d6 alone is NULL (round-29, dashboard1/dashboard3/dashboard123.scx cluster:
    'CREATE CURSOR sales1 (Chart1 n(8,2) NULL, Color i, Hide_Slice l)') and
    0a d6 is NOT NULL (r54-cursornull, 25 programs, both verbs, sized and
    unsized, every position of the list); anything else in that slot keeps
    raising field tail.
    Round-33: optional CODEPAGE = <n> clause `ba fc <numeric-literal> fd`
    measured exactly BETWEEN the cursor name (after its optional c0 separator)
    and the field list — VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx
    s5 stmts 4..42 <-> stored L178..L235 'CREATE CURSOR c_strings CODEPAGE =
    <n> (id I, workbook I, stringvalue M, string M)' x20 aligned pairs; every
    clause value appears literally on the wire as an f9 literal (620=f9036c02 …
    1256=f904e804), and the same section's stmt44 lifts WITHOUT the clause, so
    the ba-group is the ONLY delta. The group admits ONLY the plain f8/f9
    integer-literal spellings (the round-33 simulation envelope); any other
    group content stays Unsupported, and the bare ba keeps its TRY-lead
    meaning everywhere outside this slot.
    Round-75: FROM ARRAY is `15 04` after the name (after optional FREE and
    CODEPAGE) and there is no field list. The array operand is a bare symbol,
    an fc-group, or `f5 0d f7` (`m.name`). CREATE TABLE shares the tail;
    FREE + FROM ARRAY is `c0 15 04`."""
    name: str
    fields: list
    codepage: str | None = None   # rendered value of the CODEPAGE clause; None
                                  # when the statement carried none
    table: bool = False           # True when second byte is 0x31 (CREATE TABLE);
                                  # False when 0xBD (CREATE CURSOR)
    free: bool = False            # c0 after the name — r47-createtable: the
                                  # FREE keyword, absent when unspelled
    from_array: str | None = None  # FROM ARRAY operand; None when the statement
                                   # carried a field list instead


@dataclass
class CreateStmt:
    """Lead 0x13 — bare CREATE <name> = 13 fb<name> (CMD_SWEEP), or
    CREATE REPORT = 13 33 <file-group> 15 <from-group> with runtime-paren
    groups whose final fd is reader-stripped (round-26 c3/corpus stmt[22]).
    Round-28 W4 carrier-settled: 13 c4 fb<view> d2 d1 fb<conn> c2 51 fb<query>
    = CREATE SQL VIEW <view> REMOTE CONNECTION <conn> SHARE AS <query>
    (temp.scx::Header1 s0 stmts8/10/12 'CREATE SQL VIEW CustomSelect REMOTE
    CONNECTION MyMIS SHARE AS SELECT ...' — stored source abbreviates CREAT/
    CONNECT; emission spells the full keywords). Round-29 corpus census:
    pcph/checkmatinput et al. carry NO c2, and bincode1.scx::frmbincode s2[6]
    carries a lone d1 with no REMOTE marker, so both markers are optional and
    each renders only when its byte was present.
    remote/share record which marker bytes the stream carried."""
    name: str | None = None       # bare form
    report_file: object = None    # REPORT form
    report_from: object = None
    sql_view: str | None = None   # SQL VIEW form
    remote_connection: str | None = None
    as_query: str | None = None
    remote: bool = True           # d2 REMOTE marker present (pre-round-29 shape)
    share: bool = False           # c2 SHARE marker present


@dataclass
class InsertInto:
    """72 bc <target> 15 c2 — INSERT INTO (<expr>) FROM MEMVAR
    (round-26 i1; c2 is the MEMVAR selector round-17 read as MEMO under
    SCATTER); and round-28 W1 VALUES form
    72 bc <target> [02 <cols> 03] c5 02 <value> 07 .. <value> 03 —
    each value individually fc-wrapped (carriers dashboard1.scx::Container2,
    _reportlistener.vcx::xmllistener, xfrxlib.vcx::_cookie); and r54-insertsel
    72 bc <target> [02 <cols> 03] 6f <select> — a WHOLE SELECT statement
    spliced behind the target, with no INTO clause of its own."""
    target: object              # fb/d9 table-name literal, or expression node
    columns: list | None = None # bare f7 field names of the (col, ..) section
    values: list | None = None  # VALUES expressions; None => a FROM form
    from_name: str | None = None  # r47-insertforms: FROM NAME <obj> is 15 4a
    select: str | None = None   # r54-insertsel: the spliced SELECT, emitted


@dataclass
class BrowseWindow:
    """09 [11 <FIELDS>] [2c <window>] [27 fc<TITLE>fd] [ce fc<TIMEOUT>fd] —
    BROWSE WINDOW (m5); ce cross-binds round-15's WAIT TIMEOUT byte.
    Round-28 W4 measured additions (pricelistdetail Command1 s0 stmt16 et al.):
    a bare one-byte 09 is plain BROWSE, an optional leading 11 clause carries
    browse columns `f7 <field> [c9 <int width>] [c2 10 fc<picture>[fd]]`
    joined by 07 ('BROWSE WINDOWS wBrowse FIELDS 阶层:10,... TITLE .. TIMEOUT
    20' — the wire puts FIELDS before WINDOW; emission follows source order),
    and the :P picture operand arrives as c2 10 + fc-group.
    Round-31 measured additions (testrecord/attendancereadrecord
    frmattendancerecord s3/s4, attendanceset frmWeixiu s1): a column may carry
    the :H heading attribute as `bf 10 fc<heading>fd` — bf is the :H marker,
    the 10 is the same EQ byte as the :P arm's c2 10 — in EITHER order with
    the width (source spells both ':10 :H = ..' and ':h=..:10'). r49-menusweep
    measured that a field spec, unlike the statement's own clause list, stores
    the SOURCE's order: the two spellings are different frames, so each column
    carries which one it was. There is also a lead-
    position `13 fc<cond>fd` carries BROWSE .. FOR <cond> (same 13 FOR-marker
    byte as SCAN FOR / LOCATE FOR; source 'BROWSE WINDOWS wBrowse TITLE ..
    TIMEOUT 20 FOR ALLTRIM(NUMID)==''', wire puts FOR first). Unknown bf sub-
    ops stay Unsupported. Hardening: per-item attributes admit exactly the
    sequences ∅|W|P|W P (pre-round-31 reader) plus the measured W H / H W —
    each attribute once, no other order; FOR composes with WINDOW only, never
    FIELDS (no carrier shows that pair)."""
    window: str | None = None
    title: object = None
    timeout: object = None
    fields: list = field(default_factory=list)
    for_cond: object | None = None   # leading 13 fc..fd BROWSE..FOR condition
    # Every other clause, as (source word, operand) in the wire's canonical
    # order — operand None for a flag. The five attributes above are the ones
    # rounds 24/28/31 named, kept so their carriers and pins read unchanged.
    clauses: list = field(default_factory=list)


@dataclass
class Return:
    expr: object         # None for bare RETURN
    by_ref: bool = False # 'RETURN @<expr>' — the 04 marker (r50-sysapp)


@dataclass
class Dim:
    name: str
    dims: list
    # The closing byte of the declarator's dimension list records the SOURCE's
    # own spelling — 03 = '( … )', 16 = '[ … ]' — exactly as ArrayRef, the LOCAL
    # dimension tail and the ObjectChain call links already do. Default False
    # keeps the paren form for constructors that carry no closer.
    bracket: bool = False


@dataclass
class DimList:
    """Round-28: several DIMENSION declarators in one statement joined by the
    ARGJOIN byte — 'DIMENSION This.laTextures(lnLine), This.laFiles(lnLine)'
    (dashboard2.scx::frmcontrol stmt12 -> 15 f4..f6.. fc..fd 03 07 f4..f6..
    fc..fd 03). Each item is (name, dims, bracket) with single-Dim semantics —
    the spelling is PER DECLARATOR, so one statement may mix both."""
    items: list


@dataclass
class With:
    expr: object
    body: list
    as_class: str | None = None   # 'WITH x AS Class' — round-23 w3; wire text is
                                  # UPPERCASED by the compiler, source case unrecoverable
    of_library: str | None = None # '... OF <library>' — round-28 W3, corpus-forced
                                  # (foxcharts carriers: class verbatim-cased library)


@dataclass
class TextStmt:
    """TEXT [TO <target>] [flags] frame opener — lead 0x4d, round-23 FORCED
    (t1..t7). Flags emit in the compiler's canonical wire order 60(TEXTMERGE)
    -> ce(NOSHOW) -> 01(ADDITIVE) regardless of source spelling; round-37 C07/J1
    adds c3=PRETEXT, measured third in that fixed order (60 -> ce -> c3),
    carrying its numeric argument on the wire. Body lines are separate verbatim
    statements collected by the frame walker until 1f."""
    target: object | None         # None for bare TEXT; Sym or MemvarRef otherwise
    flags: list
    body: list = field(default_factory=list)


@dataclass
class TextLine:
    """One verbatim TEXT-frame body line: fb <u16 len excluding newline> <bytes>.
    Text is stored source — merge markers and case survive verbatim."""
    text: str


VERBATIM_MARK = "\x00"
"""Prefix on an emitted line whose column position is part of its payload.

r47-textblock: a TEXT frame body line compiles to `fb <u16 len> <the source
line>` — leading and trailing whitespace included — and nesting the block
inside IF does not change that payload. Enclosing blocks must therefore not
shift these lines the way they indent ordinary statements. The mark is a
character rather than a str subclass because block emitters join their body
and the walker splits it again, which drops any richer type; `lift_section`
strips the mark on the way out."""


def _indent(lines):
    """Indent one block body by a level; verbatim payload lines never move."""
    return [b if b.startswith(VERBATIM_MARK) else "    " + b for b in lines]


def _strip_verbatim_marks(lines):
    return [ln[1:] if ln.startswith(VERBATIM_MARK) else ln for ln in lines]


@dataclass
class ExprStmt:
    expr: object
    bare: bool = False   # True for lead 99 (no "=" prefix); lead 86 keeps the "="


@dataclass
class ExprList:
    """Measured comma-list body of one lead-86 statement: `fc <expr>` units joined
    by fd 07 (FD+ARGJOIN), N>=2, statement ends after the last unit ('=.DrawContour(
    EVL(a,b),c), .F.', oracle probe r38-p16 v1/v3/v4: control ends at the f6 method
    bind, '.T.' rides fc61; carriers 3f133997f6b20709:28 / 78429a71ad111792:28)."""
    exprs: list


@dataclass
class Verbatim:
    """A verbatim source line (macro 01 / compiler-rejected b4), byte-preserved.

    jump_rel set means the MEASURED framed block opener (docs/VERBATIM.md):
    <u16> <marker> <line> f9 05 <u16> — the line OPENS an IF block and the trailer
    anchors like a compiled 25-opener, so the walker pairs it to the matching
    depth-0 ELSE or bare 1e ENDIF exactly as it does for If. The framed envelope
    is measured for lead 01 (n=35) and corpus-carried for compiler-rejected b4
    lines (round-30: mainmenur.scx::grdmain stmt[107], ELSE-anchored).

    r49-residual: the block a macro line opens is not always an IF. A macro
    SCAN compiles to the same framed verbatim opener and closes on a compiled
    ENDSCAN, so the closer the walk found rides on the node."""
    text: str
    jump_rel: int | None = None
    body: list = field(default_factory=list)
    else_body: list = field(default_factory=list)
    else_target: int = -1
    closer: str = "ENDIF"


ENDWITH_SENTINEL = ("ENDWITH",)

# r49-residual: the block sentinels a framed VERBATIM opener may close on, and
# the word each one spells. ELSE is a continuation rather than a closer and is
# handled by the ELSE arm, which is why it maps to ENDIF's word.
_VERBATIM_BLOCK_CLOSERS = {
    S.ELSE_LEAD: "ENDIF",
    S.ENDIF_LEAD: "ENDIF",
    S.ENDSCAN_LEAD: "ENDSCAN",
    S.ENDCASE_LEAD: "ENDCASE",
    S.ENDFOR_LEAD: "ENDFOR",
    S.ENDEACH_LEAD: "ENDFOR",
    S.ENDWITH: "ENDWITH",
}


_SUBSCRIPT_STARTERS = frozenset({S.INT8, S.INT16, S.INT32,
    S.SYM, S.MEMBER, S.NAME, S.WITHREF, S.FLOAT, S.TRUE, S.FALSE})
# DECLARE-DLL type tokens under lead 0x7c — every mapping pinned by a carrier's own
# stored METHODS source (provenance comments on the constants in schemas.py).
_DECLARE_TYPES = {
    S.DECLARE_TYPE_INTEGER: "INTEGER",
    S.DECLARE_TYPE_SINGLE: "SINGLE",
    S.DECLARE_TYPE_LONG: "LONG",
    S.DECLARE_TYPE_STRING: "STRING",
    S.DECLARE_TYPE_SHORT: "SHORT",
    S.DECLARE_TYPE_OBJECT: "OBJECT",
}

_BINOP = {S.ADD: "+", S.SUB: "-", S.MUL: "*", S.DIV: "/", S.POW: "^",
          S.EQ: "=", S.EQEQ: "==", S.NE: "!=", S.LT: "<", S.GT: ">",
          S.LE: "<=", S.GE: ">=", S.CONTAINS: "$"}

# source precedence, low = loosest (VFP: OR < AND < NOT < cmp < +- < */% < ^)
_PREC = {"OR": 1, "AND": 2, "NOT": 3,
         "=": 4, "==": 4, "!=": 4, "<": 4, ">": 4, "<=": 4, ">=": 4, "$": 4,
         "LIKE": 4, "IN": 4,
         "+": 5, "-": 5, "*": 6, "/": 6, "%": 6, "^": 7}

_POSTFIX = {S.PAREN, S.NEG, S.NOT}

# A 43-group ends at a namespace-specific callee. Round-14 oracle probes prove
# that arguments always precede the closer in bare, ea, and x1a namespaces.
# Only bare ids with a unique measured name and usable arity join the generated
# set; the smaller curated set retains its established unconstrained behavior.
_ENABLE_EXTRA_BARE = frozenset(
    S.DECODER_ENABLED_BARE - S.CORPUS_ALIGNED_BARE_CLOSERS)
_GROUP_CLOSERS = frozenset(
    {S.NAME, S.ESCAPE, S.X1A_ESCAPE, S.BARE_BYREF, S.MOD_APPLY,
     S.SQL_LIKE_MARK}
    | S.CORPUS_ALIGNED_BARE_CLOSERS
    | set(_ENABLE_EXTRA_BARE)
    | set(S.MEASURED_LOCAL_GROUP_CLOSERS)
)
_IF_COND_STOP = frozenset({S.FD})   # the IF condition ends at its fd (FINDINGS §IF)


# ---------- symbol first-use, section-scoped (r49-clauseorder) ----------
# A section's symbol table numbers identifiers by first appearance in the
# SOURCE, so every name a statement introduces sits ABOVE every index the
# section used before it. Commands that store their clauses in a canonical
# order throw the source's order away in the frame and keep it here: of two
# clauses, the one whose LOWEST NEW index is lower was written first. The
# lowest index alone does not answer it — a clause may read a name the section
# already used, whose index is below anything this statement introduces.
#
# `_SYM_TABLE_HI` is the highest index EARLIER statements resolved, and None
# outside a section walk, where nothing about first use is known and every
# clause order falls back to canonical. Module state for the same reason
# `_MENU_SHIFTED_BLOCK` is: the readers sit deep under the walk and statement
# decoding is single-threaded and never nested.
_SYM_TABLE_HI = None
_SYM_STMT_HI = -1
_SYM_STMT_LO = None    # lowest index the statement in progress INTRODUCES
_SYM_TAPS = []


class _sym_tap:
    """Collect the symbol indexes one clause's decode resolves.

    Re-entrant on purpose: a clause the reader decodes in more than one attempt
    (the SQL WHERE tries its LIKE matrix before the generic expression reader)
    accumulates into the same list, and the lowest new index is the same either
    way.
    """

    def __init__(self):
        self.idx = []

    def __enter__(self):
        _SYM_TAPS.append(self.idx)
        return self

    def __exit__(self, *exc):
        _SYM_TAPS.pop()
        return False

    def first_new(self):
        """Lowest index this clause introduces, or None if it introduces none."""
        if _SYM_TABLE_HI is None:
            return None
        new = [i for i in self.idx if i > _SYM_TABLE_HI]
        return min(new) if new else None


def _agg_clause_end(buf, k, end, verb, word) -> int:
    """Index past a SUM/COUNT clause group's closer.

    The group normally ends `fd`. A clause that is the LAST thing in the
    statement carries none — its RPN runs to the stream end, the way LOCATE's
    does (r59-countscope `ct_no_to`, `COUNT ALL FOR c` with no TO section). Any
    other stopping point is a shape this arm has not measured.
    """
    if k < end and buf[k] == S.FD:
        return k + 1
    if k == end:
        return k
    raise Unsupported("%s %s clause unresolved" % (verb, word))


def _written_first(b, a) -> bool:
    """Was clause B written before clause A?

    Only when the table can tell: both clauses must introduce a name here.
    Two clauses that introduce none produce the same table in either source
    order — a tie, not a recovery.
    """
    ib = b.first_new() if hasattr(b, "first_new") else b
    ia = a.first_new() if hasattr(a, "first_new") else a
    return ia is not None and ib is not None and ib < ia


def _replace_all_first(syms, all_scope, in_spec, for_cond) -> bool:
    """Did the source write REPLACE's ALL in front of its field list?

    ALL is a symbol-table entry with no operand of its own, so its index is
    where the word stood in the source. Measured for the plain shape only: an
    IN clause or a trailing FOR gives the word a third possible position and
    neither order is measured there, so those keep the canonical emission.
    With neither clause present the statement's own symbols ARE the field
    list's, which is why the statement-wide low-water answers it exactly.
    """
    if not all_scope or in_spec is not None or for_cond is not None:
        return False
    i = _table_new_index(syms, "ALL")
    return i is not None and _SYM_STMT_LO is not None and i < _SYM_STMT_LO


def _table_new_index(syms, name):
    """Index of a name the frame does not spell as an operand at all.

    REPLACE's scope word ALL and an INTO CURSOR name are symbol-table entries
    with no operand of their own, which is what makes those two clause orders
    recoverable. None when the name is absent, ambiguous, or older than this
    statement.
    """
    if _SYM_TABLE_HI is None or not isinstance(name, str) or not name:
        return None
    want = name.upper()
    hits = [i for i, s in enumerate(syms) if s == want]
    if len(hits) != 1 or hits[0] <= _SYM_TABLE_HI:
        return None
    return hits[0]


def _sym(syms, idx):
    if idx >= len(syms):
        raise Unsupported(f"symbol index {idx} beyond table ({len(syms)})")
    global _SYM_STMT_HI, _SYM_STMT_LO
    if idx > _SYM_STMT_HI:
        _SYM_STMT_HI = idx
    if _SYM_TABLE_HI is not None and idx > _SYM_TABLE_HI \
            and (_SYM_STMT_LO is None or idx < _SYM_STMT_LO):
        _SYM_STMT_LO = idx
    for tap in _SYM_TAPS:
        tap.append(idx)
    return syms[idx]


def _fmt_float(v):
    return repr(float(v))


# ---------- typed-constant payloads (round-27: oracle-forced + corpus-aligned) ----------
# All three 8-byte families carry a LITTLE-ENDIAN IEEE-754 double whose value is the
# Julian Day Number of the date, plus seconds-of-day/86400 for datetimes. Oracle
# points: {^2024-01-31} -> ee 000000805ac54241 (JDN 2460341 exactly, b9) and
# {^2024-01-31 12:34:56} -> e6 6bed1ac35ac54241 (2460341 + 45296/86400, b12).
# Corpus alignment with vote counts (stored sources of the same pairs):
#   ee 000000804ebb4241 <-> {^2009.12.31} x2, ee 0000008098ba4241 <-> {^2009.01.01} x4,
#   ee/e6 00000080d66c4241 <-> {^1900.01.01} x3 / {^1900.01.01,00:00:00} x5,
#   ee all-zero <-> DTOT({}) x2 and the spaced empty spelling x1.
_JDN_ORDINAL_OFFSET = 1721425   # JDN 2451545 == proleptic-Gregorian ordinal 730120


def _ymd_of_jdn(jdn):
    ordinal = jdn - _JDN_ORDINAL_OFFSET
    if ordinal < 1 or ordinal > _date.max.toordinal():
        raise Unsupported(f"typed constant JDN {jdn} outside the calendar range")
    d = _date.fromordinal(ordinal)
    return (d.year, d.month, d.day)


def _dec_date_payload(raw):
    v = _struct.unpack("<d", raw)[0]
    if v == 0.0:
        # {}, {:} and {//} compile byte-identically (b8/b10/b11); canonical {}.
        return DateLit(None)
    if not _math.isfinite(v) or v <= 0.0:
        raise Unsupported("date constant payload not a positive finite JDN double")
    jdn = round(v)
    if abs(v - jdn) > 1e-6:
        raise Unsupported("date constant carries a time fraction (datetime is e6)")
    return DateLit(_ymd_of_jdn(jdn))


def _dec_datetime_payload(raw):
    v = _struct.unpack("<d", raw)[0]
    if not _math.isfinite(v) or v <= 0.0:
        # The all-zero payload under e6 is UNMEASURED (empty forms ride ee).
        raise Unsupported("datetime constant payload not a positive finite JDN double")
    total = round(v * 86400)
    if total <= 0:
        raise Unsupported("datetime constant rounds below one second")
    days, secs = divmod(total, 86400)
    # The wire double must BE the seconds-quantised value, not merely near it:
    # midnight keeps fraction 0 on the wire (corpus replicas) and b12 re-encodes
    # bit-exactly, so anything else is an unmeasured shape.
    if _struct.pack("<d", days + secs / 86400) != raw:
        raise Unsupported("datetime constant is not second-quantised")
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return DateTimeLit(_ymd_of_jdn(days), (h, m, s))


# ---------- expression decoding -----------------------------------------------------------------
# Round-33 shared expression stacks ("arena"): the VFP compiler emits ONE linear
# RPN stream per expression, so an operator/postfix can reach a fresh 43-group
# segment while its operands sit on an ENCLOSING live group/window stack (r33
# matrix C1: 'mNote=ClosePsd((.txtName.VALUE))', config.scx::cdSave s16). Every
# operand stack registers itself in _ARENA (innermost last) for the duration of
# its own decode; _pop consults it only inside dec_statement's stock-failure
# retry pass (_EXPR_RETRY_ACTIVE), so any statement that lifts stock is untouched.
_EXPR_RETRY_ACTIVE = False   # True only inside dec_statement's retry pass
_STMT_MIDWINDOW_FIRED = False  # the mmid mid-window f6 close fired in THIS
                               # statement's decode (round-30/31 suppressed
                               # reading — deferred-correction territory)
# r54-selnointo: a 43 packet that ended because the decode WINDOW ran out, not
# on a closer of its own. Reset per statement in dec_statement and read by
# _clause_group_close, which otherwise cannot tell a reader-stripped closer at
# statement end from a truncated group.
_GROUP_EOW_CLOSE = False
# r54-subquery: a SELECT body being read inside an `e8` block. The block's own
# LENGTH ends the body, so its last clause group closes on its own fd — the
# opposite of a statement, where the closer is stripped at the end.
_SQL_SUBQUERY_BODY = False
_ARENA = []                  # live operand stacks, innermost last
_GROUP_DEPTH = 0              # live 43-group frames (the packet-nesting test
                              # of the W15-close residual gates on this)
# r49-residual: where an expression segment sits relative to a doubled `43 43`
# opener, as two independent bits. Threaded as a parameter, never as module
# state, so no statement can inherit another's packet position. Both bits ride
# together on the first segment of an inner packet — `STRTOFILE(STRCONV(<chain
# with a link argument>, 13), "f")` nests three openers, and the middle group is
# an inner packet whose own first segment opens the next one.
_PACKET_NONE = 0
_PACKET_INSIDE_FIRST = 1      # inside the group a doubled opener produced
_PACKET_OPENS_FIRST = 2       # this is a group's FIRST segment: a 43 doubles
_ARG_BYREF_CLOSE = False     # r38 M3/a0004: an 18 flag rode immediately before
                             # the f6 that closes the enclosing nested group
                             # ('@arr(sub)' — subscript already pushed). Set by
                             # the expression reader, read-and-cleared by the
                             # group loop right after that segment returns;
                             # dec_statement clears it defensively at entry
                             # and again where the retry pass begins (r38
                             # follow-up), so a pass-1 death after consuming
                             # '18 f6' cannot stain the retry decode.


def _reset_arg_byref_close():
    global _ARG_BYREF_CLOSE
    _ARG_BYREF_CLOSE = False


_INT16_LITERAL_MAX = 32767
"""Largest value the f9 literal opcode holds; above it the compiler uses e9
(r48-intlit: 255 -> f8, 256 and 32767 -> f9, 32768 -> e9)."""

_LINENO_ESCAPE = 0x0A
"""Digit byte of a folded LINENO() call (FORMAT.md §6; r42-tiera3; r65-hexlit).
A stored e9 whose value fits f8/f9 cannot be a hex or decimal token: r65-hexlit
compiled 0x0000002a to f8 0a 2a and LINENO() to e9 0a <line>."""


_SQL_AGG_SCOPE = False
"""True while a SELECT projection column body is being decoded, which is the
only place `ea <agg-id>` closes a group as a SQL aggregate (r48-sqlproj). The
ids collide with ordinary ea builtins everywhere else."""


@_contextlib.contextmanager
def _sql_agg_scope():
    global _SQL_AGG_SCOPE
    was = _SQL_AGG_SCOPE
    _SQL_AGG_SCOPE = True
    try:
        yield
    finally:
        _SQL_AGG_SCOPE = was


def _hex_literal_width(d: int) -> int:
    """Width byte a hex literal of `d` digits rides: ceil(6d/5).

    r48-intlit measured d = 2..14: 2->3, 3->4, 4->5, 5->6, 6->8, 7->9, 8->10,
    9->11, 10->12, 11->14, 12->15, 13->16, 14->17. The map skips 7, 13 and 19,
    so those widths have no hex spelling at all."""
    return -(-6 * d // 5)


def _int32_spelling(digits, v):
    """Source spelling of an `e9 <digits> <u32>` literal, or None.

    Round-48 `r48-intlit` compiled the same three values at every spelling and
    read both bytes off the wire:

    * a HEX token of d digits rides `ceil(6d/5)` — 2 digits ride 3, 4 ride 5,
      5 ride 6, 6 ride 8, 10 ride 12, 11 ride 14, 14 ride 17. The map skips
      7, 13 and 19, so those widths have NO hex spelling at all.
    * a DECIMAL token rides its own length, leading zeros included
      (`0065280` rides 7).
    * the opcode is the narrowest that holds the value, so a stored `e9` whose
      value fits in 16 bits is not a literal: it is the folded zero-argument
      builtin family (FORMAT.md §6). r65-hexlit compiled every boundary hex
      token of a 16-bit value to f8 or f9, never e9; `0x0000002a` is
      `f8 0a 2a`. Digit byte 0x0a on a 16-bit payload is LINENO's escape.

    That corrects, and subsumes, the two readings this arm carried before. The
    round-37 P1/C01-C02 measurement — an UNPADDED hex token rides
    `hexdigit_count + 1`, `0xFFFF` -> 05, `0x10000` -> 06 — is the d <= 5 case
    of the same formula and is unchanged. The zero-padded reading, which the
    schemas `HEX_LITERAL_PREFIX_CHARS` note derived from corpus alignment on
    `0x00080000` -> `e9 0a`, is right only for widths 8..12, where the formula
    also picks `d = width - 2` and reproduces it exactly; everywhere else it
    put a zero-padded DECIMAL's width on a hex spelling, which is what stored
    `e9 07` (a written `0065280`) came back from as `e9 06`.

    A 16-bit payload has no literal spelling on e9 (r65-hexlit). Returning
    the pre-round-48 padded-hex reading for those frames is what compiled
    back to f8/f9 and is the e9->f8 cluster.
    """
    hex_digits = "%x" % v
    if v <= _INT16_LITERAL_MAX:
        return None
    # Both spellings are candidates only when the value NEEDS this opcode:
    # 255 and below ride f8, 32767 and below ride f9 (r48-intlit
    # boundaries). So `e9 02 <0>` is not the token `0x0` or `00` — it is
    # the folded-builtin family.
    for d in range(len(hex_digits), 17):
        w = _hex_literal_width(d)
        if w == digits:
            return "0x" + hex_digits.rjust(d, "0")
        if w > digits:
            break
    if digits > len(str(v)):
        return "%0*d" % (digits, v)
    pad = digits - S.HEX_LITERAL_PREFIX_CHARS - len(hex_digits)
    if pad >= 0:
        return "0x" + "0" * pad + hex_digits
    if pad == -1 and v > 0:
        return "0x" + hex_digits
    return None


def _arena_fallback(stack):
    """Nearest enclosing live operand stack holding a value, or None."""
    for fb in reversed(_ARENA):
        if fb is not stack and fb:
            return fb
    return None


def _dec_expr(buf, i, end, syms, stop_at_one=False, stop_bytes=frozenset(),
              member_callee_tail=False, packet=_PACKET_NONE):
    stack = []
    _ARENA.append(stack)
    try:
        return _dec_expr_run(buf, i, end, syms, stack,
                             stop_at_one=stop_at_one, stop_bytes=stop_bytes,
                             member_callee_tail=member_callee_tail,
                             packet=packet)
    finally:
        _ARENA.pop()


def _dec_expr_run(buf, i, end, syms, stack, stop_at_one=False,
                  stop_bytes=frozenset(), member_callee_tail=False,
                  packet=_PACKET_NONE):
    seg_start = i
    while i < end:
        if stop_at_one and len(stack) == 1 and not (i < end and buf[i] in _POSTFIX):
            break
        if buf[i] in stop_bytes:
            break
        op = buf[i]
        if op == S.INT8:
            # r38 M4: keep (op, width, value) verbatim — the width byte is
            # source-spelling provenance, restored at emission.
            stack.append(Num(str(buf[i + 2]), op=op, width=buf[i + 1]))
            i += 3
        elif op == S.INT16:
            _vv = _struct.unpack_from("<h", buf, i + 2)[0]
            stack.append(Num(str(_vv), op=op, width=buf[i + 1]))
            i += 4
        elif op == S.INT32:
            if i + 6 > end:
                raise Unsupported("int32 literal truncated")
            digits = buf[i + 1]
            v = _struct.unpack_from("<i", buf, i + 2)[0]
            if len(str(v)) != digits and v >= 0:
                spelling = _int32_spelling(digits, v)
                if spelling is not None:
                    stack.append(Num(spelling)); i += 6
                    continue
            if len(str(v)) != digits:
                # r65-hexlit: digit byte 0x0a on a payload that fits f8/f9 is
                # LINENO(). Hex of the same value compiles to f8/f9 (0x0000002a
                # -> f8 0a 2a); LINENO() compiles to e9 0a <line>. Other
                # escapes stay the folded-builtin refusal.
                if (digits == _LINENO_ESCAPE
                        and 0 <= v <= _INT16_LITERAL_MAX):
                    stack.append(Num("LINENO()", lineno=v)); i += 6
                    continue
                raise Unsupported(
                    f"zero-arg builtin call (escape 0x{digits:02x}, payload {v}) "
                    f"— funcnum table pending")
            stack.append(Num(str(v))); i += 6
        elif op == S.FLOAT:
            v = _struct.unpack_from("<d", buf, i + 3)[0]
            # r41-C: the fa header's (width, decimals) is source-spelling
            # provenance. r48-foldmark corrects what the 0xCC marker beside it
            # means: NOT "folded" but "not a bare token" — a PARENTHESISED
            # literal carries it exactly as arithmetic does, and leaves the
            # header the bare token's own (`(0143.25)` is `fa 07 02 <143.25>
            # cc`). So the header is provenance for a marked literal too, and
            # the emitter decides whether it spells one; where it describes an
            # arithmetic result no token can spell, the round-47 cap stands and
            # the emitter falls back to the value's own rendering.
            marked = i + 11 < end and buf[i + 11] == 0xCC
            stack.append(Flt(_fmt_float(v), buf[i + 1], buf[i + 2],
                             marked=marked)); i += 11
        elif op == S.STR:
            n = S.u16(buf, i + 1)
            stack.append(Str(_payload_text(buf[i + 3:i + 3 + n]))); i += 3 + n
        elif op == S.STR2:
            # double-quoted literal (FINDINGS: quote style is canonical, 12/12 aligned)
            n = S.u16(buf, i + 1)
            stack.append(Str(_payload_text(buf[i + 3:i + 3 + n]), dq=True)); i += 3 + n
        elif op == S.TRUE:
            stack.append(Bool(True)); i += 1
        elif op == S.FALSE:
            stack.append(Bool(False)); i += 1
        elif op == S.NULL:
            stack.append(Null()); i += 1
        elif op == S.BINARY:
            # ff <type=01> <u16 len LE> <payload> — round-27 forced rule: the length
            # field is TWO bytes (the one-byte prediction was REFUTED by b1's 02 00);
            # odd nibble counts pad high-nibble-first into whole bytes (0hA -> 0a) and
            # empty 0h is accepted with a zero-length payload. Decode-side bounds are
            # the strict gate; no length cap, since the payload is opaque on the wire
            # and literals the compiler rejects (>~300 bytes measured) cannot occur.
            if i + 4 > end:
                raise Unsupported("binary literal header truncated")
            if buf[i + 1] == 0x02 and member_callee_tail \
                    and buf[i + 2] == S.X1A_ESCAPE and buf[i + 3] == 0x0E:
                # Round-37 package P2 (probes/oracle_harvest/round37_findings.json
                # C03/C04, probes B1-B7): inside an ICASE group the two bytes
                # 'ff 02' IMMEDIATELY before its x1a closer '1a 0e' are the
                # compiler's synthesized ReturnDefault slot. Measured grammar:
                # an EVEN-length parameter list emits exactly ONE such pair
                # there (B1/B3/B4; a .T.-final condition changes nothing), while
                # an odd list pushes its default explicitly ('f8 02 63' = 99)
                # and carries NO ff02 (B2). The slot consumes NO stack operand —
                # the call's argument list is exactly what this segment already
                # accumulated — and plain re-emitted 'ICASE(...)' source makes
                # VFP re-synthesize the pair on recompile, so emission needs no
                # new spelling. Deliberately NOT generic: only this exact
                # four-byte window inside a 43-group operand segment engages
                # (member_callee_tail is true only there); every other position,
                # follower or sibling keeps the stock rejection below — the ff01
                # binary-literal anchor rides the same opcode byte (B6) and the
                # x1a-sibling EVL control stays clean (B5, closer 1a 0c).
                # Releases exactly the ten P2-predeclared keys; canonical
                # proof: fresh oracle lift->source->compile equality for B7.
                i += 2
                continue
            if buf[i + 1] != 0x01:
                raise Unsupported(
                    f"binary literal type byte 0x{buf[i + 1]:02x} unmeasured")
            n = S.u16(buf, i + 2)
            if i + 4 + n > end:
                raise Unsupported(f"binary literal payload truncated ({n} declared)")
            stack.append(BinHexLit(bytes(buf[i + 4:i + 4 + n]))); i += 4 + n
        elif op == S.DATE:
            if i + 9 > end:
                raise Unsupported("date literal truncated")
            stack.append(_dec_date_payload(buf[i + 1:i + 9])); i += 9
        elif op == S.DATETIME:
            if i + 9 > end:
                raise Unsupported("datetime literal truncated")
            stack.append(_dec_datetime_payload(buf[i + 1:i + 9])); i += 9
        elif op == S.CURRENCY:
            # de <pfx> <type> <i64LE scaled x10^4>. The prefix byte is OPEN (08 rode
            # $100.50 with two decimals, 06 rode $0 with none — two data points), so
            # only the two complete measured triples bind; anything else fails loudly.
            if i + 11 > end:
                raise Unsupported("currency literal truncated")
            pfx = buf[i + 1]
            tag = buf[i + 2]
            val = _struct.unpack_from("<q", buf, i + 3)[0]
            if tag != 0x04:
                raise Unsupported(f"currency literal type byte 0x{tag:02x} unmeasured")
            if (pfx, val) == (0x08, 1005000):
                stack.append(CurrencyLit("$100.50"))
            elif (pfx, val) == (0x06, 0):
                stack.append(CurrencyLit("$0"))
            else:
                raise Unsupported(
                    f"currency literal shape unmeasured "
                    f"(prefix 0x{pfx:02x}, scaled {val})")
            i += 11
        elif op == S.SYM:
            nm = _sym(syms, S.u16(buf, i + 1))
            if stack and isinstance(stack[-1], WorkAreaRef):
                wa = stack.pop()
                stack.append(QualField(wa.letter, nm))
            else:
                stack.append(Sym(nm))
            i += 3
        elif op == S.MEMBER:
            # expression context: a path must terminate in f7 here — a trailing f6
            # outside a group is the historical "bare reference" rejection
            if _chain_opener(buf, i, end) and not member_callee_tail:
                # population lane PATHS: an f4-run followed by the measured e5
                # call opener is an object/method VALUE chain ('…Cells(3,1)…',
                # buyfine.scx::frmShipmentinfo); outside groups this never
                # collides with the historical MemberRef fallback or with the
                # group-context array-receiver pop
                node, i = _dec_object_chain(buf, i, end, syms)
                stack.append(node)
                continue
            if member_callee_tail and stack:
                # round-27 args-before-receiver (w1 'This.Pages.Controls(m.lii).
                # Name', w2 WITH chain): values already on the segment stack are
                # this call's arguments and the f4-run is its RECEIVER when the
                # run terminates at e5. One preceding value is the measured
                # minimum and is REQUIRED by carriers like FIELDS(1).COLOR;
                # array-element receivers keep the e5 arm below and
                # zero-argument links keep _dec_object_chain.
                jk = i
                while jk + 3 <= end and buf[jk] == S.MEMBER:
                    jk += 3
                # CONSERVATIVE GATE (population-mandated): on the STOCK decode
                # pass the pivot engages only on the full oracle shape — e5
                # immediately followed by its terminal property read (w1
                # '.NAME', w2 '.CNTPREVIEWER').
                # A bare-e5 tail is carried by corpus methods whose lift flows
                # through the object-chain fallback below (xfrxlib.vcx::
                # cntxfrxmultipage clearlink stmt3 / repaint stmt8;
                # form1.scx::Form1 Init stmt8); their emitted text is pinned
                # byte-exact in tests/test_round27_sysobj.py and changing it
                # is a separate measured correction, never a silent one.
                # r35-reval-D narrowed (d_narrow): the corpus also carries the
                # prop-less pivot '<f4-run> e5 <method-sym> f6 <name-sym>' —
                # args-before-receiver mid-chain call whose completed value
                # feeds an ENCLOSING f6 callee, the same measured continuation
                # two _dec_args_first_call already accepts ('WITH
                # THISFORM.Controls[m.i].pages[m.j]', samples.vcx::resizable
                # adjustcontrols and its _controls.vcx::_resizable twin). The
                # added f6 continuation engages ONLY inside dec_statement's
                # retry pass (_EXPR_RETRY_ACTIVE): the stock decode pass stays
                # byte-for-byte identical to the committed grammar, so no
                # already-lifted section can change text. All five measured
                # gain carriers were stock-blocked ("array-element method
                # arguments unmeasured") and therefore always reach the retry
                # lane; both measured broad-D drift sites (c79070eeff459e07:19
                # stmt#7 'CLEARLINKS(LNI, THIS.PAGES.CONTROLS())' and
                # fd022df9d14dad4f:0 stmt#8 'CLICK("hdSubmit", OIE.DOCUMENT.
                # GETELEMENTBYID())') lift on the STOCK pass through the
                # fallback above, so this gate pins their text exactly. Both
                # corrections are REAL (they match the stored METHODS source)
                # but belong to the text-correction authority, never to an
                # acceptance envelope. Guards unchanged: bounds jk>i /
                # jk+6<=end reject a truncated e5+f6 tail before any stack
                # mutation; a truncated method token dies 'mid-chain method
                # token truncated'; an operand index beyond the table dies
                # 'symbol index N beyond table'; the enclosing group keeps its
                # empty-stack / pending-marker guards; _GroupDone can never
                # escape a statement (a leak would surface as <LEAK>; the
                # population shows none).
                # r40 group43 adds two further RETRY-ONLY followers, both
                # measured against the stored sources of their carriers:
                # f4 (the call's value continues onto a member run —
                # 'loShell.NameSpace(tcTempPath).Items.Count') and e5 (the
                # value is the receiver of the next chain link —
                # 'oMyVar.shapes(c1).GroupItems(T1).HasTextFrame'). Same
                # stability contract as the f6 follower above: the stock pass
                # is byte-for-byte unchanged, so no lifted section can re-text.
                # r49-residual adds ONE stock-pass topology to that gate, and
                # only one: a group the compiler opened as `43 43` — an inner
                # argument packet at the very FIRST position of an outer call's
                # packet. `ALLTRIM(o.p.Shapes(m.y).q.r.s)` is `43 43 00 <m.y>
                # <chain> 9b` while the genuinely two-argument `ALLTRIM(m.y,
                # o.p.Shapes().q.r.s)` is `43 <m.y> 43 <chain> 9b`, so the
                # doubled opener IS the wire's own mark that the operands
                # belong to the chain's link and not to the outer callee.
                # Without it the stock pass reads both as the two-argument
                # spelling and recompiles the first one into the second.
                if jk > i and jk + 6 <= end and buf[jk] == S.ARRAY_ELEM_CALL \
                        and (buf[jk + 3] == S.SYM
                             or (buf[jk + 3] in (S.NAME, S.MEMBER,
                                                 S.ARRAY_ELEM_CALL)
                                 and (_EXPR_RETRY_ACTIVE
                                      or packet & _PACKET_INSIDE_FIRST))):
                    recv = []
                    kt = i
                    while kt < jk:
                        recv.append(_sym(syms, S.u16(buf, kt + 1)))
                        kt += 3
                    _dec_args_first_call(buf, jk, end, syms, stack, recv)
            try:
                node, i = _dec_path(buf, i, end, syms,
                                    allow_callee_tail=member_callee_tail)
            except Unsupported as e:
                # an f4-run that terminates at an OBJECT which is then called
                # ('…Document.getElementById("r")', oaasstant.scx::Label10 IF
                # condition) is a measured VALUE chain — engage only on the
                # specific gap, never on the group callee tail
                if "member path without terminal property" not in str(e):
                    raise
                node, i = _dec_object_chain(buf, i, end, syms)
            stack.append(node)
        elif op == S.WITHREF:
            hops = []
            hj = i + 1
            if member_callee_tail:
                # Round-40 lane C: the round-28 W3 pivot below also carries a
                # HOPPED receiver — e2 <f4 hop>+ e5 <M> — where the hops name
                # members of the WITH object rather than the WITH object
                # itself. Corpus-forced on foxchartsbeta.vcx::foxcharts toxls
                # stmt#33 '54 f50df70700 10 fc 43 f80101 e2 f41500 e51700
                # f71800' <-> stored 'm.lnHeight=.activesheet.PICTURES(1).
                # HEIGHT' and toword stmt#75 '99 fc 4343 00 f50df70d00 00
                # f50df70a00 e2 f43100 e53400 f63000' <-> stored
                # '.ActiveDocument.Range(m.lnStart,m.lnEnd).Paste()' (both
                # artifact copies of the record, 4 carriers). The hop run is
                # read with the SAME loop _dec_withref uses, so an out-of-range
                # hop index still dies 'symbol index N beyond table' at the
                # same byte; when no e5 closes the run every byte falls
                # through to the historical _dec_withref rejection below.
                while hj + 3 <= end and buf[hj] == S.MEMBER:
                    hops.append(_sym(syms, S.u16(buf, hj + 1)))
                    hj += 3
            if member_callee_tail and hj + 3 <= end \
                    and buf[hj] == S.ARRAY_ELEM_CALL:
                # round-28 W3: WITH-scoped indexed-member VALUE read, mid-group
                # (segment) position — <args> e2 [f4 hop]* e5 <M> [f7 <prop>].
                # Same args-before convention as the round-27 system-object
                # pivot: every value on this segment's stack is the call's
                # argument list, the WITH object is the implicit receiver, and
                # the completed value closes its group implicitly (_GroupDone,
                # so an outer f6 may still consume it as a receiver). Corpus
                # alignment foxcharts::foxcharts s82[43]:
                # 'm.lcValue1 = .Fields(1).FieldValue'. Prior group state at
                # the close is rejected by the enclosing _dec_group handler.
                name = _sym(syms, S.u16(buf, hj + 1))
                args = list(stack)
                stack.clear()
                j2 = hj + 3
                prop = None
                if j2 + 3 <= end and buf[j2] == S.SYM:
                    prop = _sym(syms, S.u16(buf, j2 + 1))
                    j2 += 3
                elif _EXPR_RETRY_ACTIVE and j2 + 3 <= end \
                        and buf[j2] == S.MEMBER:
                    # r40 group43: the WITH-scoped spelling of the same
                    # multi-hop tail — `43 f8<1> e2 e5<WorkBooks> f4<Sheets>
                    # f7<Count>` <-> 'lnSheetCount=.WorkBooks(1).Sheets.Count'
                    # inside 'With oExcel' (translate.scx / translate_en.scx
                    # ::frmDaily forexcel, stored L53 / L35). Retry-pass only,
                    # and it DECLINES back to the historical prop-less close
                    # on anything the chain reader does not measure, so no
                    # blocked message can shift off a non-carrier.
                    try:
                        node, k2 = _dec_chain_continue(
                            buf, j2, end, syms,
                            ObjectChain([""] + hops, [(name, list(args))], []))
                    except (Unsupported, _ChainOpen):
                        pass
                    else:
                        raise _GroupDone(node, k2)
                raise _GroupDone(MidCall([""] + hops, name, args, prop), j2)
            # Chained e2 f4.. f6 forms only parse when the trailing f6 may stay
            # unconsumed for the enclosing group to resolve as the callee.
            node, i = _dec_withref(buf, i, end, syms,
                                   allow_callee_tail=member_callee_tail)
            stack.append(node)
        elif op == S.NAME:
            raise Unsupported("bare array/function reference outside its wrapper")
        elif op == S.PAREN:
            stack.append(Paren(_pop(stack))); i += 1
        elif op == S.NEG:
            stack.append(Neg(_pop(stack))); i += 1
        elif op == S.NOT:
            stack.append(Not(_pop(stack))); i += 1
        elif op == S.SQL_SUBQUERY:
            # r54-subquery: `e8 <u16 n> <n bytes>` is one operand — a SELECT
            # body with no lead of its own, carrying its own byte length.
            node, i = _dec_sql_subquery(buf, i, end, syms)
            stack.append(node)
        elif op == S.ESCAPE and i + 1 < end \
                and (buf[i + 1] in S.SQL_SUBQUERY_OPS
                     or buf[i + 1] in S.SQL_SUBQUERY_QUANT) \
                and any(isinstance(x, SqlSubquery) for x in stack):
            # r54-subquery: the `ea` pair that APPLIES a subquery. IN takes the
            # operand in front of it; EXISTS takes none. Bound to a stack that
            # actually holds a subquery, so the ea builtin namespace elsewhere
            # is untouched.
            # r63-sqlop: ANY (`f6`) and ALL (`f7`) wrap the subquery; a
            # comparison byte follows (`ea f6 10` is `= ANY`).
            ident = buf[i + 1]
            if ident in S.SQL_SUBQUERY_QUANT:
                sub = _pop(stack)
                stack.append(SqlSubquery(
                    sub.text, prefix=S.SQL_SUBQUERY_QUANT[ident]))
                i += 2
            else:
                name = S.SQL_SUBQUERY_OPS[ident]
                if name == "EXISTS":
                    sub = _pop(stack)
                    stack.append(SqlSubquery(sub.text, prefix="EXISTS"))
                else:
                    r = _pop(stack)
                    l = _pop(stack)
                    stack.append(Bin(name, l, r))
                i += 2
        elif op in _BINOP:
            r = _pop(stack); l = _pop(stack)
            stack.append(Bin(_BINOP[op], l, r)); i += 1
        elif op in (S.SC_AND, S.SC_OR):
            skip = S.u16(buf, i + 1)
            right_len = skip - 1
            rs, ri = _dec_expr(buf, i + 3, i + 3 + right_len, syms)
            if len(rs) != 1:
                raise Unsupported("short-circuit right side unresolved")
            want = S.AND_APPLY if op == S.SC_AND else S.OR_APPLY
            if buf[i + 3 + right_len] != want:
                raise Unsupported("short-circuit apply opcode mismatch")
            r = _pop(stack)
            stack.append(ShortCircuit("AND" if op == S.SC_AND else "OR", r, rs[0]))
            i = i + 3 + right_len + 1
        elif op == S.ARRAY_MEMBER:
            # e0 <u16 sym>: the member NAME token of a path/WITH-scoped array
            # reference — the operand is the member's own symbol id
            # (schemas.ARRAY_MEMBER). A preceding f4/f7 run folds into one dotted
            # path; a preceding WITH-scoped node leaves the e0 member as its own
            # WithMemberPath. This branch consumes EXACTLY the 3-byte token and no
            # more: the bytes after it belong to the ENCLOSING context. Measured on
            # _reportlistener.vcx::_reportlistener adjustreportpagesinfo
            # (corpus alignment): 'IF ALEN(THIS.reportPages,2) < 2' compiles to
            # 43 f4<THIS> e0<REPORTPAGES> f8<2> cd — the literal after e0 is ALEN's
            # SECOND ARGUMENT and cd is the group's bare callee closer, so any
            # subscript-style consumption here swallows the argument list, strands
            # the enclosing expression (it then dies on the clause's fd), and
            # mis-emits passing methods (e.g. _base.vcx::_checkbox releaseobjrefs,
            # where 'ALEN(this.aObjectRefs,1)' was emitted '.AOBJECTREFS[1]'). True
            # in-expression subscripts of member arrays are measured to ride the
            # f4+f6 method-call shape instead ('THIS.AOBJECTREFS(LNCOUNT, 1)',
            # same method's caller) — never an e0 subscript section.
            if i + 3 > end:
                raise Unsupported("array-member token truncated")
            nm = _sym(syms, S.u16(buf, i + 1))
            if stack and isinstance(stack[-1], MemberRef):
                stack.append(MemberPath([stack.pop().name, nm]))
            elif stack and isinstance(stack[-1], MemberPath):
                prev = stack.pop()
                stack.append(MemberPath(list(prev.names) + [nm]))
            elif stack and isinstance(stack[-1], Sym):
                stack.append(MemberPath([stack.pop().name, nm]))
            elif stack and isinstance(stack[-1], MemvarRef):
                # r44-arity: m.<name> e0 <member> is one path, not two
                # ASCAN operands. Authored ASCAN is 2-6 args; the foxcharts
                # getchartproperties stream is
                # 43 f5 0d f4<LOPROPERTIESLIST> e0<_DESCRIPTIONS> … ea 11 —
                # six operands once the e0 name folds onto the memvar.
                prev = stack.pop()
                stack.append(MemberPath(["m." + prev.name, nm]))
            else:
                stack.append(WithMemberPath([nm]))
            i += 3
        elif op == S.SCOPE_OP:
            # r73-scope: df [f4 hop]* e3 <class> then either f7 <member>
            # (property: Class::Member) or f6 <method> (Class::Method(args),
            # arguments already on this segment's stack). Oracle r73-scope:
            # C1::Name -> df e3 f7; C1::M1() -> 43 df e3 f6; C1::M1(1) ->
            # 43 f8 1 df e3 f6; THIS.Custom::Init() -> 43 df f4 e3 f6.
            j = i + 1
            hops = []
            while j + 3 <= end and buf[j] == S.MEMBER:
                hops.append(_sym(syms, S.u16(buf, j + 1)))
                j += 3
            if j + 3 > end or buf[j] != S.SCOPE_CLASS:
                raise Unsupported("scope-ref shape")
            cls = _sym(syms, S.u16(buf, j + 1))
            j += 3
            if j + 3 > end:
                raise Unsupported("scope-ref shape")
            if buf[j] == S.SYM:
                member = _sym(syms, S.u16(buf, j + 1))
                stack.append(ScopeRef(cls, member, hops=tuple(hops)))
                i = j + 3
                continue
            if buf[j] == S.NAME:
                member = _sym(syms, S.u16(buf, j + 1))
                args = list(stack)
                stack.clear()
                node = ScopeRef(cls, member, hops=tuple(hops), args=args)
                if member_callee_tail:
                    raise _GroupDone(node, j + 3)
                stack.append(node)
                i = j + 3
                continue
            raise Unsupported("scope-ref shape")
        elif op == S.ARRAY_ELEM_CALL and stack:
            # e5 <sym> closes an array-element method receiver: the subscript
            # precedes the marker and the named array follows it.
            if i + 3 > end:
                raise Unsupported("array-element receiver truncated")
            sub = stack.pop()
            if member_callee_tail:
                # round39 W15: in a segment the element read may carry the
                # property tail that belongs to IT — attach, never detach.
                attached = _dec_w15_elem_prop_tail(buf, i, end, syms,
                                                   stack, sub,
                                                   seg_start=seg_start)
                if attached is not None:
                    stack.append(attached[0])
                    i = attached[1]
                    continue
            stack.append(ArrayElement(
                Sym(_sym(syms, S.u16(buf, i + 1))), [sub], method_receiver=True))
            i += 3
            continue
        elif op == 0xE1:
            # e1 <id> = system-OBJECT reference opener, id per variable
            # (schemas.SYSTEM_OBJECT_REFS; oracle round-21 BOUND for _SCREEN/_VFP),
            # then intermediate member hops as f4 <u16> and ONE terminal property
            # read as f7 <u16>. Measured shapes:
            #   zero hops  'e1 39 f7<CAPTION>' (oracle round-21 e4) ==
            #              '_screen.Caption' (_base.vcx::_checkbox s11, corpus)
            #   one hop    'WITH _SCREEN.SYSTEM.Drawing'
            #              (foxchartsbeta.vcx::DeltaLegend s1, corpus alignment)
            #   four hops  'm.loImgFormat = _SCREEN.SYSTEM.Drawing.Imaging.
            #              ImageFormat.Bmp' (chartadjust.scx::CmdSave s0, corpus
            #              alignment; five aligned statements BMP/Jpeg/Gif/Png/Tiff)
            # Bare sysvar reads are NOT e1-encoded (_cliptext -> ed 1d; oracle
            # round-21 REFUTED the bare-read prediction; round-27 s8 binds bare
            # `_SCREEN` as ed 39), so a bare opener, an id outside
            # SYSTEM_OBJECT_REFS, or a missing terminal property raises rather
            # than guesses. Bounds-check before every byte read.
            #
            # Round-27 extends the tails (minimal pair s1/s2): after the hop run,
            # f6 <u16> is a TERMINAL method call whose group closer follows
            # (left unconsumed for _dec_group, same convention as _dec_path),
            # and e5 <u16> is the MID-chain call spelling when a member access
            # or an enclosing call follows (s2 `_SCREEN.Foo().Bar`).
            if i + 2 > end or buf[i + 1] not in S.SYSTEM_OBJECT_REFS:
                raise Unsupported("system-object reference form")
            names = [S.SYSTEM_OBJECT_REFS[buf[i + 1]]]
            j = i + 2
            while j + 3 <= end and buf[j] == S.MEMBER:
                names.append(_sym(syms, S.u16(buf, j + 1)))
                j += 3
            if j + 3 <= end and buf[j] == S.SYM:
                stack.append(MemberPath(names + [_sym(syms, S.u16(buf, j + 1))]))
                i = j + 3
            elif member_callee_tail and j + 3 <= end and buf[j] == S.NAME:
                # RECEIVER shape (no terminal f7) — see MemberPath.receiver
                stack.append(MemberPath(names, receiver=True))
                i = j
            elif member_callee_tail and j + 3 <= end \
                    and buf[j] == S.ARRAY_ELEM_CALL:
                # s2 `_SCREEN.Foo().Bar`: pivot consumes e5 <method> [+ terminal
                # f7] and closes the enclosing group with the completed value
                # (_GroupDone); it never returns.
                _dec_args_first_call(buf, j, end, syms, stack, names)
            else:
                raise Unsupported("system-object reference form")
        elif op == S.SYSVAR_READ:
            # ed <u8 id>: bare system-variable read, family oracle-measured round 21
            # (_cliptext -> 'ed 1d'); ids carried in schemas.SYSTEM_VARS with their
            # own provenance. A SEPARATE arm from e1 above on purpose: round-21's
            # recorded refutation is precisely that bare sysvar reads are NOT
            # e1-encoded. Unknown ids stay Unsupported, never guessed.
            if i + 2 > end:
                raise Unsupported("system-variable read truncated")
            if buf[i + 1] not in S.SYSTEM_VARS:
                raise Unsupported(
                    f"system-variable id 0x{buf[i + 1]:02x} unmapped")
            stack.append(Sym(S.SYSTEM_VARS[buf[i + 1]]))
            i += 2
        elif op == S.WORKAREA_REF:
            sub = buf[i + 1]
            if sub == 0x0D:
                # m.<name>: normally followed by f7 <sym>, but may also use
                # f4 <sym> (member-of-memvar) or f6 <sym> (array-of-memvar)
                if i + 5 > end:
                    raise Unsupported("memvar reference truncated")
                if buf[i + 2] == S.NAME and i + 8 <= end \
                        and buf[i + 5] == S.FC:
                    # Round-30 memvar-array element READ, rvalue twin of the
                    # round-28 PUT target: 'm.laX(<subs>)' in VALUE position
                    # rides the same f5 0d f6 <arr> <fc..fd units> shape with
                    # the source's own bracket closer. Bounds-checked reads;
                    # unmeasured subscript tails stay Unsupported. (The plain
                    # no-subscript form stays the MemvarRef arm below.)
                    nm = _sym(syms, S.u16(buf, i + 3))
                    j = i + 5
                    subs = []
                    bracket = False
                    while True:
                        if j >= end or buf[j] != S.FC:
                            raise Unsupported("memvar-array subscript shape")
                        es2, k2 = _dec_expr(
                            buf, j + 1, end, syms,
                            stop_bytes=frozenset({S.FD, 0xCD, S.ARGJOIN}))
                        if len(es2) != 1 or k2 >= end or buf[k2] != S.FD:
                            raise Unsupported("memvar-array subscript unresolved")
                        subs.append(es2[0])
                        j = k2 + 1
                        if j < end and buf[j] == S.ARGJOIN:
                            j += 1
                            continue
                        if j < end and buf[j] in (S.PAREN, 0x16):
                            bracket = buf[j] == 0x16
                            j += 1
                            break
                        raise Unsupported("memvar-array subscript list tail")
                    stack.append(ArrayRef("m." + nm, subs, bracket=bracket))
                    i = j
                elif buf[i + 2] == S.SYM:
                    nm = _sym(syms, S.u16(buf, i + 3))
                    # The alias-M run TERMINATES at its terminal f7 (oracle
                    # round-21 j1/j3, BOUND): a following f4/f7 ref begins an
                    # INDEPENDENT value — operators join complete values left-
                    # associatively and call arguments stay separate pushes.
                    # The former greedy fold across the terminal f7 merged two
                    # operands into one bogus m.x.THIS.y path, causing the
                    # operand stack underflow (6bdc77c08e42b46c:2) and spliced
                    # adjacent call arguments in lifted methods.
                    stack.append(MemvarRef(nm))
                    i += 5
                elif buf[i + 2] == S.NAME:
                    nm = _sym(syms, S.u16(buf, i + 3))
                    if member_callee_tail and i + 5 == end:
                        # Round-30 call-group close form: the ref is the LAST
                        # token of its group window — '43 <args> f5 0d f6 <arr>'
                        # names an array-element READ (foxcharts _drawaxis
                        # stmts#95..97, _MemArrayClose provenance). The terminal
                        # gate exists for STABILITY: it keeps Round-29 emitted
                        # text byte-for-byte under this campaign's zero-drift
                        # gate. It does not measure a mid-group m.<f6> as plain
                        # MemvarRef: on three cited carriers the suppressed
                        # mid-group array-element reading MATCHES gold
                        # (_SPELLPROPERTY(m.laMembers(lnI,1)), UPPER(m.laLines[
                        # liLine]) — see _MemArrayClose docstring); correcting
                        # that reading is deferred to the approved
                        # authority/text-correction procedure.
                        raise _MemArrayClose(nm, i + 5, partial=list(stack))
                    elif member_callee_tail and i + 6 == end \
                            and buf[i + 5] == 0xBC and stack:
                        # Round-31 group-boundary extension of the same close
                        # form, measured envelope ONLY: the closing ref is
                        # followed by exactly ONE byte — the parent group's own
                        # bare closer 0xBC — which is the statement's final
                        # byte, and this segment already accumulated >=1
                        # subscript operand. Corpus alignment (four independent
                        # twin copies of ONE spelling, stored sources bound):
                        # foxcharts.vcx::foxcharts sec30 (Source/ copy)
                        # stmts#14/#15 = '54 f50df7{05,06}00 10 fc 43 43 00
                        # f50df70800 f8010{1,2} f50df60100 bc' <-> stored
                        # L1736/L1737 'm.lcName = Proper(m.laProperties(
                        # m.lnI,1))' / 'm.lcType = Proper(m.laProperties(
                        # m.lnI,2))'; identical bytes in the class/
                        # foxcharts.vcx and both foxchartsbeta.vcx copies.
                        # The ref+bc tail has no legal stock parse: bc's
                        # registry arity is 1 ('PROPER'), so any >=2-operand
                        # reading of the inner group was already rejected
                        # ('bare 0xBC arity rejected') — this arm only converts
                        # statements that were blocked, never re-texts lifted
                        # ones. The zero-subscript shape stays stock (guard =
                        # non-empty segment stack). Every other follower byte
                        # keeps the Round-29/30 stock readings byte-for-byte
                        # (SPELLPROPERTY / ALLTRIM-UPPER stability pins).
                        raise _MemArrayClose(nm, i + 5, partial=list(stack))
                    elif member_callee_tail and stack and (
                            _GROUP_DEPTH >= 2
                            or i + 5 == end
                            or buf[i + 5] not in (S.MEMBER, S.SYM, S.NAME,
                                                  S.ARRAY_ELEM_CALL)):
                        # r48-nestcall: the round-30 comment above already
                        # recorded that the SUPPRESSED mid-group reading
                        # matches gold on its own carriers and deferred the
                        # correction. The oracle matrix measures it directly:
                        # 'x = ALLTRIM(m.a(m.b, 1))' is
                        # '43 43 00 <m.b> <1> f5 0d f6 <A> 9b' — a call in
                        # argument position opens its own 43 packet, and the
                        # unresolved callee 'f5 0d f6 <sym>' closes THAT packet
                        # args-first wherever it sits, not only at statement
                        # end ('x = m.a(m.b, 1) + 2' closes the same way with
                        # two operator bytes behind it). Read as a plain
                        # MemvarRef its arguments fell into the enclosing
                        # call's argument list, which is how a one-argument
                        # builtin came back holding three. Inside a NESTED
                        # packet the ref closes whatever follows it, because
                        # the enclosing packet's own callee is what follows —
                        # 'x = THIS._SPELLPROPERTY(m.a(m.b, 1))' is
                        # '43 43 00 <m.b> <1> f5 0d f6 <A> f4 THIS f6 _SPELL'.
                        # At depth 1 a follower byte that continues a path
                        # (f4/f6/f7/e5) belongs to the arms below and is left
                        # to them, which is where round 30's single-packet
                        # receiver/closer discriminator lives. The
                        # zero-argument shape stays stock — the guard is a
                        # non-empty segment stack.
                        raise _MemArrayClose(nm, i + 5, partial=list(stack))
                    elif _EXPR_RETRY_ACTIVE and member_callee_tail:
                        # mmid: mid-window memvar-array element READ — the
                        # 'f5 0d f6 <arr>' spelling closes its group args-first
                        # without statement-final position (a489e426e9d86703:7
                        # 'IF ":" $ m.laVals[m.liIndex]' <-> stored L1035;
                        # foxcharts s68 VARTYPE wrapper). The round-30/31
                        # terminal envelopes above keep priority: this arm runs
                        # only on the retry pass, never over a stock success.
                        global _STMT_MIDWINDOW_FIRED
                        _STMT_MIDWINDOW_FIRED = True
                        raise _MemArrayClose(nm, i + 5, partial=list(stack))
                    stack.append(MemvarRef(nm))
                    i += 5
                elif buf[i + 2] == S.MEMBER:
                    # Round-19 FORCED (probes/oracle_harvest/round19_streams.json):
                    # an alias-M run is ONE value — f5 0d f4<a> [f4<b>]* f7<t>
                    # compiles m.<a>[.b...].<t> as a single push (p1/p6), it may
                    # carry a trailing operator without splitting (p3: ADD
                    # consumes run+literal — the "two adjacent operands" reading
                    # is NEVER real), and the callee tail ends in f6 <name>
                    # exactly like the WITH family (p7). Bounds-checked reads:
                    # every operand byte is guarded before use.
                    hops = []
                    j2 = i + 2
                    while j2 + 3 <= end and buf[j2] == S.MEMBER:
                        hops.append(_sym(syms, S.u16(buf, j2 + 1)))
                        j2 += 3
                    base = "m." + hops.pop(0)
                    if j2 < end and buf[j2] == S.SYM:
                        stack.append(MemberPath([base] + hops
                                                + [_sym(syms, S.u16(buf, j2 + 1))]))
                        i = j2 + 3
                    elif member_callee_tail and j2 < end and buf[j2] == S.NAME:
                        # method call on the m-path: leave f6 for _dec_group,
                        # which pops this node as the MethodCall receiver. The
                        # run has no terminal f7 — see MemberPath.receiver.
                        stack.append(MemberPath([base] + hops, receiver=True))
                        i = j2
                    elif j2 + 3 <= end and buf[j2] == S.ARRAY_MEMBER:
                        # r44-arity: f5 0d <f4-run> e0 <member> terminates
                        # the alias-M path the same way a terminal f7 does.
                        stack.append(MemberPath(
                            [base] + hops + [_sym(syms, S.u16(buf, j2 + 1))]))
                        i = j2 + 3
                    elif member_callee_tail and j2 + 3 <= end \
                            and buf[j2] == S.ARRAY_ELEM_CALL:
                        # round-27 args-before-receiver on the alias-M run
                        # itself (oracle round27_streams.json r3a/r3b/r5):
                        # 'm.loO.Doc.GetEl("r").innerhtml' compiles the WHOLE
                        # receiver as ONE f5 0d f4-run; the e5 names GetEl, the
                        # stack holds its arguments (pushed first), and the
                        # completed value closes the enclosing group implicitly.
                        _dec_args_first_call(buf, j2, end, syms, stack,
                                             [base] + hops)
                    else:
                        # no terminator here: keep the historical bare
                        # m.<first> reference (array/fn-name forms)
                        stack.append(MemvarRef(base[2:]))
                        i += 5
                elif buf[i + 2] == S.ARRAY_ELEM_CALL and _EXPR_RETRY_ACTIVE \
                        and member_callee_tail and i + 5 <= end \
                        and not _STMT_MIDWINDOW_FIRED:
                    # round-37 P4 memvar solos (probes/oracle_harvest/
                    # ROUND37_FINDINGS.md C05, probes C1-C4; predeclared keys
                    # 04cea6515394fcec:{56,68} / 24d2f326ff2417d3:{56,68}):
                    # a memvar-array element READ whose value CONTINUES spells
                    # the e5 closer — same args-before convention as every
                    # closer namespace, array ref as the closer spelling, ONE
                    # optional terminal property read attached to the completed
                    # value, and the read closes its enclosing 43 group
                    # implicitly (the round-27/r35-A contract: decoding resumes
                    # in the ENCLOSING expression right after). Corpus alignment
                    # foxcharts.vcx::foxcharts _drawpolygon/_drawaxis carriers:
                    # '.Point.New(m.laPoints(3).x, ...)' stored L3066 =
                    # 43 43 f80103 f50de54400 f74800 ...; 'This._PrepareBrushes(
                    # m.laMainPolygon(m.n).X, ...)' stored L5771-5773. The
                    # oracle-measured boundary stays closed elsewhere: mid-group
                    # reads that do NOT continue reuse the TERMINAL f6 bytes
                    # verbatim (C2, already decoded), and value-position
                    # memvar-object calls ride '43 <arg> f50d f4<var>
                    # f6/e5<meth>' (C4, already decoded) — this arm adds only
                    # the corpus e5-continuation spelling. The arm also stays
                    # OUT of statements where the SUPPRESSED mid-window f6
                    # reading (mmid) fired earlier in the SAME statement: that
                    # reading is deferred-correction territory (r30/r31
                    # _MemArrayClose provenance; r35 bulk rejection), and a
                    # statement COMPOSING it with the e5 continuation has no
                    # measured witness (foxcharts s64/beta s27 stmt164 are the
                    # only corpus carriers of the composition) — the mix keeps
                    # its stock rejection instead of silently widening two
                    # envelopes at once. Retry-pass-only with the
                    # member_callee_tail gate: a statement that lifts stock
                    # can never reach it, so no lifted text can change (same
                    # stability contract as the mmid arm above); the three
                    # r30/r31 suppressed-mid-group stability pins stay pinned.
                    nm = _sym(syms, S.u16(buf, i + 3))
                    j = i + 5
                    args = list(stack)
                    stack.clear()
                    prop = None
                    if j + 3 <= end and buf[j] == S.SYM:
                        prop = _sym(syms, S.u16(buf, j + 1))
                        j += 3
                    elif not (j + 3 <= end and buf[j] == S.NAME):
                        # measured continuations only: the attached property
                        # read, or the r5 nesting consumer (an enclosing f6
                        # callee); any other follower is unmeasured and stays
                        # Unsupported rather than guessing a shape.
                        raise Unsupported("memvar-array e5 continuation "
                                          "without its measured follower")
                    raise _GroupDone(MidCall(["m"], nm, args, prop), j)
                else:
                    raise Unsupported("memvar reference without variable")
            elif 0x01 <= sub <= 0x0A:
                stack.append(WorkAreaRef(chr(0x40 + sub)))   # A..J
                i += 2
            else:
                raise Unsupported(f"work-area id {sub:#04x} outside measured set")
        elif op in (S.SKIP_PARAM_ON_FALSE, S.SKIP_PARAM_ON_TRUE):
            # IIF()/ICASE() parameter-list navigation: token + u16 skip, no node.
            # The surrounding call's parameter structure handles branching; confirmed
            # by 11 corpus statements lifting once these are consumed (FINDINGS iter.22)
            if i + 3 > end:
                raise Unsupported("skip-param marker truncated")
            i += 3
            continue
        elif op == 0x18:
            # ByRef argument marker (Guineu Token.ByRef), r38 M1/M2/M3: inside
            # the direct-call 43-group family EVERY variable argument carries a
            # one-byte flag slot immediately before its push token — 00 byval
            # default (still consumed node-less below) and 18 = '@' by
            # reference. Measured shapes: '18 f7 <u16>' variable argument
            # (c0005/a0001/a0002/a0003/stored frame27; per-argument,
            # position-independent), '18 f5 0d f7 <u16>' the same argument
            # m.-qualified (r41 a01 vs a02, one-byte delta; see
            # ByrefMemvarRef), and '18 f6 <u16>' closing the nested
            # array-element group '@arr(subscript)' (a0004 — flag precedes the
            # NAME ref, not the subscript). Anything else keeps the historical
            # node-less consumption. Two further shapes ARE on the grammar but
            # occur nowhere in the corpus, so nothing decodes them yet: the
            # two-hop path '@This.Width' / '@alias.field' = 18 f4 <u16>
            # f7 <u16> (r41 e02/f02 — they compile, contrary to the r38
            # prediction that no wire could demand more), and the m.-qualified
            # array element '@m.arr(sub)' = 43 <sub> f5 0d 18 f6 <u16>
            # (r41 d01/d02), whose flag rides BETWEEN the bank prefix and the
            # name ref. Whole-corpus raw scan: 18 f5 0d f4, 18 f5 0d f6 and
            # f5 0d 18 all have zero occurrences, and every raw '18 f4'/'18 f6'
            # hit is the INT8 literal 'f8 02 18' (value 24). The paren form and
            # bare '@' stay compiler-rejected (a0005/a0006, retwinned
            # m.-qualified as e04/e05), as does '@' on an expression (e03), on
            # a three-hop path (e01) and WITH-scoped (e06).
            if i + 4 <= end and buf[i + 1] == S.SYM:
                stack.append(ByrefSym(_sym(syms, S.u16(buf, i + 2))))
                i += 4
                continue
            if i + 6 <= end and buf[i + 1] == S.WORKAREA_REF \
                    and buf[i + 2] == 0x0D and buf[i + 3] == S.SYM:
                stack.append(ByrefMemvarRef(_sym(syms, S.u16(buf, i + 4))))
                i += 6
                continue
            if i + 2 <= end and buf[i + 1] == S.NAME:
                global _ARG_BYREF_CLOSE
                _ARG_BYREF_CLOSE = True
            i += 1
            continue
        elif op == 0x00:
            # ByVal argument marker (Guineu Token.ByVal): prefixes call arguments
            # passed by value. Consumed without producing a node; emission matches
            # stored sources because VFP recompiles both spellings identically.
            i += 1
            continue
        elif op == 0xE0 and stack:
            # array brackets inside expressions: base popped from stack,
            # subscripts until cd ('this.aRefs[x,y]' iter. 46)
            base = stack.pop()
            i += 1
            subs = []
            while True:
                if i >= end:
                    raise Unsupported("array subscript unterminated")
                if buf[i] == 0xCD:
                    i += 1
                    break
                es3, k3 = _dec_expr(buf, i, end, syms,
                                    stop_bytes=frozenset({S.FD, 0xCD, S.ARGJOIN}))
                if len(es3) != 1:
                    raise Unsupported("array subscript unresolved")
                subs.append(es3[0])
                i = k3
                if i < end and buf[i] == S.ARGJOIN:
                    i += 1
                    continue
                if i < end and buf[i] == 0xCD:
                    i += 1
                    break
                raise Unsupported("array subscript tail")
            stack.append(ArrayElement(base, subs))
            continue
        elif op == 0xCC:
            # Constant-folded-literal marker, consumed as a NO-VALUE byte: it rides
            # immediately AFTER a constant-folded numeric literal and BEFORE the
            # operator that consumes it (RPN [operand][fa literal][cc][binop]).
            # Corpus forcing (round-30 census, stored METHODS alignment):
            #   chartadjust.scx::base64encode 'm.lnLong=m.ln1*(2^16)+m.ln2*(2^8)+
            #   m.ln3' compiles [fa 65536.0][cc][04][fa 256.0][cc][04][06] — the
            #   same pairing inside the FLOOR/MOD 43-groups closed by bare 7a/47;
            #   xfrxlib.vcx::xfrxdm 'nFactor=10000/(96*100/100)' compiles
            #   [fa 104.166…][cc] (docs/FORMAT.md: constant folding is
            #   irreversible — the folded value IS the faithful decode).
            # Any push or pop here strands an operand or underflows the stack at
            # the following binop, so no-value is the only reading consistent with
            # every carrier. Strictly additive: 0xCC previously always raised
            # "expression opcode 0xcc". Full-population replay at landing: gained
            # exactly the 14 blocked cc-carrying solos, LOST=LEAK=text-drift=0;
            # the 3 combo carriers reattribute to their measured co-blocker
            # (indexed-member property component missing) and stay blocked.
            i += 1
            continue
        elif op == 0xCD:
            break   # array closer terminates this expression segment (iter. 46)
        elif op == S.EMPTY_ARG:
            # r63-emptyarg: ONE db per omitted argument slot inside an fc..fd
            # group — DO FORM WITH a,,b compiles `d1 f7 <a> 07 fc db fd 07
            # f7 <b>`. Round 22 already peeks db at 43-group segment
            # boundaries (stop_bytes includes EMPTY_ARG there, so this arm
            # is not reached inside a 43-group). A trailing slot at
            # statement end is `fc db` with the fd reader-stripped.
            stack.append(EmptyArg())
            i += 1
            continue
        elif op == S.CALL_OPEN:
            # r35-A: a group whose value completes via the group-level pivot's
            # implicit close (_GroupDone) surfaces HERE when the group was
            # opened directly by an expression rather than a parent group's
            # segment loop. Stock code can never observe this exception at
            # this arm (a _GroupDone escaping _dec_group uncaught would have
            # leaked at the statement boundary; the baseline population has
            # zero leaks), so the handler is additive-only: adopt the
            # completed value and resume at its position.
            try:
                node, i = _dec_group(
                    buf, i, end, syms,
                    # only a 43 that is the FIRST byte of the enclosing
                    # group's first segment doubles its opener; one that
                    # follows an operand is an ordinary later packet
                    opens_first_packet=(bool(packet & _PACKET_OPENS_FIRST)
                                        and i == seg_start and not stack))
            except _GroupDone as gd:
                node, i = gd.node, gd.pos
            except _ChainOpen as co:
                # r40 group43: the group just read is one link of a longer
                # args-before chain whose next link takes THIS segment's
                # operands as its arguments (see _ChainOpen). _dec_group has a
                # single call site, so this is the only place the exception is
                # ever observed; a stock pass can never raise it (the arm that
                # does is retry-gated), so this handler is additive-only.
                node, i = _dec_chain_link(buf, co, end, syms, stack)
            except Unsupported as stock_err:
                # Round37 P8 (C09/G5, retry pass only): the measured multi-link
                # call-value chain grammar (_dec_chain_group) engages ONLY when
                # the stock group reader rejected the bytes, and ONLY at plain
                # expression level — never inside an r27 callee-tail segment.
                # A stock success can never reach this arm; when the chain
                # grammar declines too, the STOCK message is re-raised so
                # blocked-method diagnostics stay byte-identical.
                if not _EXPR_RETRY_ACTIVE or member_callee_tail:
                    raise
                try:
                    node, i = _dec_chain_group(buf, i, end, syms)
                except Unsupported:
                    raise stock_err
            stack.append(node)
        else:
            raise Unsupported(f"expression opcode 0x{op:02x}")
    return stack, i


def _dec_operand(buf, i, end, syms):
    stack, j = _dec_expr(buf, i, end, syms, stop_at_one=True)
    if len(stack) != 1:
        raise Unsupported("operand did not resolve to a single value")
    return stack[0], j


def _pop(stack):
    if not stack:
        # Round-33 arena: an operator/postfix whose operands were accumulated on
        # an ENCLOSING group/window stack reaches its own fresh segment empty;
        # the compiler emitted one linear RPN stream per expression, so pull
        # from the nearest enclosing live stack. Engages only inside the retry
        # pass -- stock behaviour is untouched wherever a stock parse succeeds.
        if _EXPR_RETRY_ACTIVE:
            fb = _arena_fallback(stack)
            if fb is not None:
                return fb.pop()
        raise Unsupported("operand stack underflow")
    return stack.pop()


def _dec_str_arg(buf, i, end):
    """A d9- or fb-encoded literal at i; returns (text, next_index). Both quote styles
    occur in SQL statements (measured: FROM/CURSOR names arrive as either)."""
    op = buf[i]
    if op not in (S.STR, S.STR2):
        raise Unsupported("expected string literal")
    n = S.u16(buf, i + 1)
    return _payload_text(buf[i + 3:i + 3 + n]), i + 3 + n


def _on_handler_text(buf, t, end):
    """The trailing fb command-string of an ON statement (round-20 grammar); it must
    run exactly to the end of the stream. Handler text is stored source and is
    re-emitted verbatim."""
    if t + 3 > end or buf[t] != S.STR:
        raise Unsupported("ON handler string missing")
    n = S.u16(buf, t + 1)
    if t + 3 + n != end:
        raise Unsupported("ON trailing bytes")
    return _payload_text(buf[t + 3:t + 3 + n]), t + 3 + n


def _dec_withref(buf, i, end, syms, allow_callee_tail=False):
    """e2 forms, all measured:
    - legacy 4-byte: e2 f7 <u16> -> WithRef(.name)              (f8_wit probe)
    - path form:     e2 <f4-run> f7 <term> -> WithMemberPath     (.A.B, WITH-scoped;
      forced by systeminfo::frmSysinfo '.txtCompany.VALUE=' assignments)
    - callee tail:   e2 [<f4-run>] f6 <u16> -> partial path, f6 UNCONSUMED; valid ONLY
      with allow_callee_tail (inside a 43-group the f6 names the method being called,
      forced by '.refresh()' / '.A.Method()' statements).
    - array member:  e2 [<f4-run>] e0 <u16 sym> -> WithMemberPath, fully consumed.
      The e0 token carries the member's own symbol id (schemas.ARRAY_MEMBER), so the
      reference is complete without any closer. Corpus alignment:
      _dialogs.vcx::cmdEnter — 'FOR lnCount = 1 TO ALEN(.aChoices)'
      compiles the TO-argument as 43 e2 e0 <ACHOICES> cd (cd = ALEN bare closer),
      and ASORT(.aChoices) as 43 e2 e0 <ACHOICES> ea 10; in both the group must
      close on its own callee, so e2 may NOT stop short at the e0."""
    j = i + 1
    if j < end and buf[j] == S.SYM:
        return WithRef(_sym(syms, S.u16(buf, j + 1))), j + 3
    names = []
    while j + 3 <= end and buf[j] == S.MEMBER:
        names.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if j < end and buf[j] == S.SYM:
        names.append(_sym(syms, S.u16(buf, j + 1)))
        return WithMemberPath(names), j + 3
    if allow_callee_tail and j < end and buf[j] == S.NAME:
        # RECEIVER shape (no terminal f7) — see MemberPath.receiver
        return WithMemberPath(names, receiver=True), j   # f6 left for the closer
    if j + 3 <= end and buf[j] == S.ARRAY_MEMBER:
        # WITH-scoped array member named BY the e0 operand (.aChoices); bounds
        # check precedes the u16 read (standing decoder rule 1).
        names.append(_sym(syms, S.u16(buf, j + 1)))
        return WithMemberPath(names), j + 3
    raise Unsupported("with-reference form unresolved")


def _as_class_name(marker, text):
    """Spelling of a class name after AS / OF.

    r47-localas: a BARE name is an identifier — the compiler uppercases it and
    stores it under fb, so its source case is gone. A QUOTED name is a string,
    stored under d9 with its case intact. Emitting a d9 payload unquoted writes
    the fb frame instead, so the quotes are part of the recovered spelling.

    r50-sysapp: an EMPTY payload has no bare spelling at all — a name with no
    characters is not an identifier — so it is written with the delimiters its
    own marker records, which is round 42's strdelim rule applied to the one
    payload where the bare form does not exist ('AS []' -> fb 00 00,
    'AS ""' -> d9 00 00)."""
    if text == "":
        return '""' if marker == S.STR2 else "[]"
    return '"%s"' % text if marker == S.STR2 else text


# r50-leadsweep: the one-byte command bank, identified by compiling every one
# of them and reading the lead off the result. Each optional modifier is ONE
# byte appended to the bare frame — the shape every flag word in this format
# takes — and only the modifiers measured here are admitted.
_R50_BARE_COMMANDS = {
    0x07: ("ASSIST", {}),
    0x0D: ("CHANGE", {}),
    0x16: ("DIR", {}),
    0x17: ("DISPLAY", {0x1B: "MEMORY", 0xCB: "STATUS"}),
    0x19: ("EDIT", {}),
    0x1A: ("EJECT", {0xBE: "PAGE"}),
    0x41: ("RESUME", {}),
    0x58: ("RETRY", {}),
    0x59: ("LOGOUT", {}),
    0x5A: ("UNLOCK", {0x03: "ALL"}),
    0x5B: ("FLUSH", {0xCA: "FORCE"}),
    0x93: ("BLANK", {}),
    0x94: ("RESET", {}),
    0x9C: ("ROLLBACK", {}),
}

# BEGIN / END TRANSACTION each spend a `bd` keyword byte; VFP has no bare
# BEGIN or END statement, so the one-byte spelling has no producer.
_R50_TRANSACTION = {0x9B: "BEGIN TRANSACTION", 0x9D: "END TRANSACTION"}


def _r50_operand(buf, t, end, syms, what):
    """One name / file operand in the sweep's commands.

    r50-leadsweep: the same one-bit spelling REPORT FORM's and EXTERNAL's own
    name operands carry — an UNQUOTED name rides bare `fb <str>` and a quoted
    one a grouped `fc d9 <str> fd`, whose trailing fd is reader-stripped when
    it ends the statement. A variable target rides its own symbol tokens.
    Returns (text, next_index).
    """
    if t < end and buf[t] in (S.STR, S.STR2):
        return _dec_str_arg(buf, t, end)
    if t < end and buf[t] == S.FC:
        es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("%s operand unresolved" % what)
        if k < end and buf[k] == S.FD:
            k += 1
        return _emit(es[0]), k
    if t + 5 <= end and buf[t] == S.WORKAREA_REF and buf[t + 1] == 0x0D \
            and buf[t + 2] == S.SYM:
        return "m." + _sym(syms, S.u16(buf, t + 3)), t + 5
    if t + 3 <= end and buf[t] == S.SYM:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    raise Unsupported("%s operand unresolved" % what)


def _dec_array_elem_call(buf, i, end, syms):
    """`[f5 0d] e5 <arr> <subscript units> 16 [f4 <hop>]* f6 <M> <arg units> 03`

    r50-sysapp: a bare statement whose RECEIVER is an array element —
    `m.ac[1].fromargb(m.a)`. The e5 names the array (its other reading, the
    array-element method receiver closer, is the same token from the value
    side) and the subscript list that follows closes with the same 16 the
    memvar-array PUT target uses, then an ordinary f6 member callee with the
    universal fc..fd/07 argument list closed by 03. Measured with and without
    the m. root, with one and two arguments, and with a hop between the
    element and the callee; the no-argument spelling compiles to a 43 packet
    instead and is NOT this shape. Declines to None on every byte that is not
    the measured shape, so every other bare statement keeps its own reader.
    """
    t = i
    prefix = ""
    if t + 2 <= end and buf[t] == S.WORKAREA_REF and buf[t + 1] == 0x0D:
        prefix, t = "m.", t + 2
    if t + 3 > end or buf[t] != S.ARRAY_ELEM_CALL:
        return None
    name = prefix + _sym(syms, S.u16(buf, t + 1))
    t += 3

    def _units(t):
        out = []
        while True:
            if t >= end or buf[t] != S.FC:
                return None, t
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                return None, t
            out.append(es[0])
            t = k + 1
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            return out, t

    subs, t = _units(t)
    if not subs or t >= end or buf[t] != 0x16:
        return None
    t += 1
    hops = []
    while t + 3 <= end and buf[t] == S.MEMBER:
        hops.append(_sym(syms, S.u16(buf, t + 1)))
        t += 3
    if t + 4 > end or buf[t] != S.NAME:
        return None
    method = _sym(syms, S.u16(buf, t + 1))
    args, t = _units(t + 3)
    if not args or t + 1 != end or buf[t] != 0x03:
        return None
    return MethodCall([ArrayRef(name, subs, bracket=True)] + hops, method, args)


def _typed_extension(name, buf, t, end, syms, what):
    """Typed-parameter extension after a name (round-24 l1 byte-exact vs
    workerchart.scx::Organizationchart1.onnodeclick 'Lparameters to_Node As
    ChartNode Of ..\\org_chart'): 51 fb<Class UPPERCASED> [c3 <library>].
    Round-28 corpus census: the OF library is OPTIONAL after the class —
    'af f7 0000 51 fb' x19 (foxcharts _drawcone family, deskalert,
    ctl32 _resize: 'Lparameters tc_Key As String') and PUBLIC tails
    '37 f7 .. 51 fb IMAGE' x11+ carry AS with no OF at all. When OF is
    present it is required to parse; when absent the pair degrades to
    (name, typ, None). Returns (name-or-(name, class, library|None),
    next_index)."""
    if t >= end or buf[t] != S.AS_CLAUSE_MARK:
        return name, t
    if t + 1 == end:
        # r50-sysapp: the mark ALONE, with nothing behind it. Two sources
        # produce it and both destroy the text — a type name that preprocesses
        # away ('#DEFINE ZZTYPE' then 'AS ZZTYPE') and a parenthesised name
        # expression ('AS (m.a)'), whose operand the compiler discards
        # entirely. Every literal spelling stores something (bare fb, quoted
        # d9, 'AS []' fb 00 00, 'AS ""' d9 00 00), so no written type
        # reproduces the bare mark. The declaration is admitted with no type
        # rather than refused: an AS clause is an annotation with no runtime
        # meaning, so the text without it is the same program. Registered as
        # the round's one cap.
        return (name, None, None), end
    if t + 2 > end or buf[t + 1] not in (S.STR, S.STR2):
        raise Unsupported("%s AS clause without class" % what)
    marker = buf[t + 1]
    typ, t = _dec_str_arg(buf, t + 1, end)
    typ = _as_class_name(marker, typ)
    if t >= end or buf[t] != S.PARAM_OF_MARK:
        return (name, typ, None), t
    # r50-sysapp: a QUOTED library rides a grouped `c3 fc d9 <str> fd` while a
    # bare one rides `c3 fb <str>` — the same one-bit spelling difference the
    # class name itself carries, measured side by side on FOR EACH's own OF.
    grouped = t + 1 < end and buf[t + 1] == S.FC
    m = t + 2 if grouped else t + 1
    if m + 1 >= end or buf[m] not in (S.STR, S.STR2):
        raise Unsupported("%s OF library unresolved" % what)
    lib_marker = buf[m]
    lib, t = _dec_str_arg(buf, m, end)
    if grouped:
        if t < end and buf[t] == S.FD:
            t += 1
        elif t != end:
            raise Unsupported("%s OF library unresolved" % what)
    return (name, typ, _as_class_name(lib_marker, lib)), t


def _dec_param_name(buf, t, end, syms):
    """One declaration/parameter name: f7 <sym>, f6 <array/fn name>,
    optionally m.-prefixed via f5 0d f7 <sym>, or — since round-32 —
    f5 0d f6 <name> when the enclosing LOCAL declarator's dimension group
    (fc ...) follows immediately.
    Returns (display_name, next_index)."""
    if t < end and buf[t] == S.WORKAREA_REF and t + 5 <= end \
            and buf[t + 1] == 0x0D and buf[t + 2] == S.SYM:
        return "m." + _sym(syms, S.u16(buf, t + 3)), t + 5
    if t < end and buf[t] == S.WORKAREA_REF and t + 5 <= end \
            and buf[t + 1] == 0x0D and buf[t + 2] == S.NAME \
            and t + 5 < end and buf[t + 5] == S.FC:
        # round-32: f6 beside f7 inside the memvar arm. The ONLY measured
        # envelope is a LOCAL array declarator whose subscript group starts
        # right after the name — fc <dim> fd (07 fc <dim> fd)* [03|16], read
        # by the LOCAL arm's dimension loop, not here. Hardening after review
        # P6.1: without the FC-follower requirement a bare f5 0d f6 lifted
        # under PUBLIC/PARAMETERS/LPARAMETERS ('PUBLIC m.x' etc.) with no
        # carrier anywhere; those shapes now fall through to the rejection
        # below, as does a dim-less LOCAL m.<name>.
        #   ae f5 0d f6 0b00 fc f80101 fd 16 = 'LOCAL m.laBind[1]'
        #     (_reportlistener.vcx::gfxoutputclip sec5 stmt1,
        #      census key 539ab7008a1fea0e:5)
        #   ae f5 0d f7 0f00 07 f5 0d f6 1200 fc f80101 fd 16 =
        #     'LOCAL m.liIndex, m.laMembers[1]' (same record ::xmllistener
        #      sec39 stmt42; its method stays blocked on 'unterminated 43
        #      group'). Other f5 ids are NOT memvar names (namespace guard).
        return "m." + _sym(syms, S.u16(buf, t + 3)), t + 5
    if t < end and buf[t] == S.SYM:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    if t < end and buf[t] == S.NAME:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    raise Unsupported("parameter name form")


def _dec_path(buf, i, end, syms, allow_callee_tail=False):
    """A run of f4 tokens (object path) with a terminal f7 (property read):
    f4 A f4 B f7 C -> A.B.C. Forced by 39 in-scope path steps (FINDINGS).

    Inside a 43-group the run may instead terminate at the group's f6 callee
    (THIS.Parent.grid1.DoScroll: the path is the RECEIVER, the f6 names the method);
    that form is only valid with allow_callee_tail — the f6 stays unconsumed for the
    group loop. A lone f4 falls back to the historical MemberRef so pre-cluster
    callers keep their behaviour; anything else is Unsupported, never a guess."""
    names = [_sym(syms, S.u16(buf, i + 1))]
    j = i + 3
    while j + 3 <= end and buf[j] == S.MEMBER:
        names.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if j < end and buf[j] == S.SYM:
        names.append(_sym(syms, S.u16(buf, j + 1)))
        return MemberPath(names), j + 3
    if j + 3 <= end and buf[j] == S.ARRAY_MEMBER \
            and not (j + 3 < end and buf[j + 3] == S.FC):
        # r49-valsweep: an ARRAY-valued property closes a path with e0 rather
        # than f7 — `x = ALEN(m.a.ob.arr, 1)` is `43 f5 0d f4 A f4 OB e0 ARR
        # f8 01 01 cd`. The subscripted spelling (`e0 <sym> fc <sub> …`) is the
        # WITH-scoped array element the expression walk already reads, so only
        # a TERMINAL e0 is taken here and that reader keeps its own frames.
        names.append(_sym(syms, S.u16(buf, j + 1)))
        return MemberPath(names), j + 3
    if j < end and buf[j] == S.NAME and allow_callee_tail:
        # RECEIVER shape: the run carries no terminal f7, so this path is the
        # object the following f6 names a method on (MemberPath.receiver).
        return MemberPath(names, receiver=True), j   # callee byte left for _dec_group
    if len(names) == 1:
        return MemberRef(names[0]), i + 3
    raise Unsupported("member path without terminal property")


# Clause marks that follow a DO WITH list (IN, NAME, TO, trailing flags).
# The list reader returns at the first of these; the arm names the leftover.
_DO_WITH_STOP = frozenset({0x16, 0x4A, S.TO_MARK, 0xBE, 0xCE, 0xBC, 0xBD})


def _dec_do_with_list(buf, t, end, syms):
    """WITH-list slots after REPLACE_WITH, shared by every 0x18 spelling.

    r68-arglist: DO <sym>, DO <name.prg>, DO (<expr>) and DO FORM share one
    list. A slot is a bare symbol, a MEMBER path (or WITHREF), or an fc-group
    (string, number, expression, array element, omitted db). Slots join by
    ARGJOIN; the final group's fd may be reader-stripped. An inner _dec_expr
    refusal keeps its own class. A bare @ argument is not on the wire.
    Returns (args, t) at end-of-list or at the first clause mark.
    """
    args = []
    if t >= end:
        raise Unsupported("DO WITH argument unresolved")
    while True:
        if t >= end:
            raise Unsupported("DO WITH argument unresolved")
        if args and buf[t] in _DO_WITH_STOP:
            return args, t
        if buf[t] == S.SYM:
            if t + 3 > end:
                raise Unsupported("DO WITH argument truncated")
            args.append(Sym(_sym(syms, S.u16(buf, t + 1))))
            t += 3
        elif buf[t] == S.MEMBER:
            try:
                node, t = _dec_path(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("DO WITH argument unwrapped")
            if not isinstance(node, MemberPath):
                raise Unsupported("DO WITH argument unwrapped")
            args.append(node)
        elif buf[t] == S.WITHREF:
            try:
                node, t = _dec_path(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("DO WITH argument unwrapped")
            args.append(node)
        elif buf[t] == S.FC:
            try:
                es, k = _dec_expr(buf, t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
            except Unsupported:
                raise
            if len(es) != 1:
                raise Unsupported("DO WITH argument unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            args.append(es[0])
            t = k
        else:
            raise Unsupported("DO WITH argument unwrapped")
        if t >= end:
            break
        if buf[t] != S.ARGJOIN:
            break
        t += 1
    return args, t


def _dec_do_in(buf, t, end, syms):
    """IN operand after byte 0x16 (r68-dotail).

    Unquoted filename is STR (fb). Quoted filename and IN (expr) are an
    fc-group. A 16 with nothing behind it (or WITH next) is an empty IN.
    Returns (operand, t).
    """
    if t >= end or buf[t] in _DO_WITH_STOP or buf[t] == S.REPLACE_WITH:
        return "", t
    if buf[t] in (S.STR, S.STR2):
        return _dec_str_arg(buf, t, end)
    if buf[t] == S.FC:
        node, t = _fc_group(buf, t, end, syms)
        return node, t
    raise Unsupported("DO IN operand unwrapped")


def _dec_do_tail(buf, t, end, syms):
    """Optional IN then optional WITH, the interned order (r68-dotail).

    A WITH-then-IN source compiles to the same wire as IN-then-WITH. Returns
    (args, in_target, t).
    """
    in_target = None
    if t < end and buf[t] == 0x16:
        in_target, t = _dec_do_in(buf, t + 1, end, syms)
    args = []
    if t < end and buf[t] == S.REPLACE_WITH:
        args, t = _dec_do_with_list(buf, t + 1, end, syms)
    return args, in_target, t


_DO_FORM_FLAGS = {0x53: "NOREAD", 0xBE: "LINKED", 0xCE: "NOSHOW"}


def _dec_do_form_name(buf, t, end, syms):
    """NAME operand after 4a (r68-formbank): SYM, MEMBER path, array, or group.

    Array NAME is f4-hops then f6 <arr> <subscripts> 16/03 — the same
    subscript grammar _dec_lvalue uses at f6, reached here because a
    single-hop f4+f6 PUT arm would swallow the hops and leave the
    subscripts behind.
    """
    if t + 3 <= end and buf[t] == S.SYM:
        return Sym(_sym(syms, S.u16(buf, t + 1))), t + 3
    if t < end and buf[t] == S.MEMBER:
        jr = t
        hops = []
        while jr + 3 <= end and buf[jr] == S.MEMBER:
            hops.append(_sym(syms, S.u16(buf, jr + 1)))
            jr += 3
        if jr < end and buf[jr] == S.NAME:
            try:
                node, j2 = _dec_lvalue(buf, jr, end, syms)
            except Unsupported:
                raise Unsupported("DO FORM NAME path unwrapped")
            if isinstance(node, ArrayRef):
                return ArrayRef(".".join(hops + [node.name]), node.subs,
                                bracket=node.bracket), j2
            raise Unsupported("DO FORM NAME path unwrapped")
        try:
            node, t = _dec_path(buf, t, end, syms)
        except Unsupported:
            raise Unsupported("DO FORM NAME path unwrapped")
        return node, t
    if t < end and buf[t] == S.WITHREF:
        try:
            node, t = _dec_lvalue(buf, t, end, syms)
        except Unsupported:
            raise Unsupported("DO FORM NAME path unwrapped")
        return node, t
    if t < end and buf[t] == S.FC:
        node, t = _fc_group(buf, t, end, syms)
        return node, t
    raise Unsupported("DO FORM NAME operand unwrapped")


def _dec_do_form_clauses(buf, t, end, syms):
    """Interned DO FORM bank: NAME, TO, WITH, then NOREAD LINKED NOSHOW."""
    name_target = None
    to_target = None
    args = []
    flags = []
    seen = set()
    while t < end:
        b = buf[t]
        if b == 0x4A:
            if "NAME" in seen:
                raise Unsupported("DO FORM duplicate NAME")
            seen.add("NAME")
            name_target, t = _dec_do_form_name(buf, t + 1, end, syms)
        elif b == S.TO_MARK:
            if "TO" in seen:
                raise Unsupported("DO FORM duplicate TO")
            seen.add("TO")
            to_target, t = _dec_lvalue(buf, t + 1, end, syms)
        elif b == S.REPLACE_WITH:
            if "WITH" in seen:
                raise Unsupported("DO FORM duplicate WITH")
            seen.add("WITH")
            args, t = _dec_do_with_list(buf, t + 1, end, syms)
        elif b in _DO_FORM_FLAGS:
            word = _DO_FORM_FLAGS[b]
            if word in seen:
                raise Unsupported("DO FORM duplicate %s" % word)
            seen.add(word)
            flags.append(word)
            t += 1
        else:
            break
    return args, to_target, name_target, flags, t


def _dec_with_index_prop(buf, j, end, syms):
    """99 e2 e5 <M> fc <sub> fd 03 f7 <term> (r42-formrel).

    WITH-scope `.M(sub).term` with no callee-arg list and no f4 hops.
    AATest frstestharn s12[5] is 99 e2 e5 <FORMS> fc f7 <I> fd 03 f7
    <RELEASE>. An f4 root before e5 is the P8 put topology and stays
    rejected. Bracket closer 16 and f6-callee forms stay with the other
    readers. Returns MidCall or None when any byte is not this shape."""
    t = j
    if t >= end or buf[t] != S.WITHREF:
        return None
    t += 1
    if t + 3 > end or buf[t] != S.ARRAY_ELEM_CALL:
        return None
    mid = _sym(syms, S.u16(buf, t + 1))
    t += 3
    if t >= end or buf[t] != S.FC:
        return None
    subs, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
    if len(subs) != 1 or k >= end or buf[k] != S.FD:
        return None
    t = k + 1
    if t >= end or buf[t] != S.PAREN:
        return None
    t += 1
    if t + 3 != end or buf[t] != S.SYM:
        return None
    term = _sym(syms, S.u16(buf, t + 1))
    return MidCall([""], mid, [subs[0]], prop=term)


def _dec_with_chain_call(buf, j, end, syms):
    """Round37 P8 (C09/G2 on the WITH-scoped spelling; retry pass ONLY). The
    measured indexed-mid-call statement shape, oracle canary c09 + corpus
    carriers MainPara::frmMainPara stmts 22/34 (gold L127/L139
    '.pfInfo.Pages(mActivePage).SetAll('ENABLED',.T.,'TextBox')') and
    xfrxlib::xfrxprop stmt 42 (gold L434 '.Columns(lii).SetAll("Visible",.T.)'):

        99 e2 [f4 <root>]* e5 <M> fc <sub> fd 03 f6 <T>
           fc <arg> fd [07 fc <arg> fd]* 03      (statement-final)

    renders '.[root.]M(sub).T(args)'. EXACTLY one subscript unit and the
    statement-final 03 are admitted — every other tail is unmeasured and keeps
    its historical rejection (returns None so the caller re-raises)."""
    t = j
    if t >= end or buf[t] != S.WITHREF:
        return None
    t += 1
    roots = []
    while t + 3 <= end and buf[t] == S.MEMBER:
        roots.append(_sym(syms, S.u16(buf, t + 1)))
        t += 3
    if t + 3 > end or buf[t] != S.ARRAY_ELEM_CALL:
        return None                     # exactly ONE measured mid-call opener
    mid = _sym(syms, S.u16(buf, t + 1))
    t += 3
    if t >= end or buf[t] != S.FC:
        return None
    subs, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
    if len(subs) != 1 or k >= end or buf[k] != S.FD:
        return None
    t = k + 1
    if t >= end or buf[t] != S.PAREN:   # the measured subscript-closing 03
        return None
    t += 1
    if t + 3 > end or buf[t] != S.NAME:  # terminal callee f6 <T>
        return None
    term = _sym(syms, S.u16(buf, t + 1))
    t += 3
    r = _dec_call_arg_units(buf, t, end, syms)
    if r is None:
        return None
    args, t2 = r
    if t2 + 1 != end or buf[t2] != S.PAREN:
        return None                     # statement-final closing 03 required
    midcall = MidCall([""] + roots, mid, [subs[0]])
    return MethodCall([midcall], term, args)


def _dec_scope_call_tail(buf, j, end, syms):
    """Bare scope-resolved invocation tail under lead 99 (round 33, lane R33-1):
    `df e3 <cls u16> f7 <mbr u16> f7 <dup u16>` ending EXACTLY at the statement
    end, where the trailing duplicate f7 repeats the member index. Measured on
    libs.vcx::Themedoutlooknavbar1 s0 stmt1
    'OutlookNavBar::changetheme' <-> 99dfe30100f70200f70200 (+class/ twin) and
    libs.vcx::Mycnt1 s0 stmt0 'mycnt::init' <-> 99dfe30000f70100f70100; both had
    misread the e3 position as a symbol index ("symbol index 483 beyond table").

    Returns the ScopeRef node, or None when ANY byte deviates from this measured
    spelling — the caller then falls through to the stock reader so every other
    99 tail keeps its historical rejection unchanged."""
    if j + 10 != end or buf[j + 1] != S.SCOPE_CLASS \
            or buf[j + 4] != S.SYM or buf[j + 7] != S.SYM:
        return None
    cls_i = S.u16(buf, j + 2)
    mbr_i = S.u16(buf, j + 5)
    if S.u16(buf, j + 8) != mbr_i \
            or cls_i >= len(syms) or mbr_i >= len(syms):
        return None
    return ScopeRef(_sym(syms, cls_i), _sym(syms, mbr_i))


def _dec_memvar_path_tail(buf, j, end, syms):
    """Bare memvar-path invocation tail under lead 99 (round 33, lane R33-1):
    `f5 0d (<f4 hop>)+ f7 <term>` ending EXACTLY at the statement end — the
    round-19 alias-M run shape in bare-invocation position. Measured on
    chartadjust.scx::chartadjust s4 stmt5 'm.lo.CLICK' <->
    99f50df40200f70700 (+chartadjust1 twin) and foxchartsbeta.vcx::foxcharts
    s34 stmt38 'm.loChart._PrepareTooltip' <-> 99f50df40300f71f00 (+Source/
    twin); the stock path reader read its first index from the '0d f4' pair
    ("symbol index 62477 beyond table").

    Returns MemberPath(['m.' + first-hop, ...]), or None when any byte deviates
    (missing terminal f7 included) — the caller falls through to the stock
    reader, keeping every unmeasured variant loudly Unsupported."""
    names = []
    k = j + 2                       # past f5 0d
    while k + 3 <= end and buf[k] == S.MEMBER:
        names.append(S.u16(buf, k + 1))
        k += 3
    if not names or k + 3 != end or buf[k] != S.SYM:
        return None
    names.append(S.u16(buf, k + 1))
    if max(names) >= len(syms):
        return None
    hops = [_sym(syms, i) for i in names]
    return MemberPath(["m." + hops.pop(0)] + hops)


def _dec_memvar_chain_tail(buf, j, end, syms):
    """Bare memvar-ROOTED object chain under lead 99 (round 40, lane C):
    `f5 0d <f4 hop>+ e5 <M> <fc arg fd [07 fc arg fd]*> 03 [f4 hop]* f7 <term>`
    ending EXACTLY at the statement end — the f4-rooted bare chain already read
    at this lead (`99 <f4 run> e5 …`), with the round-19 alias-M root in front
    of it. The stock reader started its path at the `f5` and took its first
    index from the '0d f4' pair, which is why these statements died 'symbol
    index 62477 beyond table' (0xF40D) rather than on a real symbol id.

    Corpus alignment, stored sources bound, three spellings x two artifact
    copies of the record (class/ + Source/ foxchartsbeta.vcx::foxcharts
    toxls):
      99 f50d f40a00 e51900 fc f50df70800 fd 07 fc f80101 fd 03 f71c00
        <-> 'm.loSheet.cells(m.lnLine,1).SELECT'
      99 f50d f40a00 e52300 fc d90300 "A:A" fd 03 f42400 f72500
        <-> 'm.loSheet.COLUMNS("A:A").EntireColumn.AUTOFIT'
      99 f50d f40a00 e51900 fc f80101 fd 07 fc f80101 fd 03 f71c00
        <-> 'm.loSheet.cells(1,1).SELECT'

    Returns the ObjectChain with the root 'm.'-prefixed (the spelling
    _dec_memvar_path_tail already uses for the call-less form), or None when
    the chain reader declines, when it stops short of the statement end, or
    when it found no call link — the caller then falls through to the stock
    reader, so every unmeasured 99 tail keeps its historical rejection."""
    try:
        node, k = _dec_object_chain(buf, j + 2, end, syms)
    except Unsupported:
        return None
    if k != end or not node.recv or not node.calls:
        return None
    node.recv[0] = "m." + node.recv[0]
    return node


def _dec_call_arg_units(buf, i, end, syms):
    """Measured multi-argument call tail for object chains: `fc <expr> fd
    [07 fc <expr> fd]*` (same ARGJOIN-between-units grammar as DIM subscripts).
    Returns ([arg ASTs], i_after_last_fd) or None when the shape does not fit."""
    args = []
    while i < end and buf[i] == S.FC:
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or k >= end or buf[k] != S.FD:
            return None
        args.append(es[0])
        i = k + 1
        if i < end and buf[i] == S.ARGJOIN and i + 1 < end \
                and buf[i + 1] == S.FC:
            i += 1
            continue
        return args, i
    return None


def _dec_object_chain(buf, i, end, syms):
    """Parse the corpus-forced member/method chain from an f4-run:

        <f4 run> ( e5 <m> <call-arg-units> 03 | f6/f7/f4 hop with optional call )*

    Call links are `e5 <method-sym> fc <args fd [07 fc args fd]*> 03`; chain hops
    after a call ride f4/f6/f7 member tokens, and a following fc opens that
    member's own argument units. A lone f6 is NEVER consumed here: it is either a
    chained method whose arguments follow (fc present) or the enclosing group's
    callee tail -- preserving the measured receiver/callee namespace boundary.

    Returns (ObjectChain, next_index) or raises Unsupported. Engaged only where
    the legacy terminal-property paths fail, so existing bindings keep their
    historical node types."""
    recv = []
    j = i
    while j + 3 <= end and buf[j] == S.MEMBER:
        recv.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if not recv:
        raise Unsupported("object chain without receiver")
    calls = []
    brackets = []
    link_hops = []
    tail = []
    while True:
        if j >= end:
            break
        b = buf[j]
        if b in (S.SYM, S.MEMBER) and j + 3 <= end:
            # r48-callhops: a member name read here follows the call BEFORE it,
            # so it is that link's hop and not the chain's trailing property
            # run. Only the names after the LAST call are the tail; `tail`
            # accumulates and is flushed into the previous link the moment
            # another call appears.
            tail.append(_sym(syms, S.u16(buf, j + 1)))
            j += 3
            continue
        if b == S.NAME and j + 6 <= end and buf[j + 3] == S.FC:
            # chained method by name with its own argument units
            name = _sym(syms, S.u16(buf, j + 1))
            r = _dec_call_arg_units(buf, j + 3, end, syms)
            if r is None:
                raise Unsupported("object-chain call args unresolved")
            args, j = r
            if calls:
                link_hops.append(tail)
                tail = []
            calls.append((name, args))
            brackets.append(False)
            if j < end and buf[j] == 0x03:
                j += 1
                continue
            break
        if b == S.ARRAY_ELEM_CALL and j + 3 <= end:
            # method link: `e5 <m> fc <args fd [07 fc args fd]*> 03` when
            # argument units follow; a bare `e5 <m>` without them is the measured
            # zero-argument spelling (translate-class/dashboard2 carriers)
            name = _sym(syms, S.u16(buf, j + 1))
            j += 3
            if j < end and buf[j] == S.FC:
                r = _dec_call_arg_units(buf, j, end, syms)
                if r is None:
                    raise Unsupported("object-chain call args unresolved")
                args, j = r
            else:
                args = []
            if calls:
                link_hops.append(tail)
                tail = []
            calls.append((name, args))
            # The subscript/argument list closes with the SOURCE's own bracket
            # marker, exactly as ArrayRef, IndexedElemRef, the LOCAL dimension
            # tail and the DIMENSION dims already record it: 03 = '( … )',
            # 16 = '[ … ]'. Only 03 was consumed before, so every element chain
            # written '[ … ]' stopped dead on the 16 and its statement raised
            # ('lvalue object-chain without terminal property' /
            # 'bare member-statement shape'). Measured carrier: vfp_skins.vcx::
            # Shape1 MouseMove (census key c46ffc91b5f95164:2), where eight
            # statements spell THIS.PARENT.PARENT.MENUPCONT.MENUPOPU[
            # NEXTPOPUP+1,1] with a property or method continuing the chain.
            if args and j < end and buf[j] in (S.PAREN, 0x16):
                brackets.append(buf[j] == 0x16)
                j += 1
            else:
                brackets.append(False)
            continue
        # anything else (fe-stripped terminator reached, foreign opcode, bare f6
        # callee tail): stop; caller judges whether the chain is complete
        break
    if not calls and not tail:
        raise Unsupported("member path without terminal property")
    return ObjectChain(recv, calls, tail, brackets, link_hops), j


def _chain_opener(buf, i, end):
    """True when an f4-run starting at i is immediately followed by the measured
    e5 call opener -- the population-lane chain shape, not a plain path."""
    j = i
    while j + 3 <= end and buf[j] == S.MEMBER:
        j += 3
    return j > i and j < end and buf[j] == S.ARRAY_ELEM_CALL


# Round39 W15-close residual: token bytes measured to follow a COMPLETED
# element-read property-tail packet in the foxchartsbeta ::50 carriers (stmts
# 77/78/80/87/88; instrumented single-decode census across all five streams,
# identical in both artifact copies — 0x43 ×3, 0xf5 ×8, 0x08 ×2, 0x00 ×1).
# Anything else after the tail (another symbol push = the ::23 natural-close
# twins, an f4 hop = mid-chain spelling, EOF = faa199:63 speculative
# adjacency) keeps the plain attach-and-continue reading verbatim.
_W15_PACKET_CLOSE_AHEAD = frozenset((
    S.CALL_OPEN,      # 0x43: next argument-packet opener (:50 stmts 80, 88)
    S.WORKAREA_REF,   # 0xf5: memvar read composing at the enclosing level
                      #       ('… .X + m.LN3D', stmts 77/78/80/87)
    S.SUB,            # 0x08: subtraction over packet values (stmt 80)
    0x00,             # ByVal marker of the following argument (stmt 88)
))


def _dec_w15_elem_prop_tail(buf, i, end, syms, stack, sub, seg_start):
    """Round39 W15 array-property-tail attachment (oracle u22/z04/v05; corpus
    carriers foxchartsbeta.vcx::foxcharts ::23 stmts 99-101 and ctl32.vcx::
    ctl32_scontainer ::48 stmt 7 first occurrence). Inside a 43-group operand
    segment (member_callee_tail) an element read carries the property push that
    belongs to IT, per the measured wire law

        <f8 packet> e5 <arr> f7 <prop>
              -> arr(sub).prop            (u22 'qq = oa(1).Name', foxcharts 99-101)
        <f8 packet> f4 <recv> e5 <arr> f4 <hop>+ f7 <term>
              -> recv.arr(sub).hop.term   (ctl32 ::48#7 'This.Controls(1).
                                           ActiveControl.BaseClass')

    The stock arm detached the property push into a bogus extra call argument
    and the emitter refused the node ('array-element receiver without method
    callee'). Engagement is exactly where the measured wire puts it: segment
    context, an f8 subscript packet immediately before the tail run (the
    element-read signature — a mid-call chain pushes ordinary argument symbols
    instead and stays on its own lane, cf. faa199b32ddf0b1c :11/:61
    'm.loShell.Namespace(x).Items.Count'), exact token shapes after the e5
    marker. A bare e5 with no trailing f7 keeps the stock ArrayElement path
    verbatim (z04 'OA[1].RESET()' pinned); the zero-hop receiver spelling
    (`f8 f4 recv e5 arr f7 term`, ctl32 ::48#7 second occurrence) already lifts
    through the round-27 args-before-receiver pivot and never reaches here.

    Round39 W15-close residual (review plan step 2): a PLAIN attachment whose
    packet frame ends at the tail is the foxchartsbeta ::50 argument-packet
    family — `43 [00] <subscript operands> e5 <arr> f7 <prop>` with NO closer
    of its own; the completed IndexedElemRef is delivered as the segment's
    terminal completion (_GroupDone, same resume contract as the round-27
    pivot) and the enclosing RPN composes around the value (stmt80's
    'LAMAINPOLYGON(LNREC + 1).X + m.LN3D - LAMAINPOLYGON(LNREC).X' binds the
    subtraction AFTER both packets closed). The close is gated on the MEASURED
    packet boundaries only: the subscript run must have consumed everything the
    packet frame held (empty segment stack at commit), and the next byte must
    be one of the four token classes sighted after a completed :50 packet —
    0x43 next packet opener, 0xf5 memvar read, 0x08 subtraction, 0x00 ByVal
    marker of the next argument. Ordinary property tails whose group closes
    through its own closer keep the natural attach-and-continue reading byte-
    for-byte (:23 twins: the byte after the tail is another symbol push,
    'LAPOINTS(3).X, Y0 - …'), as does every unknown continuation.
    Returns (node, next_i), or None when any byte deviates — the caller then
    runs the stock arm unchanged. Nothing is popped before every check passes.
    """
    recv = None
    below = None
    if isinstance(sub, MemberRef):
        # receiver spelling: the f8 subscript packet rides BELOW the member
        # run — measured byte-exact as `f8 <w> <v> f4 <recv> e5 <arr>`
        if i - 6 < seg_start or buf[i - 3] != S.MEMBER or buf[i - 6] != S.INT8:
            return None
        recv = sub.name
        below = stack[-1]
    j = i + 3
    hops = []
    if recv is not None:
        while j + 3 <= end and buf[j] == S.MEMBER:
            hops.append(S.u16(buf, j + 1))
            j += 3
        if not hops:
            return None             # measured receiver spelling always hops
    if j + 3 > end or buf[j] != S.SYM:
        return None                 # no attached property -> stock behaviour
    arr_id = S.u16(buf, i + 1)
    prop_id = S.u16(buf, j + 1)
    if max([arr_id, prop_id] + hops) >= len(syms):
        return None                 # stock arm raises the same beyond-table msg
    if recv is None:
        node = IndexedElemRef(_sym(syms, arr_id), [sub],
                              prop=_sym(syms, prop_id))
        if not stack and _GROUP_DEPTH >= 2 and j + 3 < end \
                and buf[j + 3] in _W15_PACKET_CLOSE_AHEAD:
            # commit point: the packet frame holds nothing but this read and
            # the next byte is a measured :50 packet boundary -> implicit close
            raise _GroupDone(node, j + 3)
        return node, j + 3
    # commit point: every check passed
    sub = below
    stack.pop()
    tail = [_sym(syms, h) for h in hops]
    tail.append(_sym(syms, prop_id))
    return ObjectChain([recv], [(_sym(syms, arr_id), [sub])], tail), j + 3


def _dec_args_first_call(buf, j, end, syms, stack, recv):
    """Round-27 mid-chain call pivot (oracle round27_streams.json, forced_rules:
    'System-object path boundary'). Call grammar measured on s2/w1/w2/r3a/r3b/r5
    and corpus c79070eeff459e07:39: the arguments precede the receiver run inside
    the SAME 43 group (each variable argument behind ByVal 00, already consumed
    by the generic marker arm), the receiver path has just been read, and
    `e5 <u16>` names the method because a member access or an enclosing method
    call follows. EVERY node now on `stack` is therefore this call's argument;
    the completed value closes its group implicitly (see _GroupDone).

    recv is the already-resolved receiver name list (system-object root riding
    verbatim, e.g. ['_SCREEN', 'A']). Only ever called with member_callee_tail
    semantics (inside a 43-group segment), so the exception lands in _dec_group.
    """
    if j + 3 > end:
        raise Unsupported("mid-chain method token truncated")
    # ZERO arguments is a measured shape (s2 '_SCREEN.Foo().Bar', oracle
    # round27_streams.json): the e5 follows the receiver run directly. Only
    # the generic-MEMBER hook gates on a non-empty stack (the single value is
    # that call's argument — FIELDS(1).COLOR rides exactly this shape), while
    # array-element receivers keep the e5 arm in _dec_expr and zero-argument
    # links keep the chain decoder.
    name = _sym(syms, S.u16(buf, j + 1))
    j += 3
    args = list(stack)
    stack.clear()
    # Round-40 lane C: measured continuation ONE generalises from a single
    # terminal property read to a member PATH — `(f4 <hop>)+ f7 <prop>` — the
    # same tail the f4-run reader (_dec_path) accepts everywhere else. The
    # completed value is then a chain, not a MidCall (which carries exactly one
    # prop), so it rides the existing ObjectChain node. Corpus-forced on
    # foxchartsbeta.vcx::foxcharts toword stmts #73/#74 (both artifact copies,
    # 4 carriers): '54 f70d00 10 fc 43 00 f50df70e00 f80101 f50df40f00 e53900
    # f43400 f73a00' <-> stored 'lnStart = m.loTable.Cell(m.lnStartRows,1).
    # Range.Start', and the lnEnd twin with an additive subscript. Indices are
    # bounds-checked BEFORE any symbol is resolved, so this arm never fabricates
    # a chain over a symbol the table does not have; an out-of-range id falls
    # through to the readers below, which name it exactly ('symbol index N
    # beyond table') the same way the C1 hop run one arm over does. Reached 20
    # times over all 13,551 corpus sections in all three splits; the bounds
    # check has never yet failed on a real stream.
    hop_at = []
    k = j
    while k + 3 <= end and buf[k] == S.MEMBER:
        hop_at.append(k)
        k += 3
    if hop_at and k + 3 <= end and buf[k] == S.SYM:
        ids = [S.u16(buf, h + 1) for h in hop_at] + [S.u16(buf, k + 1)]
        if max(ids) < len(syms):
            raise _GroupDone(
                ObjectChain(list(recv), [(name, args)],
                            [_sym(syms, x) for x in ids]), k + 3)
    prop = None
    if j + 3 <= end and buf[j] == S.SYM:
        # measured continuation one: ONE terminal property read (s2 `.BAR`,
        # w1 `.NAME`, w2 `.CNTPREVIEWER`, r3a `.INNERHTML`)
        prop = _sym(syms, S.u16(buf, j + 1))
        j += 3
    elif not (j + 3 <= end and buf[j] == S.NAME):
        # r40 group43 continuation three, RETRY-PASS ONLY: the call value
        # continues into a longer chain — a member run before its terminal
        # property read, and/or a further e5 link whose arguments live in the
        # enclosing 43 frame. `_dec_chain_continue` always leaves through one
        # of its three measured exits, so an unmeasured tail still lands on
        # the historical rejection below with its wording unchanged.
        if _EXPR_RETRY_ACTIVE:
            try:
                node, k = _dec_chain_continue(
                    buf, j, end, syms,
                    ObjectChain(list(recv), [(name, list(args))], []))
            except Unsupported as ce:
                # only the reader's OWN decline restores the historical
                # wording; a real fault it found (an operand index beyond the
                # symbol table) keeps its own diagnostic, exactly as before.
                if str(ce) != "chain link continuation unmeasured":
                    raise
                raise Unsupported(
                    "prop-less mid-chain call without its f6 consumer") \
                    from None
            raise _GroupDone(node, k)
        # measured continuation two: the value feeds an enclosing f6 callee
        # (r5 nesting) and NOTHING else. The terminal-call spelling proper
        # is f6 (s1/s7), so an e5 at EOF or before any other token has no
        # measured consumer and stays Unsupported rather than emitting a
        # call the stream never asked for.
        raise Unsupported(
            "prop-less mid-chain call without its f6 consumer")
    # otherwise the call value itself feeds an enclosing f6 receiver or ends the
    # group (r5: inner group ends at e50200 with the outer f60400 next); any
    # OTHER tail is judged by the enclosing context, never consumed here.
    raise _GroupDone(MidCall(recv, name, args, prop), j)


def _dec_chain_continue(buf, j, end, syms, node):
    """Round-40 group43 — the tail that follows one args-before call link.

        f4 <hop>* ( f7 <terminal>  |  f6 <name>  |  e5 <method> )

    Measured on the eight group43 carrier sections against their stored
    METHODS sources; every emitted line below is the stored line verbatim
    modulo the symbol table's uppercasing:

      f7 terminal, hops>=1
        `43 00 f7<tcTempPath> f4<loShell> e5<NameSpace> f4<Items> f7<Count>`
        <-> 'lnCountBefore = loShell.NameSpace(tcTempPath).Items.Count'
        (VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx unzipfile L359; twin at L1904
        'lnCntTot = loShell.NameSpace(lcZipName).Items.Count'; translate.scx::
        frmDaily 'mg = oMyVar.shapes(c1).GroupItems.count' and
        'xxx = oExcel.Worksheets(oMyVar.Name).Shapes.count').
      f6 name, hops>=1
        `… e5<Item> f4<ChildNodes> f6<Item>` closing the enclosing frame
        <-> 'loNode = loNodes.Item(lnNode).ChildNodes.Item(lnCnt)'
        (readstylesxml L2424).
      e5 method, hops 0 or more
        `… e5<shapes> e5<GroupItems> f7<HasTextFrame>`
        <-> 'IF oMyVar.shapes(c1).GroupItems(T1).HasTextFrame = -1'
        (translate.scx::frmDaily); `… e5<Item> f4<ChildNodes> e5<Item>
        f4<Attributes> e5<Item> f7<NodeTypedValue>` <-> readstylesxml L2465.

    Returns (node, next_i) when the chain COMPLETES on its terminal property
    read; raises _ChainOpen when the next link needs the enclosing frame's
    operands (see that class). Any other follower — and any pending link at
    group depth < 2, where no enclosing frame exists to hold its arguments —
    rejects, so the arm can never become a catch-all."""
    hops = []
    while j + 3 <= end and buf[j] == S.MEMBER:
        hops.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if j + 3 <= end and buf[j] == S.SYM:
        node.tail = list(node.tail) + hops + [_sym(syms, S.u16(buf, j + 1))]
        return node, j + 3
    if j + 3 <= end and buf[j] in (S.NAME, S.ARRAY_ELEM_CALL) \
            and _GROUP_DEPTH >= 2:
        raise _ChainOpen(node, hops, j)
    raise Unsupported("chain link continuation unmeasured")


def _dec_chain_link(buf, co, end, syms, stack):
    """Round-40 group43 — consume the pending link of an open chain (_ChainOpen)
    using THIS segment's operands as that link's argument list.

    `stack` is the enclosing 43 frame's live operand segment; the args-before
    convention makes every value standing on it this link's arguments, exactly
    as `_dec_args_first_call` reads them one frame in. Two exits:

      f6 <name>  the chain is the RECEIVER of the enclosing group's TERMINAL
                 call: leave the closer byte for _dec_group_run's NAME arm
                 (which collects the whole group stack, not just this segment)
                 and hand it a ChainRecv.
      e5 <method>  one more chain link; its own tail is read straight away and
                 may itself raise _ChainOpen for the next frame out.
    """
    j = co.pos
    if buf[j] == S.NAME:
        return ChainRecv(co.node, list(co.hops)), j
    name = _sym(syms, S.u16(buf, j + 1))
    args = list(stack)
    stack.clear()
    node = ObjectChain([co.node] + list(co.hops), [(name, args)], [])
    return _dec_chain_continue(buf, j + 3, end, syms, node)


def _bare_arity_admits(byte, stack):
    """Whether the current argument stack satisfies a measured bare callee.

    Round-14 proved that the callee is always the final byte of its group, so
    bytes after it belong to the enclosing expression and need no lookahead.
    Registry-only bare ids always have a parseable arity before reaching here.
    """
    bounds = S.parse_arity(S.ARITY.get(("bare", byte)))
    if bounds is None:
        return False
    lo, hi = bounds
    return lo <= len(stack) <= hi


def _dec_chain_group(buf, i, end, syms):
    """Round37 P8 (C09/G5 multi-link call-value chains; retry pass ONLY).
    Measured on oracle canaries c05/c11/c12/c13 (round37_streams.json G1/G5)
    and corpus carrier VFPxWorkbookXLSX::vfpxworkbookxlsx stmt 8
    ('loNodes.Item(lnNode).getElementsByTagName("t").Item(0).nodeTypedValue'):

        43 <packets>+ <f4 root-run> e5 <link>+ (f6 <term> | f7 <prop>)

    Each PACKET is one positional argument source, read left-to-right:
      - loose literal/symbol:        f8 <w> <v>   |   f7 <u16>
      - framed single argument:      43 [00] (f8 | d9-str | f7)
      - empty frame / barrier:       43 <anything else>   (consumes nothing)

    Binding is REVERSED against the wire's link order with barriers skipped
    (validated on every measured stream: the LAST packet feeds the FIRST
    link; c13 'ox.GetItem("t").Item(lnN)' pairs its packets ['t'],lnN as
    GetItem("t"), Item(lnN)). The number of non-empty packets MUST equal the
    number of consumers (links + an f6 terminal); a post-link f4 hop before
    the terminal (ff363bb95a04845a twins) is NOT part of this grammar and
    declines. Returns ObjectChain or raises Unsupported."""
    j = i + 1
    packets = []                    # each: [ast] (non-empty) or [] (barrier)
    while j < end:
        if buf[j] == 0x00:
            # ByVal marker riding before a variable argument (round-27
            # grammar, c13 'Item(lnN)' carrier); it emits nothing.
            j += 1
            continue
        b = buf[j]
        if b == S.CALL_OPEN:
            j += 1
            if j < end and buf[j] == 0x00:
                j += 1              # ByVal marker rides unemitted (r27 grammar)
            inner = None
            if j + 3 <= end and buf[j] == S.INT8:
                inner, j = (Num(str(buf[j + 2]), op=S.INT8,
                                width=buf[j + 1]), j + 3)
            elif j + 3 <= end and buf[j] == S.SYM:
                inner, j = Sym(_sym(syms, S.u16(buf, j + 1))), j + 3
            elif j + 3 <= end and buf[j] == S.STR2:
                ln = S.u16(buf, j + 1)
                if j + 3 + ln > end:
                    raise Unsupported("chain group frame string truncated")
                raw = buf[j + 3:j + 3 + ln]
                inner, j = Str(_payload_text(raw), dq=True), j + 3 + ln
            packets.append([inner] if inner is not None else [])
            continue
        if b == S.INT8 and j + 3 <= end:
            packets.append([Num(str(buf[j + 2]), op=S.INT8,
                                width=buf[j + 1])])
            j += 3
            continue
        if b == S.SYM and j + 3 <= end:
            packets.append([Sym(_sym(syms, S.u16(buf, j + 1)))])
            j += 3
            continue
        break
    recv = []
    while j + 3 <= end and buf[j] == S.MEMBER:
        recv.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if not recv or not packets:
        raise Unsupported("chain group without packets or receiver")
    links = []
    while j + 3 <= end and buf[j] == S.ARRAY_ELEM_CALL:
        links.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if not links:
        raise Unsupported("chain group without links")
    term = None
    tail_prop = None
    if j + 3 <= end and buf[j] == S.NAME:
        term = _sym(syms, S.u16(buf, j + 1))
        j += 3
    elif j + 3 <= end and buf[j] == S.SYM:
        tail_prop = _sym(syms, S.u16(buf, j + 1))
        j += 3
    else:
        raise Unsupported("chain group without terminal")
    if j != end:
        raise Unsupported("chain group trailing bytes")
    consumers = links + ([term] if term is not None else [])
    filled = [p[0] for p in packets if p]
    if len(filled) != len(consumers) or len(consumers) > len(packets):
        raise Unsupported("chain group packet binding mismatch")
    calls = [(nm, [filled[len(filled) - 1 - k]])
             for k, nm in enumerate(consumers)]
    node = ObjectChain(recv, calls,
                       [tail_prop] if tail_prop is not None else [])
    return node, j                     # j == end (strict statement-final form)


def _dec_group(buf, i, end, syms, opens_first_packet=False):
    """43-group: operands accumulate on one stack (binops included — FILE(GETENV(..)+..)),
    and a closer token names the callee: f6 <u16> user name, ea/x1a <u8> builtin escape,
    a bare one-byte builtin id, or 47 modulus. EA19 and EB prefix by-reference arguments.
    A user callee preceded by a MemberPath is a METHOD call on that object path.

    Round-33: the window stack registers in _ARENA like every segment stack (see
    the arena note above `_dec_expr`), so a retry-pass operator may pull operands
    that live here, and this loop's fd peek (below) closes wrapper groups."""
    global _GROUP_DEPTH
    stack = []
    _ARENA.append(stack)
    _GROUP_DEPTH += 1
    try:
        return _dec_group_run(buf, i, end, syms, stack,
                              opens_first_packet=opens_first_packet)
    finally:
        _GROUP_DEPTH -= 1
        _ARENA.pop()


def _dec_group_run(buf, i, end, syms, stack, opens_first_packet=False):
    pending_marker = None
    byref_close_pending = False   # r38 a0004: '@arr(sub)' awaiting its f6 close
    j = i + 1
    while True:
        if j >= end:
            if pending_marker is not None:
                raise Unsupported(f"{pending_marker} argument marker without operand")
            # an array-bracket closer (cd) can terminate the group itself;
            # a lone resulting node ends the group cleanly (iter. 46) -- but an
            # empty-argument slot is only ever an ELEMENT of an argument list,
            # so a truncated stream that stops on one must reject, never emit
            if len(stack) == 1 and not isinstance(stack[0], EmptyArg):
                # r54-selnointo: record that a 43 packet ended because the
                # WINDOW ran out rather than on a closer of its own. A SQL
                # clause group whose closer is reader-stripped at statement end
                # cannot tell the two apart on its own, and a packet that
                # closed this way is a truncation, not a stripped closer.
                global _GROUP_EOW_CLOSE
                _GROUP_EOW_CLOSE = True
                return stack[0], j
            raise Unsupported("unterminated 43 group")
        peek = buf[j]
        if peek == S.FD and _EXPR_RETRY_ACTIVE:
            # fdclose: the statement's expression terminator reached while this
            # group is still open closes it iff exactly ONE value stands (the
            # wrapper-group form 'IF VARTYPE(m.laPoints(m.n-1)) = "L"',
            # 04cea6515394fcec:64 <-> stored METHODS). Anything else stays
            # rejected -- never dropped silently (faa199b32ddf0b1c:65 keeps its
            # blocked status under this arm).
            if len(stack) == 1 and not isinstance(stack[0], EmptyArg):
                return stack[0], j
            raise Unsupported("unterminated 43 group")
        if peek == S.ESCAPE and j + 2 <= end and buf[j + 1] == S.EA_BYREF_ID:
            if pending_marker is not None:
                raise Unsupported("consecutive argument markers")
            pending_marker = "ea19"
            j += 2
            continue
        if peek == S.BARE_BYREF:
            if pending_marker is not None:
                raise Unsupported("consecutive argument markers")
            pending_marker = "eb"
            j += 1
            continue
        if peek == S.EMPTY_ARG:
            # Round-22: ONE db per omitted comma slot, position-independent —
            # leading pair (d2), middle (d3) and trailing (d4) all measured;
            # direct var args keep their ByVal 00 prefixes inside their own
            # operand segments. Pushes an empty-slot placeholder so emission
            # keeps every omitted slot's comma. db is only ever peeked at
            # segment boundaries here (inside an operand segment the generic
            # expression dispatch still rejects it), which is exactly the
            # measured grammar.
            if pending_marker is not None:
                raise Unsupported("argument marker without operand")
            stack.append(EmptyArg())
            j += 1
            continue
        if pending_marker is not None and peek in _GROUP_CLOSERS:
            raise Unsupported(f"{pending_marker} argument marker without operand")
        if peek == S.NAME:
            if j + 3 > end:
                raise Unsupported("user callee truncated")
            name = _sym(syms, S.u16(buf, j + 1))
            if stack and isinstance(stack[-1], MidCall) \
                    and stack[-1].prop is None:
                # r5 nesting: a prop-less mid-chain call VALUE feeds this
                # outer f6 as its RECEIVER ('m.loA.B(m.x).C(m.y)'); the
                # emitter renders the nested node inside recv.
                mid = stack.pop()
                return MethodCall([mid], name, stack), j + 3
            if (len(stack) == 1 and isinstance(stack[-1], ArrayElement)
                    and stack[-1].method_receiver):
                recv = stack.pop()
                recv.method_receiver = False
                return MethodCall([recv], name, stack), j + 3
            if (stack and isinstance(stack[-1], ArrayElement)
                    and stack[-1].method_receiver):
                raise Unsupported("array-element method arguments unmeasured")
            if stack and isinstance(stack[-1], ChainRecv):
                # r40 group43: the receiver's ROOT is a completed args-before
                # chain value ('loNodes.Item(lnNode).ChildNodes' before the f6
                # Item closer, readstylesxml L2424); everything below it on
                # this group's stack is still this call's argument list.
                recv = stack.pop()
                return MethodCall([recv.node] + list(recv.hops),
                                  name, stack), j + 3
            if stack and isinstance(stack[-1], (MemberPath, WithMemberPath)) \
                    and stack[-1].receiver:
                # ONLY the receiver-shaped run (no terminal f7) is this call's
                # object. A path that DID terminate in f7 is a value and stays
                # in `stack` as the call's last argument — MemberPath.receiver
                # carries the oracle-measured discriminator. Without the flag
                # 'apiSetfocus(Thisform.HWnd)' (43 f4 f7 f6) was emitted
                # 'Thisform.HWnd.apiSetfocus()', which is the OTHER stream
                # (43 f4 f4 f6): valid FoxPro that calls something else.
                recv = stack.pop()
                withp = isinstance(recv, WithMemberPath)
                return MethodCall(recv.names, name, stack, recv_with=withp), j + 3
            if byref_close_pending:
                # r38 M3/a0004: this group is the measured nested
                # array-element form '@arr(subscript)' — its 18 rode directly
                # before THIS f6. Wrap so emission spells '@arr(sub)'; the
                # paren '@(' and bare '@' forms are compiler-rejected
                # (a0005/a0006) and never synthesized.
                return ByrefCall(("user", name), stack), j + 3
            if stack and isinstance(stack[-1], ObjectChain):
                # r48-callchain: `o.a.b().c()` is
                # `43 43 <c-args> <b-args> <hops> e5 <B> f6 <C>`. The inner
                # call closes with e5 BECAUSE its value is the receiver of the
                # next call — an argument-position call closes with f6
                # instead, measured on `ALLTRIM(o.p.q())` and
                # `STRTRAN(o.p.q(), a)`, which both carry `f6 Q`. So an
                # e5-closed chain standing under an f6 user callee is that
                # call's RECEIVER. Read as a plain callee it became
                # `C(o.a.b())`, valid FoxPro that calls something else.
                #
                # Whose arguments the operands below it are is decided by the
                # inner call's own 43 frame, which PRECEDES them: `o.a.b(1).c()`
                # is `43 43 <1> <hops> e5 B f6 C` and `o.a.b().c(2)` is
                # `43 <2> 43 <hops> e5 B f6 C`. The second shape never reaches
                # here — its outer argument keeps the group on the measured
                # MidCall path — so an operand run standing under a chain whose
                # last call took NO arguments is that call's argument list.
                recv = stack.pop()
                args = list(stack)
                calls = list(recv.calls)
                if args and calls and not calls[-1][1]:
                    calls[-1] = (calls[-1][0], args)
                    args = []
                inner = ObjectChain(recv.recv, calls, [],
                                    list(recv.call_brackets))
                return MethodCall([inner] + list(recv.tail), name, args), j + 3
            return Call(("user", name), stack), j + 3
        if peek == S.ESCAPE:
            if j + 2 > end:
                raise Unsupported("ea callee truncated")
            ident = buf[j + 1]
            if _SQL_AGG_SCOPE and ident in S.SQLSEL_AGG and len(stack) == 1:
                # r48-sqlproj: inside a SELECT projection column an
                # `ea <agg-id>` closes ITS 43 group as the aggregate wherever
                # it sits — `INT(SUM(f))` is `43 43 <f> ea fa 38`, so the
                # column group ends with the OUTER callee and the top-of-group
                # reader never matched. The ids collide with ordinary ea
                # builtins, so the arm is SQL-local and takes exactly the one
                # operand an aggregate has.
                return SqlAgg(S.SQLSEL_AGG[ident], _emit(stack[0])), j + 2
            if ident not in S.BUILTIN_ESCAPES:
                raise Unsupported(f"ea builtin callee 0x{ident:02x} unmapped")
            bounds = S.MEASURED_EA_GROUP_CLOSERS.get(ident)
            if bounds is not None and not bounds[0] <= len(stack) <= bounds[1]:
                # r42-msgbox: MESSAGEBOX operand count is the emission arity.
                raise Unsupported(
                    "ea 0x%02X arity rejected at %d args" % (ident, len(stack)))
            return Call(("builtin", ident), stack), j + 2
        if peek == S.X1A_ESCAPE:
            if j + 2 > end:
                raise Unsupported("x1a callee truncated")
            ident = buf[j + 1]
            if ident not in S.BUILTIN_X1A:
                raise Unsupported(f"x1a builtin callee 0x{ident:02x} unmapped")
            if ident == 0x0F:
                # r42-cast: extra INT8 width groups (Q(n), C(n), N(w,d), …)
                # fold here so RETURN/IF/IIF see the same envelope as ASSIGN.
                _fold_cast_args(stack)
            return Call(("x1a_builtin", ident), stack), j + 2
        if peek == S.MOD_APPLY:
            if len(stack) != 2:
                raise Unsupported("modulus operand count")
            return Mod(stack[0], stack[1]), j + 1
        if peek == S.SQL_LIKE_MARK:
            # r73-like: `43 <lhs> <rhs> cf` is `lhs LIKE rhs`. The round-34
            # WHERE matrix already binds SYM SYM; ALLTRIM / UPPER / concat /
            # string-literal operands close here. Two operands, always.
            if len(stack) != 2:
                raise Unsupported("LIKE operand count")
            return Bin("LIKE", stack[0], stack[1]), j + 1
        if peek in S.MEASURED_LOCAL_GROUP_CLOSERS:
            # Corpus-gated bare closers: the IDENTITY is oracle-measured
            # (registry.BARE_IDS via function_ids.json), the ARGUMENT COUNT is
            # the corpus-mined gate this table adds (schemas provenance). The
            # name is read from the generated registry at point of use so the
            # two can never disagree (ALEN-defect class); emitted through the
            # same bare_builtin namespace as every other bare closer.
            lo, hi = S.MEASURED_LOCAL_GROUP_CLOSERS[peek]
            if not lo <= len(stack) <= hi:
                raise Unsupported(
                    "bare 0x%02X arity rejected at %d args" % (peek, len(stack)))
            return Call(("bare_builtin", peek), stack), j + 1
        if peek in S.CORPUS_ALIGNED_BARE_CLOSERS:
            # Corpus-aligned unconditional close. Gating these through the
            # registry arity measured -2 (453/618): several pinned grammars use
            # counts the oracle snippets did not enumerate. Byte-agreement with
            # the registry is enforced in schemas.test_registry_agreement.
            return Call(("bare_builtin", peek), stack), j + 1
        if peek in _ENABLE_EXTRA_BARE:
            if _bare_arity_admits(peek, stack):
                return Call(("bare_builtin", peek), stack), j + 1
            raise Unsupported(
                "bare 0x%02X arity rejected at %d args" % (peek, len(stack)))
        if peek == S.WITHREF and j + 4 <= end \
                and buf[j + 1] == S.ARRAY_ELEM_CALL:
            # round-28 W3: WITH-scoped indexed-member VALUE read inside a group,
            # args-before spelling (same convention as the round-27 system-object
            # pivot): <args> e2 e5 <M> [f7 <prop>] — every value already on the
            # stack is this call's argument list and the WITH object is the
            # implicit receiver. Corpus alignment foxcharts::foxcharts s82[43]
            # 'm.lcValue1 = .Fields(1).FieldValue' =
            # 54 f50df70900 10 fc 43 f80101 e2e51300 f71500. An argument marker
            # still awaiting its operand has no measured pivot shape and rejects.
            if pending_marker is not None:
                raise Unsupported(
                    f"{pending_marker} argument marker without operand")
            name = _sym(syms, S.u16(buf, j + 2))
            j += 4
            args = list(stack)
            stack.clear()
            prop = None
            if j + 3 <= end and buf[j] == S.SYM:
                prop = _sym(syms, S.u16(buf, j + 1))
                j += 3
                # r35-A: a group-level pivot that reads its TERMINAL PROPERTY
                # is the same measured construct as the expression-level pivot
                # (round-28 W3 alignment 'm.lcValue1 = .Fields(1).FieldValue'),
                # which closes its group implicitly via _GroupDone. This arm is
                # reached only when the pivot bytes began a fresh group-loop
                # peek (previous segment ended on a WITH-ref push), where the
                # implicit close was skipped because of WHERE the bytes were
                # consumed. Close identically; the enclosing handler keeps its
                # empty-stack / pending-marker guards. Corpus alignments:
                # foxcharts s40 stmt73 'laStack(m.lnLine,7) = IIF(.Fields(
                # ._ChartIndex).Bartype<0, .Bartype, .Fields(._ChartIndex).
                # Bartype)' and its twins.
                raise _GroupDone(MidCall([""], name, args, prop), j)
            stack.append(MidCall([""], name, args, prop))
            pending_marker = None
            continue
        if peek == S.WITHREF:
            node, j = _dec_withref(buf, j, end, syms, allow_callee_tail=True)
            stack.append(node)
            pending_marker = None
            continue
        if peek == 0xE0 and stack:
            # array-bracket access: pop receiver, collect ARGJOIN-joined
            # subscripts until the cd closer ('a[x,y]' iter. 46)
            base = stack.pop()
            j += 1
            subs = []
            while True:
                if j >= end:
                    raise Unsupported("array subscript unterminated")
                if buf[j] == 0xCD:
                    j += 1
                    break
                es2, k2 = _dec_expr(buf, j, end, syms,
                                    stop_bytes=frozenset({S.FD, 0xCD, S.ARGJOIN}))
                if len(es2) != 1:
                    raise Unsupported("array subscript unresolved")
                subs.append(es2[0])
                j = k2
                if j < end and buf[j] == S.ARGJOIN:
                    j += 1
                    continue
                if j < end and buf[j] == 0xCD:
                    j += 1
                    break
                raise Unsupported("array subscript tail")
            stack.append(ArrayElement(base, subs))
            continue
        try:
            segment, j = _dec_expr(
                buf, j, end, syms,
                # fdclose retry pass: an operand segment may also stop at the
                # statement's fd, handing control to the peek-close above.
                stop_bytes=(_GROUP_CLOSERS | {S.EMPTY_ARG, S.FD})
                if _EXPR_RETRY_ACTIVE else (_GROUP_CLOSERS | {S.EMPTY_ARG}),
                member_callee_tail=True,
                # r49-residual: this group's FIRST segment, when it opens
                # another 43, is the doubled-opener packet
                packet=((_PACKET_INSIDE_FIRST if opens_first_packet else 0)
                        | (_PACKET_OPENS_FIRST if j == i + 1 else 0)))
        except _GroupDone as gd:
            # round-27 implicit group close: an args-before-receiver chain
            # completes AND ends its group in one step (_GroupDone docstring),
            # so the group's value IS the MidCall and decoding resumes at
            # gd.pos in the ENCLOSING expression (w1: the IF comparison).
            # The pivot consumed every segment value as its arguments; a
            # group that still holds earlier operands, or an argument marker
            # (ea19/eb) awaiting its operand when the close lands, is
            # unmeasured — reject, never drop group state silently.
            if stack or pending_marker is not None:
                raise Unsupported(
                    "mid-chain close with pending group state")
            return gd.node, gd.pos
        except _ChainOpen:
            # r40 group43: the chain link that just completed leaves THIS
            # frame entirely — its arguments were this frame's operands and
            # the next link takes the enclosing frame's. Same boundary as the
            # _GroupDone close above: any operand this frame still holds, or
            # an argument marker awaiting its operand, is unmeasured.
            if stack or pending_marker is not None:
                raise Unsupported(
                    "mid-chain close with pending group state") from None
            raise
        except _MemArrayClose as mc:
            # round-30 memvar-array element READ: the closing ref names the
            # array, the group's accumulated operands are its subscripts
            # (args-first, same convention as every closer namespace). An
            # argument marker (ea19/eb) still awaiting its operand at close
            # time has no measured shape — reject, never drop group state.
            if pending_marker is not None:
                raise Unsupported(
                    f"{pending_marker} argument marker without operand") from None
            return ArrayRef("m." + mc.name, stack + mc.partial), mc.pos
        if not segment:
            raise Unsupported("43 group operand unresolved")
        stack.extend(segment)
        pending_marker = None
        if _ARG_BYREF_CLOSE:
            # r38 M3/a0004: the segment that just returned ended on '18' with
            # the f6 group closer as its stop byte ('@arr(subscript)'). The
            # NEXT plain user-name close builds this group's call; mark it.
            _reset_arg_byref_close()
            byref_close_pending = True


# ---------- lvalues ------------------------------------------------------------------------------
def _dec_lvalue(buf, i, end, syms):
    op = buf[i]
    if op == S.SYSVAR_READ and i + 2 <= end and buf[i + 1] in S.SYSTEM_VARS:
        # r40-H: a system variable is also a PUT target, spelled with the same
        # two bytes it reads as — `54 ed <id> 10 fc <value>`. Oracle probe f29
        # ('_ASCIICOLS = 80' / '_ASCIIROWS = 63') emits 54ed3e10fcf80250 /
        # 54ed3f10fcf8023f, raw-equal to _reports.vcx::_output #85/#86. The id
        # table is schemas.SYSTEM_VARS and is never guessed from frequency: an
        # id absent from it falls through to the generic lvalue rejection
        # below, keeping that diagnostic byte-identical to what it was.
        return Sym(S.SYSTEM_VARS[buf[i + 1]]), i + 2
    if op == 0xE1:
        if i + 5 <= end and buf[i + 1] == 0x43 and buf[i + 2] == S.SYM:
            # r46-autoyield: e1 43 f7 <sym> is _VFP.<prop> (SYSTEM_OBJECT_REFS
            # 0x43; same as e1 39 = _SCREEN). THIS.oHost is f4, not e1 43.
            return MemberPath([S.SYSTEM_OBJECT_REFS[0x43],
                               _sym(syms, S.u16(buf, i + 3))]), i + 5
        if i + 5 <= end and buf[i + 1] == 0x39 and buf[i + 2] == S.SYM:
            # round-27 s6 (oracle round27_streams.json), EXACT measured shape:
            # '_SCREEN.Caption = "x"' compiles the PUT target as e1 39 f7 <term>
            # — a single rooted hop. Hop forms and other ids under this opener
            # are unmeasured and stay Unsupported (fall through to the opcode
            # rejection below); do not broaden without a fresh measurement.
            return MemberPath([S.SYSTEM_OBJECT_REFS[0x39],
                               _sym(syms, S.u16(buf, i + 3))]), i + 5
        return _dec_lvalue(buf, i + 1, end, syms)
    if op == S.ARRAY_ELEM_CALL:
        # Round-28 indexed-element PUT target (see IndexedElemRef): subscripts
        # ride the shared fc..fd units joined by ARGJOIN, closed by the source's
        # own bracket marker; ONE optional terminal property read follows.
        if i + 3 > end:
            raise Unsupported("array-element receiver truncated")
        nm = _sym(syms, S.u16(buf, i + 1))
        j = i + 3
        subs = []
        bracket = False
        while True:
            if j >= end or buf[j] != S.FC:
                raise Unsupported("array-element subscript shape")
            es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("array-element subscript unresolved")
            subs.append(es[0])
            j = k + 1
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            if j < end and buf[j] in (S.PAREN, 0x16):
                bracket = buf[j] == 0x16
                j += 1
                break
            raise Unsupported("array-element subscript list tail")
        prop = None
        if j + 3 <= end and buf[j] == S.SYM:
            prop = _sym(syms, S.u16(buf, j + 1))
            j += 3
        return IndexedElemRef(nm, subs, prop=prop, bracket=bracket), j
    if op == S.FC:
        # Round-28 grouped name-expression target: '( … )' around an indirect
        # NAME in lvalue position. Measured carriers —
        #   STORE  '4a fc f70600 fd 28 fc f50df70f0003'
        #        = STORE m.loRef TO (m.lcVariableName)   (xfrxlib xfcont stmt19;
        #          xfrxtlbobject stmt2 'TO ("THIS."+m.lcName+".Value")')
        #   REPLACE '3e fc <name-expr> fd d1 …' field-name position
        #        (foxcharts.vcx sec94 stmt13 'REPLACE (m.lcSource + "." + …)')
        # The closing 03 is the shared PAREN postfix: statement-final groups
        # lose their fd to reader stripping and the postfix lands INSIDE the
        # decoded node (same framing as dec_set_value's grouped spelling); an
        # explicit `fd 03` tail is accepted for non-final positions. Anything
        # else stays rejected — a bare expression is not a measured name form.
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("paren-name lvalue unresolved")
        # the 03 PAREN postfix lands INSIDE the group ('fc <expr> 03 [fd]',
        # foxcharts sec94 stmt13 keeps its explicit fd before the d1 WITH
        # marker); statement-final groups stop right at end-of-stream
        if not isinstance(es[0], Paren):
            raise Unsupported("lvalue opcode 0xfc")
        if k < end and buf[k] == S.FD:
            k += 1
        return es[0], k
    if op == 0xED:
        # System-variable PUT target: ed <id> with a KNOWN id only
        # (schemas.SYSTEM_VARS; the read side already decodes ed <id> in
        # _dec_operand — oracle round-21 bound '_cliptext' to ed 1d). Corpus
        # carriers are _CLIPTEXT writes: '54 ed 1d 10 fc <expr>' =
        # _CLIPTEXT = <expr>. Unknown ids keep the opcode rejection below —
        # round-35 grew the shared table by the corpus-forced reads
        # 0x32 _DOS / 0x33 _MAC / 0x34 _UNIX (provenance on schemas.SYSTEM_VARS),
        # which enables their PUT forms through this same arm.
        if i + 2 <= end and buf[i + 1] in S.SYSTEM_VARS:
            return Sym(S.SYSTEM_VARS[buf[i + 1]]), i + 2
        raise Unsupported(f"lvalue opcode {op:#04x}")
    if op == S.WITHREF:
        if i + 4 <= end and buf[i + 1] == S.ARRAY_ELEM_CALL:
            # round-28 W3: WITH-scoped member named by the e5 call opener as a
            # PUT target — '54 e2 e5 <M> fc <args> fd 03 [...] 10 fc <rhs>'
            # (= .M(args)[.Prop] = rhs; census x180+ aligned to stored sources,
            # e.g. dashboard::Optiongroup4 '.FIELDS(1).FIELDVALUE = PXX').
            # The FC-call-form continuation in the ASSIGN reader takes it from
            # here; any other follower fails there, never silently.
            return WithMemberPath([_sym(syms, S.u16(buf, i + 2))]), i + 4
        if _EXPR_RETRY_ACTIVE and i + 4 <= end and buf[i + 1] == S.MEMBER:
            # Round37 P8 (C09/G3 deep puts on the ROOTED opener spelling,
            # retry pass only; managecode::CmdSave stmts 26/27
            # '.Tree.Nodes(VAL(.Tree.Tag)).Tag=…', dashboard::frmcontrol
            # stmts 226/227): 'e2 <f4 hop>+ e5 <M>' — one or more root hops
            # ride BEFORE the e5 opener. The FC-call-form continuation in
            # the ASSIGN reader consumes the subscript units from here;
            # chain_call marks the node so the put builder renders the full
            # scoped run. The stock unrooted opener above stays untouched.
            j2 = i + 1
            hops2 = []
            while j2 + 3 <= end and buf[j2] == S.MEMBER:
                hops2.append(_sym(syms, S.u16(buf, j2 + 1)))
                j2 += 3
            if j2 + 3 <= end and buf[j2] == S.ARRAY_ELEM_CALL:
                return WithMemberPath(
                    hops2 + [_sym(syms, S.u16(buf, j2 + 1))],
                    chain_call=True), j2 + 3
        # WITH-scoped target: e2 [f4-run] NAME — terminal NAME consumed here so
        # both '.x.y =' assignments and the 54-call-form resolve (iter. 35).
        node, j = _dec_withref(buf, i, end, syms, allow_callee_tail=True)
        if isinstance(node, WithMemberPath) and j < end and buf[j] == S.NAME:
            names = list(node.names)
            names.append(_sym(syms, S.u16(buf, j + 1)))
            return WithMemberPath(names), j + 3
        if isinstance(node, (WithRef, WithMemberPath)):
            return node, j
        raise Unsupported(f"lvalue opcode {op:#04x}")
    if op == S.SYM:
        return Sym(_sym(syms, S.u16(buf, i + 1))), i + 3
    if op == S.WORKAREA_REF and i + 5 <= end and buf[i + 1] == 0x0D \
            and buf[i + 2] == S.SYM:
        # m.<name> = expr — assignment target in memvar space (forced: _reportlistener)
        return MemvarRef(_sym(syms, S.u16(buf, i + 3))), i + 5
    if op == S.WORKAREA_REF and i + 8 <= end and buf[i + 1] == 0x0D \
            and buf[i + 2] == S.NAME and buf[i + 5] == S.FC:
        # Round-28 memvar-array target: 'm.laX(i) = …' ->
        # f5 0d f6 <arr> <subscript-list> (the dominant residual lvalue form:
        # '54 f5 0d f6 ..' x96+68+44+40 across the foxcharts family; DIMENSION
        # twin '15 f50df60700 fc..fd03' foxcharts sec63 stmt87). Subscript units
        # ride the shared fc..fd/ARGJOIN grammar closed by the source's own
        # bracket marker; bounds-check before every read.
        nm = _sym(syms, S.u16(buf, i + 3))
        j = i + 5
        subs = []
        bracket = False
        while True:
            if j >= end or buf[j] != S.FC:
                raise Unsupported("memvar-array subscript shape")
            es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("memvar-array subscript unresolved")
            subs.append(es[0])
            j = k + 1
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            if j < end and buf[j] in (S.PAREN, 0x16):
                bracket = buf[j] == 0x16
                j += 1
                break
            raise Unsupported("memvar-array subscript list tail")
        return ArrayRef("m." + nm, subs, bracket=bracket), j
    if op == S.WORKAREA_REF and i + 5 <= end and buf[i + 1] == 0x0D \
            and buf[i + 2] == S.MEMBER:
        # m.<var>[.hop...].<prop> = expr — the round-19 alias-M run (ONE value,
        # f4 hops under a single f5 0d, terminal f7) as an assignment TARGET.
        # Bounds-checked reads throughout; unmeasured tails stay Unsupported.
        hops = []
        j = i + 2
        while j + 3 <= end and buf[j] == S.MEMBER:
            hops.append(_sym(syms, S.u16(buf, j + 1)))
            j += 3
        if j < end and buf[j] == S.SYM:
            hops.append(_sym(syms, S.u16(buf, j + 1)))
            return MemberPath(["m." + hops[0]] + hops[1:]), j + 3
        if hops and j + 4 <= end and buf[j] == S.NAME and buf[j + 3] == S.FC:
            # r50-sysapp: the memvar-rooted spelling of the deep f6 PUT target
            # the object-path arm below already reads —
            #   54 f5 0d f4<LOM> f6<ITEM> fc 1 fd 07 fc 2 fd 03 10 fc 5
            #     = m.loM.item(1, 2) = 5
            # measured against its own bare-rooted control (54 f4<LOM> f6<ITEM>
            # …, already read) and its THIS-rooted one, with one and two
            # subscripts and with an extra hop in the run. The run re-enters
            # _dec_lvalue at the f6 so there is ONE subscript grammar and the
            # recorded bracket spelling rides through; 'm.' is prefixed exactly
            # as the memvar-array arm prefixes it. A dim-less deep f6 keeps its
            # historical rejection below.
            node, j2 = _dec_lvalue(buf, j, end, syms)
            if isinstance(node, ArrayRef):
                return ArrayRef(".".join(["m." + hops[0]] + hops[1:]
                                         + [node.name]),
                                node.subs, bracket=node.bracket), j2
        if _chain_opener(buf, i + 2, end):
            # Round-28 memvar-rooted method chain target: the hop run is a
            # RECEIVER with e5 call links and a terminal property —
            #   'm.loChart.Fields(m.n).Color = …' ->
            #     f5 0d f4<LOCHART> e5<FIELDS> fc <m.n> fd 03 f7<COLOR>
            #   (foxcharts.vcx sec94 stmt17, twin Source/class carriers).
            # The plain terminal-property reading above keeps every existing
            # binding; only the measured e5-opener gap engages the chain.
            try:
                node, j2 = _dec_object_chain(buf, i + 2, end, syms)
            except Unsupported as ex:
                raise Unsupported("memvar path %s" % ex) from None
            node.recv[0] = "m." + node.recv[0]
            if not (node.calls and node.tail):
                raise Unsupported(
                    "memvar path lvalue without terminal property")
            return node, j2
        raise Unsupported("memvar path lvalue without terminal property")
    if op == S.MEMBER and i + 6 <= end and buf[i + 3] == S.NAME:
        # member.name two-token id used as an LVALUE target (assignment forms;
        # _reportlistener iter. 43) — inline parse mirrors the DIMENSION fix
        return MemberPath([_sym(syms, S.u16(buf, i + 1)),
                           _sym(syms, S.u16(buf, i + 4))]), i + 6
    if op == S.MEMBER and i + 6 <= end and buf[i + 3] == S.MEMBER:
        # The same member.name array id reached over a DEEPER object path:
        # '<f4-run> f6 <array> <subscript units>'. The single-hop spelling
        # above is the '<f4> f6' arm; a run of two or more hops fell through
        # every arm below it to _dec_path, which has no f6 terminal and died
        # 'member path without terminal property' — that is the whole blocker
        # on the DIMENSION and element-PUT statements of vfp_skins.vcx::Shape1
        # MouseMove (census key c46ffc91b5f95164:2):
        #   15 f4<THIS> f4<PARENT> f4<PARENT> f4<MENUPCONT> f6<MENUPOPU>
        #      fc <NEXTPOPUP> fd 07 fc 1 fd 16
        #      = DIMENSION THIS.PARENT.PARENT.MENUPCONT.MENUPOPU[NEXTPOPUP,1]
        #   54 <same lvalue> 10 fc 43 d9'sysmenupop' ea 4e
        #      = …MENUPOPU[NEXTPOPUP+1,1] = CREATEOBJECT("sysmenupop")
        # The subscript units are read by the f6 arm at the bottom of this
        # function — the run is re-entered at the f6 so there is ONE subscript
        # grammar, and its recorded bracket spelling rides through — and the
        # object path is prefixed onto the array's name exactly as the memvar
        # array arm prefixes 'm.'. Engages only when the run is followed by
        # 'f6 <sym> fc': a dim-less deep f6 has no measured carrier and keeps
        # its historical rejection below.
        jr = i
        hops = []
        while jr + 3 <= end and buf[jr] == S.MEMBER:
            hops.append(_sym(syms, S.u16(buf, jr + 1)))
            jr += 3
        if jr + 4 <= end and buf[jr] == S.NAME and buf[jr + 3] == S.FC:
            node, j2 = _dec_lvalue(buf, jr, end, syms)
            if isinstance(node, ArrayRef):
                return ArrayRef(".".join(hops + [node.name]), node.subs,
                                bracket=node.bracket), j2
    if op == S.MEMBER and i + 6 <= end \
            and buf[i + 3] == S.ARRAY_ELEM_CALL and buf[i + 6] == S.FC:
        # Round-22 indexed-member PUT target, byte-exact x2 (probes/oracle_harvest/
        # round22_streams.json v1/v2), generalised round-33 (readiness lane R33-4)
        # to the measured corpus chains:
        #   f4 <obj> e5 <member> fc <sub> fd [07 fc <sub> fd]* 03
        #       [f4 <hop>]* f7 <prop>
        #   -> <obj>.<member>(<subs>)[.<hop>]*.<prop> = <rhs via the standard
        #      10-fc tail>
        # Extra subscript units ride the shared fc..fd/ARGJOIN grammar
        # ('ef.Range(ef.Cells(4,1),ef.Cells(4,14)).Borders.LineStyle=-4142',
        # buyfine.scx::frmShipmentinfo stmt54 + buyreconciliations/salesyc
        # twins), and f4 member hops between the closing 03 and the terminal f7
        # bind the hop-tail shape ('This.Columns(lnRelCol).Check1.Value',
        # buyswwprint.scx::Grid1). The measured single-unit/no-hop shape keeps
        # its historical IndexedMemberRef node; anything beyond it emits the
        # existing ObjectChain shape. Engages ONLY under this identical stock
        # guard, so every non-matching lvalue keeps today's path; bounds-check
        # before every read, in evaluation order; a unit not closing with fd,
        # a missing 03, a missing terminal f7 or a foreign hop rejects.
        obj_name = _sym(syms, S.u16(buf, i + 1))
        member_name = _sym(syms, S.u16(buf, i + 4))
        # buf[i+6] == FC was checked above: it OPENS the first subscript unit,
        # whose expression therefore starts at i+7 and runs to its closing fd
        j = i + 6
        subs = []
        while True:
            if j >= end or buf[j] != S.FC:
                raise Unsupported("indexed-member subscript shape")
            ses, sk = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ses) != 1 or sk >= end or buf[sk] != S.FD:
                raise Unsupported("indexed-member subscript unresolved")
            subs.append(ses[0])
            j = sk + 1
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            break
        if j >= end or buf[j] not in (0x03, 0x16):
            raise Unsupported("indexed-member property component missing")
        bracket = buf[j] == 0x16
        j += 1
        hops = []
        while j + 3 <= end and buf[j] == S.MEMBER:
            hops.append(_sym(syms, S.u16(buf, j + 1)))
            j += 3
        if not (j + 3 <= end and buf[j] == S.SYM):
            raise Unsupported("indexed-member property component missing")
        prop = _sym(syms, S.u16(buf, j + 1))
        j += 3
        if len(subs) == 1 and not hops:
            return IndexedMemberRef(obj_name, member_name, subs[0], prop,
                                    bracket=bracket), j
        return ObjectChain([obj_name], [(member_name, subs)],
                           hops + [prop], call_brackets=[bracket]), j
    if op == S.MEMBER and _chain_opener(buf, i, end):
        # population lane PATHS: measured lvalue chains with multi-hop receivers
        # and multi-argument calls, always terminating at a property
        # ('ef.Cells(3,1).Value = …' buyfine.scx::frmShipmentinfo). Engaged only
        # when an e5 call opener follows the f4-run, so every legacy binding is
        # untouched; a chain without its terminal property stays rejected.
        try:
            node, j2 = _dec_object_chain(buf, i, end, syms)
        except Unsupported as e:
            raise Unsupported("lvalue %s" % e) from None
        if not (node.calls and node.tail):
            raise Unsupported("lvalue object-chain without terminal property")
        return node, j2
    if op == S.MEMBER:
        node, j = _dec_path(buf, i, end, syms)
        if not isinstance(node, MemberPath):
            raise Unsupported(f"lvalue opcode 0x{op:02x}")
        return node, j
    if op == S.WITHREF:
        # .name = expr assignments inside WITH blocks are canonical VFP
        node, j = _dec_withref(buf, i, end, syms)
        return node, j
    if op == S.NAME:
        name = _sym(syms, S.u16(buf, i + 1))
        i += 3
        subs = []
        if i >= end or buf[i] != S.FC:
            raise Unsupported("bare array name as lvalue")
        bracket = False
        while True:
            if buf[i] != S.FC:
                raise Unsupported("array subscript shape")
            # full-token parse (stop at the closing fd): compound subscripts are
            # measured — 'registry.vcx::RegEnumKey' stmt25 '54 f60000 fc m.x08 fd
            # 07 fc 02 fd16' spans two dims whose first is an memvar expression,
            # and foxchartsbeta sec11 stmt37 adds '+ 1' arithmetic inside one dim;
            # stop_at_one could span neither.
            es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("subscript unresolved")
            subs.append(es[0])
            i = k + 1
            if i < end and buf[i] == S.ARGJOIN:
                i += 1
                continue
            if i < end and buf[i] in (S.PAREN, 0x16):
                # closer records the source spelling ('( … )' vs '[ … ]'),
                # population-census-proven on the LOCAL dimension tail; the
                # registry/vfp_skins carriers close WITH-bracket lists with 16
                bracket = buf[i] == 0x16
                i += 1
                break
            raise Unsupported("subscript list tail")
        return ArrayRef(name, subs, bracket=bracket), i
    raise Unsupported(f"lvalue opcode 0x{op:02x}")


# ---------- statement decoding -------------------------------------------------------------------
def _fc_group(buf, t, end, syms):
    """One fc-wrapped expression whose closing fd may be reader-stripped when it
    is statement-final (round-19 framing note, re-confirmed round-24). Returns
    (expr, next_index); a stripped fd simply returns the end position."""
    if t >= end or buf[t] != S.FC:
        raise Unsupported("expected fc-wrapped expression")
    es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
    if len(es) != 1:
        raise Unsupported("expression unresolved")
    if k < end and buf[k] == S.FD:
        return es[0], k + 1
    return es[0], k


def _dec_report_name(buf, t, end, syms):
    """A REPORT FORM IN/WINDOW/NAME operand: SYM, STR, an fc-group, or absent."""
    if t + 3 <= end and buf[t] == S.SYM:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    if t < end and buf[t] in (S.STR, S.STR2):
        n = S.u16(buf, t + 1)
        if t + 3 + n > end:
            return None, t
        raw = _payload_text(buf[t + 3:t + 3 + n])
        if buf[t] == S.STR2:
            raw = '"%s"' % raw
        return raw, t + 3 + n
    if t < end and buf[t] == S.FC:
        node, t = _fc_group(buf, t, end, syms)
        return node, t
    return None, t


def _dec_report_clauses(buf, t, end, syms):
    """Walk the REPORT FORM clause bank in wire order. r69-bank."""
    clauses = []
    while t < end:
        b = buf[t]
        if b in S.REPORT_FLAG_CLAUSES:
            clauses.append(("flag", S.REPORT_FLAG_CLAUSES[b]))
            t += 1
            continue
        if b in S.REPORT_SCOPE_WORDS:
            word = S.REPORT_SCOPE_WORDS[b]
            t += 1
            count = None
            if word in S.REPORT_SCOPE_COUNTED:
                try:
                    count, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("REPORT FORM %s count unresolved" % word)
            clauses.append(("scope", (word, count)))
            continue
        if b == S.FOR_MARK:
            t += 1
            try:
                expr, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("REPORT FORM FOR unresolved")
            clauses.append(("for", expr))
            continue
        if b == S.DELETE_WHILE_MARK:
            t += 1
            try:
                expr, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("REPORT FORM WHILE unresolved")
            clauses.append(("while", expr))
            continue
        if b == S.REPORT_HEADING:
            t += 1
            try:
                expr, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("REPORT FORM HEADING unresolved")
            clauses.append(("heading", expr))
            continue
        if b == S.REPORT_RANGE:
            t += 1
            args = []
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
            elif t < end and buf[t] == S.FC:
                try:
                    expr, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("REPORT FORM RANGE unresolved")
                args.append(expr)
                if t < end and buf[t] == S.ARGJOIN:
                    t += 1
                    if t < end and buf[t] == S.FC:
                        try:
                            expr, t = _fc_group(buf, t, end, syms)
                        except Unsupported:
                            raise Unsupported("REPORT FORM RANGE unresolved")
                        args.append(expr)
            clauses.append(("range", args))
            continue
        if b == S.TO_MARK:
            t += 1
            if t < end and buf[t] == S.PRINTER_KW:
                t += 1
                prompt = t < end and buf[t] == S.REPORT_PROMPT_KW
                if prompt:
                    t += 1
                clauses.append(("to_printer", prompt))
                continue
            if t < end and buf[t] == S.REPORT_FILE_KW:
                t += 1
                if t < end and buf[t] in (S.STR, S.STR2):
                    n = S.u16(buf, t + 1)
                    if t + 3 + n > end:
                        raise Unsupported("REPORT FORM TO FILE unresolved")
                    expr = _payload_text(buf[t + 3:t + 3 + n])
                    t += 3 + n
                else:
                    try:
                        expr, t = _fc_group(buf, t, end, syms)
                    except Unsupported:
                        raise Unsupported("REPORT FORM TO FILE unresolved")
                clauses.append(("to_file", expr))
                continue
            raise Unsupported("REPORT FORM TO clause missing FILE")
        if b == S.REPORT_OBJECT_KW:
            t += 1
            typed = t < end and buf[t] == S.TYPE_WORD_MARK
            if typed:
                t += 1
            try:
                expr, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("REPORT FORM OBJECT unresolved")
            clauses.append(("object_type" if typed else "object", expr))
            continue
        if b == S.REPORT_NAME_KW:
            t += 1
            try:
                name, t = _r50_operand(buf, t, end, syms, "REPORT FORM NAME")
            except Unsupported:
                raise Unsupported("REPORT FORM NAME unresolved")
            clauses.append(("name", name))
            continue
        if b == S.GO_IN_CLAUSE:
            t += 1
            name, t = _dec_report_name(buf, t, end, syms)
            clauses.append(("in", name))
            continue
        if b == S.DEFINE_WINDOW_KW:
            t += 1
            name, t = _dec_report_name(buf, t, end, syms)
            clauses.append(("window", name))
            continue
        raise Unsupported("REPORT FORM trailing bytes")
    return clauses


def _emit_report_clause(kind, val):
    """One REPORT FORM clause fragment, including the leading space."""
    if kind == "flag":
        return " " + val
    if kind == "scope":
        word, count = val
        return " " + word + ("" if count is None else " " + _emit(count))
    if kind == "for":
        return " FOR " + _emit(val)
    if kind == "while":
        return " WHILE " + _emit(val)
    if kind == "heading":
        return " HEADING " + _emit(val)
    if kind == "range":
        text = " RANGE"
        if val:
            text += " " + ", ".join(_emit(a) for a in val)
        return text
    if kind == "to_printer":
        return " TO PRINTER" + (" PROMPT" if val else "")
    if kind == "to_file":
        return " TO FILE " + (val if isinstance(val, str) else _emit(val))
    if kind == "object_type":
        return " OBJECT TYPE " + _emit(val)
    if kind == "object":
        return " OBJECT " + _emit(val)
    if kind == "name":
        return " NAME " + val
    if kind == "in":
        text = " IN"
        if val is not None:
            text += " " + (val if isinstance(val, str) else _emit(val))
        return text
    if kind == "window":
        text = " WINDOW"
        if val is not None:
            text += " " + (val if isinstance(val, str) else _emit(val))
        return text
    raise Unsupported("REPORT FORM clause %s" % kind)


def _emit_report_clauses(clauses):
    """Emit the bank in wire order, except PREVIEW immediately before TO.

    r69-bank: `PREVIEW TO PRINTER` is a VFP9 syntax error (missing comma).
    The compiler stores PREVIEW ahead of TO; the source that produces that
    wire has TO first, then PREVIEW. When the next clause is TO, PREVIEW
    is written after the TO clause and any following NOCONSOLE/NOWAIT."""
    out = []
    i = 0
    n = len(clauses)
    while i < n:
        kind, val = clauses[i]
        nxt = clauses[i + 1] if i + 1 < n else (None, None)
        if (kind == "flag" and val == "PREVIEW"
                and nxt[0] in ("to_printer", "to_file")):
            out.append(_emit_report_clause(*nxt))
            i += 2
            while i < n and clauses[i][0] == "flag" \
                    and clauses[i][1] in ("NOCONSOLE", "NOWAIT"):
                out.append(_emit_report_clause(*clauses[i]))
                i += 1
            out.append(" PREVIEW")
            continue
        out.append(_emit_report_clause(kind, val))
        i += 1
    return out


def _dec_r29_dir_literal(buf, i, end, lead):
    """Direct fb/d9 path literal for CD/MKDIR/RMDIR (round-29 review guard).
    The arms emit the path BARE - every measured carrier is a plain filename (drive root, Dats, dotdot, mkd1, rdd1) - so an EMPTY or WHITESPACE-BEARING payload would render uncompilable source and rejects instead. Returns (text, next_index), or (None, i) when buf[i] holds no string literal; grouped fc operands are unaffected by this guard."""
    if i >= end or buf[i] not in (S.STR, S.STR2):
        return None, i
    path, t = _dec_str_arg(buf, i, end)
    if path == "" or any(ch.isspace() for ch in path):
        raise Unsupported("statement lead 0x%02x unsafe bare path" % lead)
    return path, t


def _dec_window_name(buf, j, end, syms, verb="DEFINE"):
    """The window name after a 2c keyword byte: bare `f7 <sym>` or the paren
    spelling `fc <expr> fd`, which the wire keeps ONLY when the source spelled
    parentheses (DEFINE POPUP's r36-D1a rule, re-measured for WINDOW by the
    round-40 lane-H replicas f19/f20/f21). Parens are preserved in emission."""
    if j + 3 <= end and buf[j] == S.SYM:
        return _sym(syms, S.u16(buf, j + 1)), j + 3
    if j < end and buf[j] == S.FC:
        node, j = _fc_group(buf, j, end, syms)
        return _emit(node), j
    raise Unsupported("%s WINDOW name form" % verb)


def _dec_define_window(buf, end, syms):
    # m1 replica byte-exact: 73 2c f7<name> 15 fc<r>fd 07 fc<c>fd
    #   28 fc<r>fd 07 fc<c>fd [0d 4e fc<n>fd] [c1] [be]
    # r40-H second position spelling (oracle f19 == carrier #15 modulo symbol
    # index): 73 2c fc<name>fd 4a fc<obj>fd 05 fc<r>fd 07 fc<c>fd d3 fc<h>fd
    #   07 fc<w>fd 40 fc<font>fd <attr bytes> 27 fc<title>fd 16 fc<parent>fd d4
    j = 2
    name, j = _dec_window_name(buf, j, end, syms)
    frm = []
    at = []
    size = []
    scheme = None
    font = []
    title = None
    obj_name = None
    in_window = None
    flags = []
    seen = set()

    def _pair(t, what):
        """`<mark> fc<a>fd 07 fc<b>fd` — the shared coordinate-pair spelling."""
        a, t = _fc_group(buf, t + 1, end, syms)
        if t >= end or buf[t] != S.ARGJOIN:
            raise Unsupported("DEFINE WINDOW %s list tail" % what)
        b, t = _fc_group(buf, t + 1, end, syms)
        return [a, b], t

    # The NAME clause rides BEFORE the position on the wire (f19/d02), so it is
    # read here rather than in the clause loop below.
    if j < end and buf[j] == S.DEFINE_WIN_NAME:
        if j + 1 >= end or buf[j + 1] != S.FC:
            raise Unsupported("DEFINE WINDOW NAME form")
        seen.add("NAME")
        obj_name, j = _fc_group(buf, j + 1, end, syms)
    if j < end and buf[j] == S.DEFINE_FROM_MARK:
        j += 1
        for idx in range(4):               # FROM row,col TO row,col
            if idx == 2:
                # the TO keyword separates the two coordinate pairs (byte 28,
                # same TO_MARK as FOR's range)
                if j >= end or buf[j] != S.TO_MARK:
                    raise Unsupported("DEFINE WINDOW TO missing")
                j += 1
            e, j = _fc_group(buf, j, end, syms)
            frm.append(e)
            if idx in (0, 2):
                if j >= end or buf[j] != S.ARGJOIN:
                    raise Unsupported("DEFINE WINDOW coordinate list tail")
                j += 1
    elif j < end and buf[j] == S.DEFINE_WIN_AT:
        at, j = _pair(j, "AT")
        if j >= end or buf[j] != S.DEFINE_WIN_SIZE:
            raise Unsupported("DEFINE WINDOW SIZE missing")
        size, j = _pair(j, "SIZE")
    else:
        # A positionless DEFINE WINDOW does compile on the oracle (probes
        # f01-f18), but no carrier in the population spells one, so this arm
        # keeps requiring one of the two measured position clauses.
        raise Unsupported("DEFINE WINDOW FROM missing")
    while j < end:
        if buf[j:j + 2] == bytes(S.WIN_SCHEME_MARK):
            if "SCHEME" in seen:
                raise Unsupported("duplicate DEFINE WINDOW clause")
            seen.add("SCHEME")
            j += 2
            scheme, j = _fc_group(buf, j, end, syms)
        elif buf[j] == S.DEFINE_WIN_FONT:
            if "FONT" in seen:
                raise Unsupported("duplicate DEFINE WINDOW clause")
            seen.add("FONT")
            e, j = _fc_group(buf, j + 1, end, syms)
            font = [e]
            if j < end and buf[j] == S.ARGJOIN:      # optional point size (d04)
                e, j = _fc_group(buf, j + 1, end, syms)
                font.append(e)
        elif buf[j] == S.DEFINE_WIN_TITLE:
            if "TITLE" in seen:
                raise Unsupported("duplicate DEFINE WINDOW clause")
            seen.add("TITLE")
            title, j = _fc_group(buf, j + 1, end, syms)
        elif buf[j] == S.DEFINE_WIN_IN:
            if "IN" in seen:
                raise Unsupported("duplicate DEFINE WINDOW clause")
            seen.add("IN")
            in_window, j = _fc_group(buf, j + 1, end, syms)
        elif buf[j] in S.DEFINE_WINDOW_ATTRS:
            word = S.DEFINE_WINDOW_ATTRS[buf[j]]
            if word in seen:
                raise Unsupported("duplicate DEFINE WINDOW clause")
            seen.add(word)
            flags.append(word)
            j += 1
        else:
            raise Unsupported(
                "DEFINE WINDOW clause 0x%02x unmeasured" % buf[j])
    return DefineStmt("WINDOW", name=name, frm=frm, flags=flags, scheme=scheme,
                      at=at, size=size, font=font, title=title,
                      obj_name=obj_name, in_window=in_window)


def _dec_popup_name(buf, j, end, syms):
    """DEFINE POPUP's IN operand: a bare `f7 <sym>` or a parenthesised group.

    r48-valsweep measured both spellings, and the wire distinguishes them, so
    the group form is admitted ONLY when it carries the explicit paren node
    every measured carrier has: a group without one would emit a bare name and
    recompile to `16 f7 <sym>` instead.
    """
    if j + 3 <= end and buf[j] == S.SYM:
        return _sym(syms, S.u16(buf, j + 1)), j + 3
    if j < end and buf[j] == S.FC:
        node, j2 = _fc_group(buf, j, end, syms)
        if isinstance(node, Paren):
            return _emit(node), j2
    raise Unsupported("DEFINE POPUP clause 0x16 unmeasured")


def _dec_define_popup(buf, end, syms):
    # g1/g2 isolation + workerchart stmt[5]: 73 c6 f7<name> 15 <groups joined 07>
    #   then flag bytes cc(RELATIVE)/57(SHORTCUT) riding AFTER the FROM list in
    #   the wire (single multi-flag sample: wire order cc then 57 — emitted as
    #   parsed; source-vs-wire flag order not separable at n=1)
    j = 2
    if j + 3 <= end and buf[j] == S.SYM:
        name = _sym(syms, S.u16(buf, j + 1))
        j += 3
    elif j < end and buf[j] == S.FC:
        # r36-D1a: paren-name form '(m.lcMenuName)' — fc <expr> fd. The wire
        # keeps fc/fd ONLY for the paren spelling (bare names compile
        # f7 <sym>), so the two forms are distinguishable and the parens are
        # stored as spelled: _emit renders the Paren node WITH its parentheses.
        # Corpus: systray.vcx::systray L616 'DEFINE POPUP (m.lcMenuName)
        # SHORTCUT RELATIVE FROM MROW(),MCOL()' <-> stmt
        # 73c6fcf50df7290003fd15fc43c7fd07fc43c5fdcc57, both twin copies
        # (Frms/class) byte-identical. Any other name form stays Unsupported.
        try:
            node, j = _fc_group(buf, j, end, syms)
        except Unsupported:
            raise Unsupported("DEFINE POPUP name form")
        name = _emit(node)
    else:
        raise Unsupported("DEFINE POPUP name form")
    # r53-popuphead: the clause list is CANONICAL, like BROWSE's — every
    # permutation of a clause set is one frame — but the order is not the one
    # round 40 read off e01/e09/e10. Those carriers spelled COLOR SCHEME,
    # SHADOW and MARGIN with no FROM list, so the reader put them in front of
    # one; the wire stores them BEHIND it, which is why twelve authored
    # programs refused at a byte the reader already knew. The measured order is
    #
    #   FROM 15, TO 28, PROMPT 22, MESSAGE 1d, TITLE 27, COLOR SCHEME 0d 4e,
    #   SHADOW cf, MARGIN c8, IN 16, RELATIVE cc, MULTISELECT d5, FOOTER c0,
    #   SCROLL ce, MOVER bd, SHORTCUT 57
    #
    # Every clause is optional and each appears at most once; a byte outside
    # the table ends the walk and raises. KEY `17` is measured too (it stores
    # an un-grouped fb literal and sits somewhere between SHADOW and SHORTCUT)
    # but the span could not RANK it, so it stays refused.
    scheme = None
    frm = []
    flags = []
    for byte, kind, word in S.DEFINE_POPUP_CLAUSES:
        if kind == "scheme":
            if not (j + 2 <= end and buf[j:j + 2] == bytes(S.WIN_SCHEME_MARK)):
                continue
            scheme, j = _fc_group(buf, j + 2, end, syms)
            continue
        if j >= end or buf[j] != byte:
            continue
        j += 1
        if kind == "flag":
            flags.append(word)
        elif kind == "group":
            operand, j = _fc_group(buf, j, end, syms)
            flags.append("%s %s" % (word, _emit(operand)))
        elif kind == "pair":
            # FROM and TO each hold two groups joined by ARGJOIN
            pair = []
            while True:
                operand, j = _fc_group(buf, j, end, syms)
                pair.append(operand)
                if j < end and buf[j] == S.ARGJOIN and len(pair) < 2:
                    j += 1
                    continue
                break
            if word == "FROM":
                frm = pair
            else:
                flags.append("%s %s" % (word,
                                        ", ".join(_emit(e) for e in pair)))
        elif kind == "prompt":
            # 22 <sub-op>: 11 FIELD <expr>, 12 FILES, cc STRUCTURE
            sub = buf[j] if j < end else None
            j += 1
            if sub == 0x11:
                operand, j = _fc_group(buf, j, end, syms)
                flags.append("PROMPT FIELD " + _emit(operand))
            elif sub == 0x12:
                flags.append("PROMPT FILES")
            elif sub == 0xCC:
                flags.append("PROMPT STRUCTURE")
            else:
                raise Unsupported("DEFINE POPUP PROMPT form")
        else:                                    # kind == "name"
            text, j = _dec_popup_name(buf, j, end, syms)
            flags.append("%s %s" % (word, text))
    if j != end:
        raise Unsupported(
            "DEFINE POPUP clause 0x%02x unmeasured" % buf[j])
    return DefineStmt("POPUP", name=name, frm=frm, flags=flags, scheme=scheme)


_MENU_SHIFTED_BLOCK = False    # section-scoped, set by lift_section (round-40 lane E)


def _menu_bar_shifted_section(stmts):
    """True when this section carries a DEFINE BAR system-menu id that can ONLY
    read as a historical (current-minus-one) constant.

    One corpus artifact was built by an older VFP whose Edit-block ids sit one
    below today's table. Four of its six ids (0x39/0x3c/0x40/0x47) match nothing
    in the measured current table, so they read shifted with no ambiguity; the
    other two (0x3d/0x3e) ARE live current ids for a different name and may only
    follow their unambiguous siblings inside the same method. Sections without
    such a sibling keep the current table — a blanket 'minus one inside menus'
    rule would silently re-bind real constants."""
    for st in stmts:
        b = getattr(st, "stream", None) or b""
        if (len(b) >= 6 and b[0] == S.DEFINE_LEAD and b[1] == S.DEFINE_BAR_KW
                and b[2] == S.FC and b[3] == S.MENU_BAR_ID_MARK
                and b[5] == S.FD and b[4] in S.MENU_BAR_IDS_SHIFTED
                and b[4] not in S.MENU_BAR_IDS):
            return True
    return False


def _menu_bar_id_name(buf, k, end, where):
    """The system-menu bar constant behind an `ec` mark, in any slot that takes
    one: `ec <id>`, or `ec ff <id>` for the five VFP9-era bars that sit in the
    second bank behind the 0xff escape (r49-barnames — the single-byte bank runs
    up to 0xfe with 0xff its only free value, which is the door to the next).

    Returns (name, index just past the id); the caller consumes the group's
    closing fd, which is reader-stripped when statement-final."""
    if k + 3 <= end and buf[k + 1] == S.MENU_BAR_ID_WIDE_MARK:
        wid = buf[k + 2]
        if wid not in S.MENU_BAR_IDS_WIDE:
            raise Unsupported(
                "%s system-menu id 0xff%02x unmeasured" % (where, wid))
        return S.MENU_BAR_IDS_WIDE[wid], k + 3
    bid = buf[k + 1]
    if bid in S.MENU_BAR_IDS:
        return S.MENU_BAR_IDS[bid], k + 2
    raise Unsupported("%s system-menu id 0x%02x unmeasured" % (where, bid))


def _menu_bar_number(buf, j, end, syms):
    """The DEFINE BAR number slot: an ordinary group, or `fc ec <id> fd` naming a
    system-menu constant (round-37 G4 frame family; the id is meaningless outside
    this slot, so the binding lives here and never widens the expression reader).

    Returns the constant NAME as a plain string for the ec form, otherwise the
    stock (expression, next_index) pair."""
    if (j + 4 <= end and buf[j] == S.FC and buf[j + 1] == S.MENU_BAR_ID_MARK
            and buf[j + 3] == S.FD):
        bid = buf[j + 2]
        if _MENU_SHIFTED_BLOCK and bid in S.MENU_BAR_IDS_SHIFTED:
            return S.MENU_BAR_IDS_SHIFTED[bid], j + 4
        if bid in S.MENU_BAR_IDS:
            return S.MENU_BAR_IDS[bid], j + 4
        if bid in S.MENU_BAR_IDS_SHIFTED \
                and bid not in S.MENU_BAR_SHIFT_AMBIGUOUS:
            return S.MENU_BAR_IDS_SHIFTED[bid], j + 4
        raise Unsupported("DEFINE BAR system-menu id 0x%02x unmeasured" % bid)
    if (j + 4 <= end and buf[j] == S.FC and buf[j + 1] == S.MENU_BAR_ID_MARK
            and buf[j + 2] == S.MENU_BAR_ID_WIDE_MARK):
        name, k = _menu_bar_id_name(buf, j + 1, end, "DEFINE BAR")
        return name, k + (1 if k < end and buf[k] == S.FD else 0)
    return _fc_group(buf, j, end, syms)


def _menu_popup_operand(buf, t, end, syms):
    """The popup a menu clause names: a symbol, a parenthesised name
    expression, or a system-menu id.

    r49-menusweep measured all three on DEFINE BAR, ON SELECTION BAR and
    RELEASE alike: `f7 <sym>`, `fc <expr> 03 fd` and `ec <id>` where the id
    names one of the seven system popups. Returns (text, next_index) or
    (None, t) when the slot holds none of them, so each caller keeps its own
    rejection message.
    """
    if t + 3 <= end and buf[t] == S.SYM:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    if t + 2 <= end and buf[t] == S.MENU_BAR_ID_MARK:
        name = S.MENU_POPUP_IDS.get(buf[t + 1])
        if name is None:
            raise Unsupported("system-menu popup id 0x%02x unmeasured"
                              % buf[t + 1])
        return name, t + 2
    if t < end and buf[t] == S.FC:
        node, k = _fc_group(buf, t, end, syms)
        # the source's parentheses ARE the operand: a group with no explicit
        # paren node would re-emit a bare name and recompile to `f7 <sym>`,
        # a different frame, so it stays refused (r48 law 15's rule)
        if not isinstance(node, Paren):
            return None, t
        return _emit(node), k
    return None, t


def _dec_define_bar(buf, end, syms):
    # g3/g4 byte-exact: 73 06 fc<n>fd c3 f7<popup>
    #   [22 fc<PROMPT>fd] [41 fc<STYLE>fd] [1d fc<MESSAGE>fd]
    #   [17 fb<KEY>[07 fc<label>fd]] [c9 13 fc<SKIP FOR>fd] [c2 fc<PICTURE>fd]
    # canonical wire order PROMPT -> STYLE -> MESSAGE -> SKIP -> PICTURE
    # regardless of source order (round-40 e02 vs e03 compile identically, e11
    # pins the full run); the LAST present group's fd may be reader-stripped.
    j = 2
    num, j = _menu_bar_number(buf, j, end, syms)
    # r49-menusweep: the 03 in the number group is the SOURCE's parentheses,
    # not a compiler-inserted ordinal wrapper — `DEFINE BAR 12 OF …` compiles
    # to `fc f8 02 0c fd` with no marker at all, while `DEFINE BAR (n) OF …`
    # is the bare-name frame plus exactly one 03. So the two spellings are
    # wire-distinguishable and the parens are kept, the same discriminator
    # r48 measured for DEFINE POPUP's IN clause.
    bar_num = num if isinstance(num, str) else _emit(num)
    if j >= end or buf[j] != S.DEFINE_BAR_OF:
        raise Unsupported("DEFINE BAR OF missing")
    j += 1
    of_popup, j2 = _menu_popup_operand(buf, j, end, syms)
    if of_popup is not None:
        j = j2
    elif j < end and buf[j] == S.FC:
        # r36-D1b: 'OF (m.lcMenuName)' — grouped spelling kept WITH parens
        # (bare f7 <sym> compiles differently, so the spellings are
        # wire-distinguishable and the parens are faithful). Corpus:
        # systray.vcx::systray L621 'DEFINE BAR (lnBarNum) OF (m.lcMenuName)
        # PROMPT (m.lcText)' <-> stmt
        # 7306fcf72e0003fdc3fcf50df7290003fd22fcf50df72d0003, both twin copies.
        # bar_num above stays Paren-unwrapped exactly as stock: ordinal groups
        # are compiler-inserted ('Define Bar 1 Of …').
        try:
            of_node, j = _fc_group(buf, j, end, syms)
        except Unsupported:
            raise Unsupported("DEFINE BAR popup form")
        of_popup = _emit(of_node)
    else:
        raise Unsupported("DEFINE BAR popup form")
    prompt = style = message = key = skip_for = picture = None
    if j < end and buf[j] == S.BAR_PROMPT_MARK:
        j += 1
        prompt, j = _fc_group(buf, j, end, syms)
    font = []
    if j < end and buf[j] == S.DEFINE_WIN_FONT:
        # r53-barhead: FONT sits between PROMPT and STYLE and carries a face
        # with an optional size, fc groups joined by ARGJOIN — the same shape
        # DEFINE WINDOW's and BROWSE's FONT clauses have
        j += 1
        while True:
            operand, j = _fc_group(buf, j, end, syms)
            font.append(operand)
            if len(font) < 2 and j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            break
    if j < end and buf[j] == S.BAR_STYLE_MARK:
        j += 1
        style, j = _fc_group(buf, j, end, syms)
    # r49-residual: BEFORE (be) and AFTER (2d) each carry the BAR kind byte 06
    # and a group naming the neighbour — `DEFINE BAR 1 OF _mtools PROMPT "x"
    # BEFORE _mfi_new` is `… 22 fc "x" fd be 06 fc ec 24 fd`. Measured composed
    # with MESSAGE, which is where the wire puts it.
    neighbour = neighbour_word = None
    if j + 1 < end and buf[j] in (0xBE, 0x2D) and buf[j + 1] == 0x06:
        neighbour_word = "BEFORE" if buf[j] == 0xBE else "AFTER"
        k = j + 2
        if k + 3 <= end and buf[k] == S.FC \
                and buf[k + 1] == S.MENU_BAR_ID_MARK:
            # the neighbour is a system-menu bar name; a statement-final
            # group's fd is reader-stripped as everywhere else here
            neighbour, j = _menu_bar_id_name(
                buf, k + 1, end, "DEFINE BAR " + neighbour_word)
            j += 1 if j < end and buf[j] == S.FD else 0
        else:
            nb, j = _menu_bar_number(buf, k, end, syms)
            neighbour = nb if isinstance(nb, str) else _emit(nb)
    if j < end and buf[j] == S.BAR_MESSAGE_MARK:
        j += 1
        message, j = _fc_group(buf, j, end, syms)
    if j < end and buf[j] == S.BAR_KEY_MARK:
        # KEY <key text>[, <label>]: the key spelling rides as a raw fb payload
        # (it is a key EXPRESSION like CTRL+A, not a value), the optional label
        # as an ordinary group behind 07 (round-37 D6 with label, round-40 e07
        # without).
        if j + 4 > end or buf[j + 1] != S.STR:
            raise Unsupported("DEFINE BAR KEY clause shape")
        n = S.u16(buf, j + 2)
        if j + 4 + n > end:
            raise Unsupported("DEFINE BAR KEY clause truncated")
        key_text = _payload_text(buf[j + 4:j + 4 + n])
        j += 4 + n
        label = None
        if j < end and buf[j] == S.ARGJOIN:
            label, j = _fc_group(buf, j + 1, end, syms)
        key = (key_text, label)
    if j < end and buf[j:j + 2] == bytes(S.BAR_SKIPFOR_MARK):
        j += 2
        skip_for, j = _fc_group(buf, j, end, syms)
    scheme = mark = None
    if j + 2 <= end and buf[j:j + 2] == bytes(S.WIN_SCHEME_MARK):
        # r53-barhead: COLOR SCHEME and MARK sit behind SKIP FOR, in that order
        scheme, j = _fc_group(buf, j + 2, end, syms)
    if j < end and buf[j] == S.PAD_MARK_CLAUSE:
        j += 1
        mark, j = _fc_group(buf, j, end, syms)
    if j < end and buf[j] == S.BAR_PICTURE_MARK:
        j += 1
        picture, j = _fc_group(buf, j, end, syms)
    pictres = None
    if j < end and buf[j] == S.BAR_PICTRES_MARK:
        # r43-pictres: PICTRES <sysbar> is 5f fc ec <id> [fd]; PICTRES 1 is
        # 5f fc <expr>. Always last on the measured wire, so the group's fd
        # is reader-stripped when statement-final.
        j += 1
        if (j + 3 <= end and buf[j] == S.FC
                and buf[j + 1] == S.MENU_BAR_ID_MARK):
            pictres, j = _menu_bar_id_name(
                buf, j + 1, end, "DEFINE BAR PICTRES")
            if j < end and buf[j] == S.FD:
                j += 1
        else:
            node, j = _fc_group(buf, j, end, syms)
            pictres = _emit(node)
    if j != end:
        raise Unsupported(
            "DEFINE BAR clause 0x%02x unmeasured" % buf[j])
    return DefineStmt("BAR", bar_num=bar_num, of_popup=of_popup, prompt=prompt,
                      style=style, message=message, key=key,
                      skip_for=skip_for, picture=picture, pictres=pictres,
                      neighbour=neighbour, neighbour_word=neighbour_word,
                      font=font, scheme=scheme, mark=mark)


def _dec_define_pad(buf, end, syms):
    # r43-pad: 73 bc f7<name> c3 ec 02 then optional clauses. PROMPT / SKIP
    # FOR / COLOR SCHEME / KEY were the Main.MPX set; AT / FONT / STYLE /
    # MESSAGE / MARK / BEFORE / NEGOTIATE LEFT compiled in the same batch.
    j = 2
    if j + 3 > end or buf[j] != S.SYM:
        raise Unsupported("DEFINE PAD name form")
    name = _sym(syms, S.u16(buf, j + 1))
    j += 3
    if j >= end or buf[j] != S.DEFINE_BAR_OF:
        raise Unsupported("DEFINE PAD OF missing")
    j += 1
    if j + 2 > end or buf[j] != S.MENU_BAR_ID_MARK:
        raise Unsupported("DEFINE PAD OF form")
    of_menu = S.PUSH_POP_MENU_IDS.get(buf[j + 1])
    if of_menu is None:
        raise Unsupported("DEFINE PAD menu id 0x%02x unmeasured" % buf[j + 1])
    j += 2
    prompt = skip_for = scheme = key = None
    at = []
    font = []
    style = message = mark = None
    before_name = ""
    negotiate = ""
    seen = set()
    while j < end:
        if buf[j] == S.BAR_PROMPT_MARK:
            if "PROMPT" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("PROMPT")
            j += 1
            prompt, j = _fc_group(buf, j, end, syms)
        elif j + 1 < end and buf[j:j + 2] == bytes(S.BAR_SKIPFOR_MARK):
            if "SKIP" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("SKIP")
            j += 2
            skip_for, j = _fc_group(buf, j, end, syms)
        elif j + 1 < end and buf[j:j + 2] == bytes(S.WIN_SCHEME_MARK):
            if "SCHEME" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("SCHEME")
            j += 2
            scheme, j = _fc_group(buf, j, end, syms)
        elif buf[j] == S.BAR_KEY_MARK:
            if "KEY" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("KEY")
            if j + 4 > end or buf[j + 1] != S.STR:
                raise Unsupported("DEFINE PAD KEY clause shape")
            n = S.u16(buf, j + 2)
            if j + 4 + n > end:
                raise Unsupported("DEFINE PAD KEY clause truncated")
            key_text = _payload_text(buf[j + 4:j + 4 + n])
            j += 4 + n
            label = None
            if j < end and buf[j] == S.ARGJOIN:
                label, j = _fc_group(buf, j + 1, end, syms)
            key = (key_text, label)
        elif buf[j] == S.DEFINE_WIN_AT:
            if "AT" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("AT")
            row, t = _fc_group(buf, j + 1, end, syms)
            if t >= end or buf[t] != S.ARGJOIN:
                raise Unsupported("DEFINE PAD AT clause")
            col, j = _fc_group(buf, t + 1, end, syms)
            at = [row, col]
        elif buf[j] == S.DEFINE_WIN_FONT:
            if "FONT" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("FONT")
            e, j = _fc_group(buf, j + 1, end, syms)
            font = [e]
            if j < end and buf[j] == S.ARGJOIN:
                e, j = _fc_group(buf, j + 1, end, syms)
                font.append(e)
        elif buf[j] == S.BAR_STYLE_MARK:
            if "STYLE" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("STYLE")
            style, j = _fc_group(buf, j + 1, end, syms)
        elif buf[j] == S.BAR_MESSAGE_MARK:
            if "MESSAGE" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("MESSAGE")
            message, j = _fc_group(buf, j + 1, end, syms)
        elif buf[j] == S.PAD_MARK_CLAUSE:
            if "MARK" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("MARK")
            mark, j = _fc_group(buf, j + 1, end, syms)
        elif buf[j] == S.PAD_BEFORE_MARK:
            if "BEFORE" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("BEFORE")
            if j + 4 > end or buf[j + 1] != S.SYM:
                raise Unsupported("DEFINE PAD BEFORE form")
            before_name = _sym(syms, S.u16(buf, j + 2))
            j += 4
        elif buf[j] == S.PAD_NEGOTIATE_MARK:
            if "NEGOTIATE" in seen:
                raise Unsupported("duplicate DEFINE PAD clause")
            seen.add("NEGOTIATE")
            if j + 1 >= end or buf[j + 1] != S.PAD_NEGOTIATE_LEFT:
                raise Unsupported("DEFINE PAD NEGOTIATE form")
            negotiate = "LEFT"
            j += 2
        else:
            raise Unsupported("DEFINE PAD clause 0x%02x unmeasured" % buf[j])
    return DefineStmt("PAD", name=name, of_popup=of_menu, prompt=prompt,
                      skip_for=skip_for, scheme=scheme, key=key, at=at,
                      font=font, style=style, message=message, mark=mark,
                      before_name=before_name, negotiate=negotiate)


def _dec_create_cursor(buf, end, syms):
    # round-26 c1/c2 byte-exact base, widened round-28 W4 along measured
    # shapes only. Second byte 0xBD = CREATE CURSOR, 0x31 = CREATE TABLE
    # (round-42 clause batch: same field-list envelope, one distinguishing
    # byte). name = fb/d9 literal OR fc-group ([03] paren inside, [fd]
    # closer); optional c0 = the FREE keyword (r47-createtable); 02 opens the
    # field list.
    #   field := f7 <sym> fb/d9 <type> [d8 d4 fc<n>fd]
    #            | {02 fc<w>fd | 07 fc<d>fd}* 03?
    # Types without a size group (M/L/I) and AUTOINC fields carry no per-field
    # closer 03 (buysmat CgView s4[20]; xmllistener s26 stmts7/8;
    # VFPxWorkbookXLSX s13[0]). Fields join by 07; a second 03 closes the list.
    j = 2
    if end < 2 or buf[1] not in (0xBD, 0x31):
        raise Unsupported("CREATE CURSOR name form")
    if j < end and buf[j] in (S.STR, S.STR2):
        name, j = _dec_str_arg(buf, j, end)
    elif j < end and buf[j] == S.FC:
        try:
            node, j = _fc_group(buf, j, end, syms)
        except Unsupported:
            raise Unsupported("CREATE CURSOR name form")
        name = _emit(node)
    else:
        raise Unsupported("CREATE CURSOR name form")
    name = str(name)
    free = False
    if j < end and buf[j] == 0xC0:
        # r47-createtable: c0 is the FREE keyword, on both the bare-name and
        # the parenthesised target; without FREE the byte is absent, and a
        # CODEPAGE clause does not spend it. CREATE CURSOR has no FREE keyword
        # and no carrier in any split spells c0 under 0xbd, so that stays
        # unmeasured rather than emitting a word VFP would reject.
        if buf[1] != 0x31:
            raise Unsupported("CREATE CURSOR c0 clause unmeasured")
        free = True
        j += 1
    # round-33: optional CODEPAGE = <n> clause, measured only in the slot
    # name [c0] ba fc <numeric-literal> fd 02 <fields>. The byte doubles as
    # TRY_LEAD at statement position — context-local reuse, never a global
    # token. Only the plain integer-literal spellings (f8/f9) are admitted:
    # the measured matrix is f9 throughout (620=f9036c02 … 1256=f904e804) and
    # the round-33 simulation envelope accepts nothing wider.
    codepage = None
    if j < end and buf[j] == 0xBA:
        j += 1
        if (j + 2 > end or buf[j] != S.FC
                or buf[j + 1] not in (S.INT8, S.INT16)):
            raise Unsupported("CREATE CURSOR CODEPAGE clause shape")
        if buf[j + 1] == S.INT8:
            if j + 4 > end:
                raise Unsupported("CREATE CURSOR CODEPAGE clause shape")
            codepage = str(buf[j + 3])
            j += 4
        else:
            if j + 5 > end:
                raise Unsupported("CREATE CURSOR CODEPAGE clause shape")
            codepage = str(S.u16(buf, j + 3))
            j += 5
        if j >= end or buf[j] != S.FD:
            raise Unsupported("CREATE CURSOR CODEPAGE clause shape")
        j += 1
    if j < end and buf[j] == S.CREATE_FROM_MARK:
        # r75-fromarray: FROM ARRAY is 15 04 <array> and there is no field
        # list. FROM without ARRAY stays a refusal (VFP9 syntax error).
        j += 1
        if j >= end or buf[j] != S.CREATE_ARRAY_MARK:
            raise Unsupported("CREATE CURSOR FROM ARRAY form")
        j += 1
        arr, j = _dec_create_array_operand(buf, j, end, syms)
        if j != end:
            raise Unsupported("CREATE CURSOR trailing bytes")
        return CreateCursor(name, [], codepage, table=(buf[1] == 0x31),
                            free=free, from_array=arr)
    if j >= end or buf[j] != 0x02:
        raise Unsupported("CREATE CURSOR field list missing")
    j += 1
    fields = []
    while True:
        if j + 3 > end or buf[j] != S.SYM:
            raise Unsupported("CREATE CURSOR field name form")
        fname = _sym(syms, S.u16(buf, j + 1))
        j += 3
        if j + 3 > end or buf[j] not in (S.STR, S.STR2):
            raise Unsupported("CREATE CURSOR type letter unresolved")
        tchar, j = _dec_str_arg(buf, j, end)
        width = decimals = None
        autoinc = None
        if j < end and buf[j] == 0xD8:
            j += 1
            if j + 2 > end or buf[j] != 0xD4 or buf[j + 1] != S.FC:
                raise Unsupported("CREATE CURSOR AUTOINC shape")
            aes, k = _dec_expr(buf, j + 2, end, syms,
                               stop_bytes=_IF_COND_STOP)
            if len(aes) != 1:
                raise Unsupported("CREATE CURSOR AUTOINC value unresolved")
            if k >= end or buf[k] != S.FD:
                raise Unsupported("CREATE CURSOR AUTOINC shape")
            autoinc = aes[0]
            j = k + 1
        had_size = False
        while j + 1 < end and buf[j] in (0x02, 0x07) and buf[j + 1] == S.FC:
            is_dec = buf[j] == 0x07
            had_size = True
            es, k = _dec_expr(buf, j + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("CREATE CURSOR size group unresolved")
            val = _emit(es[0])
            if is_dec:
                decimals = val
            else:
                width = val
            j = k + 1
        if had_size:
            if j >= end or buf[j] != 0x03:
                raise Unsupported("CREATE CURSOR field tail 0x%02x" % buf[j])
            j += 1
        # r54-cursornull (25 programs, CREATE CURSOR and CREATE TABLE alike):
        # the nullability clause is ONE slot behind the type — behind the size
        # closer when the field is sized, directly behind the type letter when
        # it is not. `d6` alone is NULL, `0a d6` is NOT NULL (0a is the reader's
        # own NOT), and a field spelling neither carries no byte here at all.
        # Round 29 measured the sized-field half of this slot; the unsized half
        # is what blocked the corpus. Any other byte still raises field tail.
        nullable = None
        if j + 1 < end and buf[j] == S.NOT and buf[j + 1] == 0xD6:
            nullable = "NOT NULL"
            j += 2
        elif j < end and buf[j] == 0xD6:
            nullable = "NULL"
            j += 1
        fields.append((fname, tchar.upper(), width, decimals,
                       _emit(autoinc) if autoinc is not None else None,
                       nullable))
        if j >= end:
            raise Unsupported("CREATE CURSOR field list unterminated")
        if buf[j] == 0x07:
            j += 1                  # 07 joins to the next field
            continue
        if buf[j] == 0x03:
            j += 1          # the list-level closer after the last field
            break
        raise Unsupported("CREATE CURSOR field tail 0x%02x" % buf[j])
    if j != end:
        raise Unsupported("CREATE CURSOR trailing bytes")
    return CreateCursor(name, fields, codepage, table=(buf[1] == 0x31),
                        free=free)


def _dec_create_array_operand(buf, j, end, syms):
    """FROM ARRAY operand: SYM, m.SYM (`f5 0d f7`), or an fc-group.

    r75-fromarray: `FROM ARRAY a` is `15 04 f7`, `FROM ARRAY m.a` is
    `15 04 f5 0d f7`, `FROM ARRAY (a)` is `15 04 fc f7 03` (fd stripped at
    statement end). A group is re-emitted with parentheses so the frame
    stays the grouped spelling.
    """
    if j + 5 <= end and buf[j] == S.WORKAREA_REF \
            and buf[j + 1] == 0x0D and buf[j + 2] == S.SYM:
        return "m." + _sym(syms, S.u16(buf, j + 3)), j + 5
    if j + 3 <= end and buf[j] == S.SYM:
        return _sym(syms, S.u16(buf, j + 1)), j + 3
    if j < end and buf[j] == S.FC:
        try:
            node, j = _fc_group(buf, j, end, syms)
        except Unsupported:
            raise Unsupported("CREATE CURSOR FROM ARRAY form")
        if j < end and buf[j] == 0x03:
            j += 1
        text = _emit(node)
        if not (text.startswith("(") and text.endswith(")")):
            text = "(%s)" % text
        return text, j
    raise Unsupported("CREATE CURSOR FROM ARRAY form")


def _dec_create(buf, end, syms):
    # bare CREATE <name> = 13 fb<name> (CMD_SWEEP); CREATE REPORT =
    # 13 33 <file-group> 15 <from-group> (round-26 c3); groups carry explicit
    # runtime-paren markers and the FINAL fd may be reader-stripped
    if end < 2:
        raise Unsupported("CREATE truncated")
    kw = buf[1]
    if kw in (S.STR, S.STR2):
        nm, j = _dec_str_arg(buf, 1, end)
        if j != end:
            raise Unsupported("CREATE trailing bytes")
        return CreateStmt(name=nm)
    if kw == 0xC4:
        # round-28 W4 carrier-settled: CREATE SQL VIEW <view> REMOTE CONNECTION
        # <conn> SHARE AS <query> = 13 c4 fb<view> d2 d1 fb<conn> c2 51 fb<query>
        # (temp.scx::Header1 s0 stmts8/10/12; the query rides as ONE fb string
        # to statement end). Round-29 census widens ONLY the two markers:
        # pcph/checkmatinput et al. carry no c2 and bincode1.scx::frmbincode
        # s2[6] carries a lone d1 — so d2 is optional before d1 and c2 optional
        # after the conn name; each renders only when its byte was present.
        # Anything else under c4 keeps the loud label.
        j = 2
        if j + 3 > end or buf[j] not in (S.STR, S.STR2):
            raise Unsupported("CREATE SQL VIEW name form")
        view, j = _dec_str_arg(buf, j, end)
        remote = False
        if j + 2 <= end and buf[j] == 0xD2 and buf[j + 1] == 0xD1:
            remote = True
            j += 2
        elif j < end and buf[j] == 0xD1:
            j += 1
        else:
            raise Unsupported("CREATE SQL VIEW REMOTE CONNECTION missing")
        if j + 3 > end or buf[j] not in (S.STR, S.STR2):
            raise Unsupported("CREATE SQL VIEW connection name form")
        conn, j = _dec_str_arg(buf, j, end)
        share = False
        if j < end and buf[j] == 0xC2:
            share = True
            j += 1
        if j >= end or buf[j] != S.AS_CLAUSE_MARK:
            raise Unsupported("CREATE SQL VIEW AS clause missing")
        j += 1
        if j >= end or buf[j] not in (S.STR, S.STR2):
            raise Unsupported("CREATE SQL VIEW query form")
        query, j = _dec_str_arg(buf, j, end)
        if j != end:
            raise Unsupported("CREATE trailing bytes")
        return CreateStmt(sql_view=view, remote_connection=conn,
                          as_query=query, remote=remote, share=share)
    if kw == S.CREATE_REPORT_KW:
        file_e, j = _fc_group(buf, 2, end, syms)
        if j >= end or buf[j] != S.DEFINE_FROM_MARK:
            raise Unsupported("CREATE REPORT FROM missing")
        from_e, j = _fc_group(buf, j + 1, end, syms)
        if j != end:
            raise Unsupported("CREATE REPORT trailing bytes")
        return CreateStmt(report_file=file_e, report_from=from_e)
    raise Unsupported("CREATE object 0x%02x unmeasured" % kw)


def _clause_group_close(buf, k, end):
    """Consume a clause group's closing fd, or None if there is none.

    r54-insertsel / r54-selnointo / r54-declarelib: a clause group that is the
    LAST thing in its statement runs to statement end with its `fd`
    reader-stripped — the same stripped closer every statement-final group in
    this format has. Under SELECT that only ever happens where the INTO clause
    would begin (a spliced INSERT body, or a destination-less SELECT); under
    DECLARE it is the library with no alias and no parameter list behind it. A
    group that ended because a `43` packet ran out of WINDOW is a truncation,
    not a stripped closer, and keeps its refusal.
    """
    if k < end and buf[k] == S.FD:
        return k + 1
    if k == end and not _GROUP_EOW_CLOSE:
        return k
    return None


def _dec_sql_subquery(buf, i, end, syms):
    """One `e8 <u16 n> <n bytes>` subquery operand (r54-subquery).

    The block's first byte is a fixed `00` and the rest is a SELECT body with
    no `6f` lead of its own, so the reader supplies the lead and hands the
    block to the statement reader. The length is what makes that safe: the
    body's groups all close inside it, and the enclosing expression resumes at
    the byte after.
    """
    if i + 3 > end:
        raise Unsupported("SQL subquery length truncated")
    n = S.u16(buf, i + 1)
    body = buf[i + 3:i + 3 + n]
    if len(body) != n or not body or body[0] != S.SQL_SUBQUERY_LEAD_BYTE:
        raise Unsupported("SQL subquery block shape")
    global _SQL_SUBQUERY_BODY
    outer = _SQL_SUBQUERY_BODY
    _SQL_SUBQUERY_BODY = True
    try:
        node = _dec_sub_statement(bytes([S.SQL_SELECT_LEAD]) + body[1:], syms)
    finally:
        _SQL_SUBQUERY_BODY = outer
    return SqlSubquery("(%s)" % _emit_line(node)), i + 3 + n


def _dec_sub_statement(buf, syms):
    """Decode a whole statement spliced INSIDE another one (r54-insertsel).

    `INSERT INTO … SELECT …` carries the SELECT with its own `6f` lead, so the
    reader for the body is the statement reader. Statement decoding keeps
    module state written for a walk that is never nested — the symbol
    high-water marks and the expression-retry flag — so it is saved around the
    nested call and the statement high-water comes back as the higher of the
    two, which is what the enclosing statement's own accounting expects.
    """
    global _SYM_STMT_HI, _SYM_STMT_LO, _EXPR_RETRY_ACTIVE
    saved_hi, saved_lo = _SYM_STMT_HI, _SYM_STMT_LO
    saved_retry = _EXPR_RETRY_ACTIVE
    try:
        return dec_statement(buf, syms)
    finally:
        _SYM_STMT_HI = max(saved_hi, _SYM_STMT_HI)
        _SYM_STMT_LO = saved_lo if saved_lo is not None else _SYM_STMT_LO
        _EXPR_RETRY_ACTIVE = saved_retry


def _dec_insert_into(buf, end, syms):
    # round-26 i1 byte-exact FROM MEMVAR: 72 bc <target-group> 15 c2.
    # round-28 W1 VALUES form (corpus carriers dashboard1.scx::Container2,
    # _reportlistener.vcx::xmllistener 'INSERT INTO (ALIAS()) VALUES',
    # xfrxlib.vcx/_internet.vcx): the target may also be a bare fb/d9 table
    # name, and a c5-introduced tuple of individually fc-wrapped values
    # follows, ARGJOIN-separated, closed by the tuple paren byte 03:
    #   72 bc <target> [02 <cols> 03] c5 02 <fc value> 07 .. <fc value> 03
    if end < 2 or buf[1] != 0xBC:
        raise Unsupported("INSERT INTO target missing")
    j = 2
    if j < end and buf[j] in (S.STR, S.STR2):
        target, j = _dec_str_arg(buf, j, end)
    else:
        target, j = _fc_group(buf, j, end, syms)
    if j < end and buf[j] == S.DEFINE_FROM_MARK:          # FROM MEMVAR/NAME tail
        if j + 2 <= end and buf[j + 1] == S.INSERT_FROM_NAME:
            # r47-insertforms: 4a selects NAME, and the object name follows as
            # an fb/d9 literal — a different frame from the c2 MEMVAR form.
            nm, k = _dec_str_arg(buf, j + 2, end)
            if k != end:
                raise Unsupported("INSERT INTO trailing bytes")
            return InsertInto(target, from_name=nm)
        if j + 2 > end or buf[j + 1] != 0xC2:
            raise Unsupported("INSERT INTO FROM MEMVAR missing")
        j += 2
        if j != end:
            raise Unsupported("INSERT INTO trailing bytes")
        return InsertInto(target)
    columns = None
    if j < end and buf[j] == 0x02:                        # ( field-name list
        j += 1
        columns = []
        while True:
            if j + 3 <= end and buf[j] == S.SYM:
                columns.append(_sym(syms, S.u16(buf, j + 1)))
                j += 3
            else:
                raise Unsupported("INSERT column list unresolved")
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            if j < end and buf[j] == 0x03:                # ) closes the list
                j += 1
                break
            raise Unsupported("INSERT column list tail")
    if j < end and buf[j] == 0xC5:                        # VALUES (
        j += 1
        if j >= end or buf[j] != 0x02:
            raise Unsupported("INSERT VALUES header missing")
        j += 1
        values = []
        while True:
            v, j = _fc_group(buf, j, end, syms)
            values.append(v)
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            if j < end and buf[j] == 0x03:                # ) closes the tuple
                j += 1
                break
            raise Unsupported("INSERT VALUES tail")
        if j != end:
            raise Unsupported("INSERT INTO trailing bytes")
        return InsertInto(target, columns=columns, values=values)
    if j < end and buf[j] == S.SQL_SELECT_LEAD:
        # r54-insertsel: the third body is a whole SELECT statement, lead and
        # all, spliced behind the target and running to statement end. It never
        # carries an INTO clause of its own — the enclosing INSERT is the
        # destination — and VFP9 refuses a source that spells one.
        node = _dec_sub_statement(buf[j:], syms)
        return InsertInto(target, columns=columns, select=_emit_line(node))
    raise Unsupported("INSERT INTO body missing")


def dec_set_value(buf, i, end, syms, sid=None):
    """One SET TO-value, the three measured spellings (r52-setvalue):
    - grouped: 'fc <expr> [03-paren] [fd]'  ('SET CLASSLIB TO (THIS.x) …',
      '(m.liDeci)' — the 03 is the PAREN postfix INSIDE the group);
    - bare:    ONE fb string operand        ('SET ORDER TO Revert',
      'SET CLASSLIB TO foxchartsBeta.vcx');
    - bare:    ONE f7 symbol, on the five ids whose `TO <name>` operand the
      sweep measured as a bare symbol (CARRY / EVENTLIST / FIELDS /
      NOCPTRANS / SKIP). `sid` is the setting id; without it the symbol
      spelling stays refused.
    Returns (node, next_index, ungrouped). ungrouped True is a bare fb
    filename (SET PROCEDURE TO xfrx); False is an fc-grouped value."""
    if i < end and buf[i] == S.FC:
        if sid in S.SET_NAME_ONLY_IDS:
            raise Unsupported("SET variant outside forced subset")
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("SET variant outside forced subset")
        if k < end and buf[k] == S.FD:
            k += 1
        return es[0], k, False
    if i + 3 <= end and buf[i] == S.STR \
            and (sid is None or sid in S.SET_NAME_VALUE_IDS):
        n = S.u16(buf, i + 1)
        if i + 3 + n > end:
            raise Unsupported("SET variant outside forced subset")
        return Str(_payload_text(buf[i + 3:i + 3 + n])), i + 3 + n, True
    if i + 3 <= end and buf[i] == S.SYM and sid in S.SET_SYMBOL_VALUE_IDS:
        return Sym(_sym(syms, S.u16(buf, i + 1))), i + 3, False
    raise Unsupported("SET variant outside forced subset")


def _dec_set_of_operand(buf, i, end, syms, grouped=False):
    """One object or owner inside the SET SKIP / MARK OF chain (r52-setof).

    Three measured spellings: a system-menu id behind `ec` (`MENU _MSYSMENU`,
    `OF _MSYSMENU`), a bare `f7` symbol (a named pad or popup), and the
    object's own `fc..fd` group, which BAR always spends for its number and a
    popup spends for the parenthesised `(m.cShortcut)` spelling. Returns
    (spelling, next_index)."""
    if i + 2 <= end and buf[i] == S.MENU_BAR_ID_MARK and not grouped:
        name = S.MENU_POPUP_IDS.get(buf[i + 1])
        if name is None:
            raise Unsupported("SET OF system-menu id 0x%02x unmeasured"
                              % buf[i + 1])
        return name, i + 2
    if i + 3 <= end and buf[i] == S.SYM and not grouped:
        return _sym(syms, S.u16(buf, i + 1)), i + 3
    if i < end and buf[i] == S.FC:
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or k >= end or buf[k] != S.FD:
            raise Unsupported("SET variant outside forced subset")
        return _emit(es[0]), k + 1
    raise Unsupported("SET variant outside forced subset")


def _dec_relation_into(buf, i, end, syms):
    """One INTO target of SET RELATION (r36-sim, r52-setin, r71-relation).

    Two measured spellings: a bare `f7` symbol (`INTO tt`) and the target's
    own `fc..fd` group, which carries the `03` runtime-paren postfix exactly
    when the source parenthesises it (`INTO (tt)`, `INTO (m.a)`). The group
    closer is reader-stripped when the target is statement-final."""
    if i + 2 > end or buf[i] != 0xBC:
        raise Unsupported("SET variant outside forced subset")
    i += 1
    if buf[i] == S.SYM:
        if i + 3 > end:
            raise Unsupported("SET variant outside forced subset")
        return _sym(syms, S.u16(buf, i + 1)), i + 3
    if buf[i] == S.FC:
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("SET variant outside forced subset")
        if k < end and buf[k] == S.FD:
            k += 1
        return _emit(es[0]), k
    raise Unsupported("SET variant outside forced subset")


def _dec_set_relation(buf, end, syms):
    """SET RELATION as one clause bank (r71-relation).

    Wire order, measured:
      47 2d [01] [16 <alias>] (28 <fc e fd> bc <target> [07 …]* | 1f bc <target>)
    ADDITIVE is a leading 01 after the id. The 16 IN mark, when present,
    carries the work area before TO or OFF, the reverse of the source order.
    TO spends a list of (expression-group, INTO target) pairs joined on 07;
    OFF spends 1f and one INTO target. An INTO target is a bare symbol or
    its own group. Source order of ADDITIVE vs IN is one frame.
    Emission is TO/OFF, INTO, ADDITIVE, IN — the spelling the 620-occurrence
    corpus skeleton round-trips."""
    t = 2
    additive = False
    if t < end and buf[t] == S.SET_ADDITIVE_MARK:
        additive = True
        t += 1
    in_alias = None
    if t < end and buf[t] == S.SET_ORDER_IN_MARK:
        in_alias, t = _dec_in_alias(buf, t + 1, end, syms)
    if t >= end:
        raise Unsupported("SET variant outside forced subset")
    if buf[t] == 0x1F:
        t += 1
        target, t = _dec_relation_into(buf, t, end, syms)
        if t != end:
            raise Unsupported("SET trailing bytes")
        text = "SET RELATION OFF INTO %s" % target
        if additive:
            text += " ADDITIVE"
        if in_alias is not None:
            text += " IN %s" % in_alias
        return SetStmt(text)
    if buf[t] != S.TO_MARK:
        raise Unsupported("SET variant outside forced subset")
    t += 1
    pairs = []
    while True:
        if t >= end or buf[t] != S.FC:
            raise Unsupported("SET variant outside forced subset")
        es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("SET variant outside forced subset")
        if k < end and buf[k] == S.PAREN:
            k += 1
        if k >= end or buf[k] != S.FD:
            raise Unsupported("SET variant outside forced subset")
        t = k + 1
        target, t = _dec_relation_into(buf, t, end, syms)
        pairs.append((es[0], target))
        if t == end:
            break
        if buf[t] == S.ARGJOIN:
            t += 1
            continue
        raise Unsupported("SET trailing bytes")
    if not pairs:
        raise Unsupported("SET variant outside forced subset")
    text = "SET RELATION TO " + ", ".join(
        "%s INTO %s" % (_emit(e), a) for e, a in pairs)
    if additive:
        text += " ADDITIVE"
    if in_alias is not None:
        text += " IN %s" % in_alias
    return SetStmt(text)


def _dec_in_alias(buf, i, end, syms,
                  refusal="SET variant outside forced subset"):
    """One work area behind a `16` IN mark (r52-setin, r54-inalias).

    Three measured spellings: a bare `f7` symbol (`IN tt`), a bare numeric
    literal (`IN 1`), and the statement's own `fc..fd` group, which carries the
    `03` runtime-paren postfix exactly when the source parenthesises the alias
    (`IN (m.a)`) and none when it does not (`IN SELECT()`). Returns
    (spelling, next_index).

    SET measured the grammar first; r54-inalias measured the same three
    spellings behind ZAP's, SKIP's and the xbase DELETE's own `16`, so the
    clause is read here once for every verb that spends it. `refusal` names the
    verb whose envelope a caller is guarding."""
    if i + 3 <= end and buf[i] == S.SYM:
        return _sym(syms, S.u16(buf, i + 1)), i + 3
    if i < end and buf[i] == S.FC:
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported(refusal)
        if k < end and buf[k] == S.FD:
            k += 1              # closer reader-stripped when statement-final
        return _emit(es[0]), k
    es, k = _dec_expr(buf, i, end, syms, stop_at_one=True,
                      stop_bytes=_IF_COND_STOP)
    if len(es) != 1 or not isinstance(es[0], Num):
        raise Unsupported(refusal)
    return _emit(es[0]), k


def _emit_set_order_tag(node):
    """SET ORDER TO tag. r42-kwperm: quote characters ride in the fb payload
    (`Revert` / `'Revert'` / `"Revert"` are three frames). Emit the payload
    as spelled; do not wrap a bare tag as a string literal."""
    if isinstance(node, Str):
        return node.text
    return _emit(node)


def _dec_order_direction(buf, k, end):
    """Trailing ASCENDING/DESCENDING on SET ORDER (r71-order).

    Measured as one leftover byte behind a finished TO-value: `3c` is
    DESCENDING, `bd` is ASCENDING. Source order of the flag vs IN is one
    frame; the flag sits last on the wire."""
    if k < end and buf[k] == S.SET_ORDER_DESCENDING_MARK:
        return " DESCENDING", k + 1
    if k < end and buf[k] == S.SET_ORDER_ASCENDING_MARK:
        return " ASCENDING", k + 1
    return "", k


def _emit_classlib_lib(node, ungrouped):
    """One SET CLASSLIB TO operand. Bare fb is the unquoted name."""
    if ungrouped and isinstance(node, Str):
        return node.text
    return _emit(node)


def _dec_classlib_alias_operand(buf, i, end, syms):
    """ALIAS operand: a bare symbol or a grouped value (r71-classlib)."""
    if i + 3 <= end and buf[i] == S.SYM:
        return _sym(syms, S.u16(buf, i + 1)), i + 3
    node, k, ungrouped = dec_set_value(buf, i, end, syms, sid=0x7E)
    return _emit_classlib_lib(node, ungrouped), k


def _dec_classlib_in_operand(buf, i, end, syms):
    """IN operand: a bare fb name or a grouped value (r71-classlib)."""
    node, k, ungrouped = dec_set_value(buf, i, end, syms, sid=0x7E)
    return _emit_classlib_lib(node, ungrouped), k


_NAME_OPERAND_UNSUPPORTED = (
    "SCATTER/GATHER variant outside measured round-17 forms")
"""The NAME-operand bank's own refusal, pinned by round 42."""


def _name_operand(buf, t, end, syms):
    """SCATTER/GATHER NAME operand (round-28 W4): m.x memvar ref or a two-part
    member.sym path, exactly as measured under those leads (Xfrxcmd1 s0[21],
    _reportlistener s54[7]/[12])."""
    if t + 5 <= end and buf[t] == S.WORKAREA_REF \
            and buf[t + 1] == 0x0D and buf[t + 2] == S.SYM:
        return MemvarRef(_sym(syms, S.u16(buf, t + 3))), t + 5
    if t + 6 <= end and buf[t] == S.MEMBER and buf[t + 3] == S.SYM:
        return MemberPath([_sym(syms, S.u16(buf, t + 1)),
                           _sym(syms, S.u16(buf, t + 4))]), t + 6
    if t + 3 <= end and buf[t] == S.SYM:
        # r48-valsweep: a bare object name is the third operand spelling —
        # `SCATTER NAME o` -> 5e 4a f7 <sym>, `GATHER NAME o` -> 5f 4a f7 <sym>
        return Sym(_sym(syms, S.u16(buf, t + 1))), t + 3
    if t + 4 <= end and buf[t] == S.WITHREF and buf[t + 1] == S.SYM:
        # r58-tail: the fourth spelling is the WITH-scoped reference the
        # expression reader has read since round 28 — inside a WITH block,
        # `SCATTER MEMO NAME .oMember` -> 5e 1b 4a e2 f7 <sym>. It rides both
        # leads, every 08/1b prefix and a trailing 01 ADDITIVE.
        return WithMemberPath([_sym(syms, S.u16(buf, t + 2))]), t + 4
    raise Unsupported(_NAME_OPERAND_UNSUPPORTED)


def _sg_sym_list(buf, t, end, syms, what):
    """A 07-joined f7 symbol list — the FIELDS <FieldNameList> items."""
    out = []
    while True:
        if t + 3 > end or buf[t] != S.SYM:
            raise Unsupported(what)
        out.append(_sym(syms, S.u16(buf, t + 1)))
        t += 3
        if t + 1 < end and buf[t] == S.ARGJOIN and buf[t + 1] == S.SYM:
            t += 1
            continue
        return out, t


def _sg_str_list(buf, t, end, what):
    """A 07-joined string list — the FIELDS LIKE / EXCEPT skeletons."""
    out = []
    while True:
        if t >= end or buf[t] not in (S.STR, S.STR2):
            raise Unsupported(what)
        text, t = _dec_str_arg(buf, t, end)
        out.append(text)
        if t + 1 < end and buf[t] == S.ARGJOIN \
                and buf[t + 1] in (S.STR, S.STR2):
            t += 1
            continue
        return out, t


def _sg_fields(buf, t, end, syms, what):
    """The FIELDS clause after a SCATTER/GATHER destination (r58-fieldlist).

    `11 [18 <skeletons>] [bc <skeletons>]` for the LIKE / EXCEPT forms — which
    may appear TOGETHER, LIKE first, measured as
    `SCATTER FIELDS LIKE a EXCEPT b MEMVAR` -> 5e c2 11 18 <str> bc <str> — and
    `11 <field names>` for the plain list, which carries no qualifier byte and
    whose items are f7 symbols rather than fb strings. Items join with 07 and a
    qualifier appears once for its whole list. The clause is stored AFTER the
    destination whichever way the source spells it.
    """
    t += 1                                  # the 11 FIELDS mark
    names = like = excep = None
    if t < end and buf[t] == S.SCATTER_FIELDS_LIKE:
        like, t = _sg_str_list(buf, t + 1, end, what)
    if t < end and buf[t] == S.SCATTER_FIELDS_EXCEPT:
        excep, t = _sg_str_list(buf, t + 1, end, what)
    if like is None and excep is None:
        names, t = _sg_sym_list(buf, t, end, syms, what)
    return names, like, excep, t


def _dec_scatter_gather(buf, end, syms, *, verb, what):
    """SCATTER (0x5e) and GATHER (0x5f), one clause grammar for both verbs.

        <lead> [08 BLANK] [1b MEMO] <destination> [11 FIELDS ...] [01 ADDITIVE]

    r58-destbank measured the destination bank: c2 is MEMVAR, 1b is MEMO and 08
    is BLANK, the two modifiers stored BEFORE the destination in a fixed
    08-then-1b order that does not depend on how the source spells them. A
    modifier never stands without a destination — VFP9 rejects SCATTER MEMO and
    SCATTER BLANK — and BLANK is SCATTER-only, which GATHER rejects. The other
    destinations are 28 f7 <arr> (SCATTER TO), 15 f7 <arr> (GATHER FROM) and
    4a <operand> (NAME). Every selector byte is CONTEXTUAL beneath these two
    leads and never a global token.
    """
    scatter = verb == "SCATTER"
    t = 1
    blank = memo = False
    if scatter and t < end and buf[t] == S.SCATTER_BLANK_MARK:
        blank = True
        t += 1
    if t < end and buf[t] == S.SCATTER_MEMO_MARK:
        memo = True
        t += 1

    memvar = additive = False
    target = source = name_obj = None
    names = like = excep = None
    # An operand or list this arm cannot resolve is reported as THIS lead's
    # variant, not as whatever the inner reader happened to say: beneath 5e/5f
    # every selector is contextual, so an unresolvable operand means the shape
    # is not one of the measured spellings, and the census keeps one class per
    # verb instead of fragmenting into the inner readers' messages.
    try:
        if t < end and buf[t] == S.SCATTER_MEMVAR_MARK:
            memvar = True
            t += 1
        elif scatter and t + 4 <= end and buf[t] == S.TO_MARK \
                and buf[t + 1] == S.SYM:
            target = _sym(syms, S.u16(buf, t + 2))
            t += 4
        elif not scatter and t + 4 <= end and buf[t] == S.GATHER_FROM_MARK \
                and buf[t + 1] == S.SYM:
            source = _sym(syms, S.u16(buf, t + 2))
            t += 4
        elif t < end and buf[t] == S.SCATTER_NAME_MARK:
            node, t = _name_operand(buf, t + 1, end, syms)
            name_obj = _emit(node)
        else:
            raise Unsupported(what)
        # r58-additive: ADDITIVE is a 01 on the NAME destination and on that
        # destination only, sitting before any FIELDS clause.
        if scatter and name_obj is not None and t < end \
                and buf[t] == S.SCATTER_ADDITIVE_MARK:
            additive = True
            t += 1
        if t < end and buf[t] == S.FIELDS_MARK:
            names, like, excep, t = _sg_fields(buf, t, end, syms, what)
    except Unsupported as exc:
        # `_name_operand`'s own message names the NAME-operand bank and is
        # pinned by round 42; everything else beneath these leads — a symbol
        # index past the table, a malformed FIELDS list — is reported as this
        # verb's variant so the census keeps one class per verb.
        if str(exc) == _NAME_OPERAND_UNSUPPORTED:
            raise
        raise Unsupported(what) from None
    if t != end:
        raise Unsupported(what)
    if scatter:
        return ScatterStmt(target=target, memvar=memvar, memo=memo,
                           blank=blank, name_obj=name_obj, additive=additive,
                           fields_names=names, fields_like=like,
                           fields_except=excep)
    return GatherStmt(source=source, name_obj=name_obj, memvar=memvar,
                      memo=memo, fields_names=names, fields_like=like,
                      fields_except=excep)


def _sg_fields_text(ast) -> str:
    """The FIELDS clause back to source, or "" when there is none."""
    if ast.fields_names:
        return "FIELDS " + ", ".join(ast.fields_names)
    out = []
    if ast.fields_like:
        out.append("FIELDS LIKE " + ", ".join(ast.fields_like))
    if ast.fields_except:
        out.append(("EXCEPT " if ast.fields_like else "FIELDS EXCEPT ")
                   + ", ".join(ast.fields_except))
    return " ".join(out)


def _emit_scatter_gather(ast):
    """SCATTER / GATHER back to source (r58-destbank, -fieldlist, -additive).

    The wire stores `[08 BLANK] [1b MEMO] <destination> [01 ADDITIVE]
    [11 FIELDS]`; the source spells the MEMVAR destination first and its
    modifiers after it, and the TO / FROM / NAME destinations after their
    modifiers. Both spellings compile to the same bytes — the oracle measured
    every order. ADDITIVE closes the NAME destination, so when it is present the
    FIELDS clause is spelled BEFORE the destination, which is the order the
    oracle measured (`SCATTER FIELDS fld0 NAME oRec ADDITIVE`); with no ADDITIVE
    the clause is written last, as law 2 proved.
    """
    scatter = isinstance(ast, ScatterStmt)
    fields = _sg_fields_text(ast)
    additive = scatter and ast.additive
    parts = ["SCATTER" if scatter else "GATHER"]
    if ast.memvar:
        parts.append("MEMVAR")
        if ast.memo:
            parts.append("MEMO")
        if scatter and ast.blank:
            parts.append("BLANK")
        if fields:
            parts.append(fields)
        return " ".join(parts)
    if ast.memo:
        parts.append("MEMO")
    if scatter and ast.blank:
        parts.append("BLANK")
    if additive and fields:
        parts.append(fields)
        fields = ""
    if scatter and ast.target is not None:
        parts += ["TO", ast.target]
    elif not scatter and ast.source is not None:
        parts += ["FROM", ast.source]
    else:
        parts += ["NAME", ast.name_obj]
    if additive:
        parts.append("ADDITIVE")
    if fields:
        parts.append(fields)
    return " ".join(parts)


def _jump_target(buf, k, end, what, with_fd=True):
    # One frame jump target following a frame opener's condition/expression.
    # Two measured widths of the SAME anchor -- the distance from the
    # post-prologue code base to the bound sentinel prefix; the frame walk
    # verifies the value against the real layout either way, so identity is
    # checked, never assumed:
    #   short: fd f9 05 <u16 LE>   dominant corpus spelling
    #   long:  fd e9 00 <u32 LE>   the same anchor past the u16 range; carried
    #       by 548 of 720 captured frame-shape fail streams at this tree
    #       (round-28 W3 census), always inside large methods whose jump
    #       distance outgrows one byte pair.
    # with_fd=False reads the fd-less clause words (ELSE / TRY / CATCH /
    # FINALLY), which sit after no expression. Returns (rel_target, end).
    if with_fd:
        if k >= end or buf[k] != S.FD:
            raise Unsupported(f"{what} closer missing")
        k += 1
    if k + 4 == end and buf[k] == S.INT16 and buf[k + 1] == 0x05:
        return S.u16(buf, k + 2), end
    if k + 6 == end and buf[k] == S.INT32 and buf[k + 1] == 0x00:
        return int.from_bytes(buf[k + 2:k + 6], "little"), end
    raise Unsupported(f"{what} frame shape")


# ---- round-29 structured statement leads (lane r29-statement-leads) ------------------------
# Every class here backs one oracle-swept lead byte (CMD_SWEEP.md) extended only by
# census-gated corpus variants; unmeasured clause bytes keep the generic raise.


@dataclass
class IndexOnStmt:
    """26 20 fc <expr> fd ca <f7 <tag>|fb|d9 <u16 len> <bytes>> [3c|01|bd|d4]*
    [13 fc <cond> fd] - INDEX ON..TAG. The TAG operand is either a symbol
    reference or a QUOTED literal whose opcode carries the quote style
    (round-40 lane F: oracle 'INDEX ON XX000 TAG "I01" ADDITIVE' ->
    2620fcf70000fdcad9030049303101, the single-quoted spelling the same with fb;
    carrier xfrxlib.vcx::xfcont s66 stmt18).
    Tails: 3c=DESCENDING (CMD_SWEEP round-10 clause pass), 01=ADDITIVE
    (clause table; census c79070eeff459e07 s67), bd=ASCENDING and d4=CANDIDATE
    (round-33 index lane: _webbrowser3 s15 stmt74 'INDEX ON IndexValue TAG
    IndexValue ASCENDING ADDITIVE' <-> ...caf70a00bd01; VFPxWorkbookXLSX s13
    stmt13 'INDEX ON BINTOC(..)+.. TAG cellindex CANDIDATE' <-> ...caf72a00d4),
    13=FOR (census c79070eeff459e07 s16). Each flag at most once; any other
    tail byte keeps 'INDEX clause 0x.. unmeasured'."""
    expr: object
    tag: str          # already-rendered TAG spelling: a bare name or a quoted literal
    descending: bool = False
    additive: bool = False
    for_cond: object = None
    ascending: bool = False
    candidate: bool = False


@dataclass
class AssertStmt:
    """a9 fc <expr> [fd [1d fc <dq-string>]] - ASSERT (CMD_SWEEP row) with the
    corpus MESSAGE clause (1d marker, foxcharts s18 family)."""
    expr: object
    message: object = None


@dataclass
class AverageStmt:
    """08 [13 fc <cond> fd] 28 <targets> (<fc expr fd>)* - AVERAGE, same
    targets-first wire layout as SUM/COUNT (iter. 38); CMD_SWEEP row + census."""
    target: object
    expr: object
    for_cond: object = None

    def __init__(self, target, expr, for_cond=None):
        self.target = target if isinstance(target, list) else [target]
        self.expr = expr if isinstance(expr, list) else [expr]
        self.for_cond = for_cond


@dataclass
class AlterTableStmt:
    """69 31 <table> <kw> d5 f7 <col> fb <type> [(02 fc..fd [07 ..]* 03)] [d6].
    kw c0=ADD (CMD_SWEEP row) / bc=ALTER (census quote.scx gold pair);
    d6=NULL column clause as in CREATE CURSOR (round-29 F03 convention)."""
    table: object     # literal name or expression node ('(lcFileName)')
    action: str       # 'ADD' | 'ALTER'
    column: str
    type: str
    widths: list      # width/decimal expressions, possibly empty
    null: bool = False


@dataclass
class ModifyStmt:
    """2f bc|12|1b ... - MODIFY COMMAND (bc, CMD_SWEEP) / MODIFY FILE (12) /
    MODIFY MEMO (1b); NOEDIT c5 and RANGE c7 bound by _webview gold pairs,
    NOWAIT 3a per CMD_SWEEP."""
    kind: str         # 'COMMAND' | 'FILE' | 'MEMO'
    target: object    # literal name, expression node, or dotted path string
    noedit: bool = False
    range_args: object = None
    nowait: bool = False
    # r48-valsweep: the editing-window clauses, shared by every kind. VFP stores
    # them in a canonical order whatever order the source wrote them in, so
    # emission uses the documented order and recompiles to the same frame.
    window: object = None     # 2c <name>
    in_window: object = None  # 16 <name>
    same: bool = False        # cf
    nomenu: bool = False      # ca
    save: bool = False        # 25
    codepage: object = None   # 51 fc <n> fd


@dataclass
class CalculateStmt:
    """7d [clauses] [28 [04] <targets>] <item> [07 <item>]* - CALCULATE.

    Items and TO targets are both joined by ARGJOIN 07. Each item is
    `<selector> 02 [<fc expr fd> [07 <fc expr fd>]*] 03`; the selector table is
    the eight aggregate functions bc..c3 (round59_calcitems), a no-argument item
    (CNT) is an empty group and NPV rides two argjoin-07 expressions.

    Every clause rides AHEAD of the 28 TO mark in one fixed frame order —
    scope, FOR, WHILE — whatever order the source spelled them, so the SOURCE
    order is recovered from the symbol table (r49-clauseorder, under a third
    lead) and carried in `clause_first`. `28 04` marks TO ARRAY, and a
    CALCULATE with no TO section at all compiles (round59_calcclause)."""
    targets: list     # lvalue nodes
    items: list       # (function-name, [arg-expr-node, ...]) pairs
    scope: object = None        # (word, count-expr or None)
    for_cond: object = None
    while_cond: object = None
    to_array: bool = False
    clause_first: bool = True   # the source wrote the clauses before TO


@dataclass
class ReportFormStmt:
    """3f 14 <form> then the clause bank in wire order — ORACLE-MEASURED r69-bank.

    Each clause is a (kind, payload) pair. Flag kinds carry the keyword
    string; RANGE / FOR / WHILE / HEADING / NEXT / RECORD / TO FILE /
    OBJECT / NAME carry their operand. The emitter writes the pairs in
    list order, which is the wire order."""
    form: object
    clauses: list = field(default_factory=list)


@dataclass
class RemoveTableStmt:
    """97 31 fb <name> [cd] - REMOVE TABLE (CMD_SWEEP row); cd=DELETE bound by
    the chartbillprint.scx gold pair 'REMOVE TABLE Foo11 DELETE'."""
    name: str
    delete: bool = False


def _dec_sql_like_cond(buf, i, end, syms):
    """SQL WHERE condition matrix, round-34 lane A — bound OFFLINE from
    already-stored source<->bytecode pairs (mhxpcontrol.vcx extwindow s0 stmt3
    <-> 'SELE EXTTEXT FROM (EXTFILE) WHERE EXTTYPE LIKE SQLTYPE AND EXTTEXT
    LIKE SQLTEXT ORDER BY EXTTEXT INTO ARRAY EXTTEMP'; text s6 stmt10 <-> the
    LostFocus SELECT). Measured grammar, exactly and only:

        cond  := 43 f7<u16> f7<u16> cf          -- cf binds LIKE (SQL_LIKE_MARK)
        chain := cond (f0 <u16> cond 09)*       -- short-circuit AND spelling

    Both LIKE operands are plain symbol pushes; every joiner's u16 counts the
    encoded right side plus its apply byte (skip = len(right) + 1 = 9 for the
    measured two-condition shape), enforced positionally below. The chain must
    close on the clause's own fd. ANY other byte raises Unsupported so the
    caller falls back to the generic expression decoder and every unmeasured
    variant stays loudly rejected.

    Returns (node, index just past the closing fd); node is a Bin("LIKE") /
    Bin("AND") tree whose emission is the stored wording ('A LIKE B AND C LIKE
    D' — VFP's AND is itself short-circuiting, so recompiles are identical).
    """
    def pair(p):
        if p + 8 > end or buf[p] != S.CALL_OPEN or buf[p + 1] != S.SYM \
                or buf[p + 4] != S.SYM or buf[p + 7] != S.SQL_LIKE_MARK:
            raise Unsupported(
                "SQL WHERE condition outside measured LIKE matrix")
        lhs = Sym(_sym(syms, S.u16(buf, p + 2)))
        rhs = Sym(_sym(syms, S.u16(buf, p + 5)))
        return Bin("LIKE", lhs, rhs), p + 8

    node, j = pair(i)
    while j + 3 <= end and buf[j] == S.SC_AND:
        skip = S.u16(buf, j + 1)
        rhs_node, q = pair(j + 3)
        if q != j + 3 + (skip - 1) or q >= end or buf[q] != S.AND_APPLY:
            raise Unsupported("SQL WHERE AND joiner unmeasured")
        node = Bin("AND", node, rhs_node)
        j = q + 1
    if j >= end or buf[j] != S.FD:
        raise Unsupported("SQL WHERE condition outside measured LIKE matrix")
    return node, j + 1


def _dec_statement_checked(buf, syms):
    try:
        return _dec_statement(buf, syms)
    except (IndexError, _struct.error) as e:
        # A truncated/odd shape is an UNSUPPORTED statement, not a crash — same discipline as
        # the reader: one statement's failure must cost one statement.
        raise Unsupported(f"malformed statement: {e}") from e
    except RecursionError as e:
        # Nested 43-groups recurse in _dec_group -> _dec_operand -> _dec_expr (~2-3 frames
        # per group), so a hostile or corrupted stream can exhaust the Python stack. A stack
        # blowout is one unrecognised construct like any other — Unsupported, never a crash.
        raise Unsupported("statement nesting exceeds recursion budget") from e


# Round-37 package P7 (C08, probes H1-H8): the measured CAST AS-type matrix.
# The type letter always rides the string payload fb0100<letter>; the number of
# trailing width/decimal sub-groups is measured PER LETTER and nothing else is
# bound: N takes two f8 literals (width, decimals), C/B/Q one (width),
# D/T/Y/L/I none. Every other letter or arity stays rejected.
_CAST_TYPE_ARITY = {"N": 2, "C": 1, "B": 1,
                    "D": 0, "T": 0, "Y": 0, "L": 0, "I": 0,
                    # r40 group43 ORACLE-MEASURED (probes/oracle_harvest/
                    # round40_group43_streams.json c01: 'lnFSize = CAST(
                    # loNode.Attributes.Item(0).NodeTypedValue AS F(8,2))'
                    # compiles fb0100'F' f80108 f80102 e41a0f): F rides the
                    # SAME width+decimal pair as N. Same batch's c04 records
                    # that the ONE-group spelling 'AS F(8)' is real VFP and
                    # stays UNBOUND — this table holds one arity per letter,
                    # so widening it is a separate measured step with no
                    # corpus carrier to force it. Carrier VFPxWorkbookXLSX.vcx::
                    # vfpxworkbookxlsx readstylesxml stmt#55
                    # 54F7140010FC4343F80100F40600F43500E52A00F73600
                    # FB010046 F80108 F80102 E41A0F <-> stored L2437
                    # 'lnFSize = CAST(loNode.Attributes.Item(0).NodeTypedValue
                    # AS F(8,2))': payload 'F' followed by exactly two f8
                    # groups 8 and 2, which is the only reading that makes the
                    # gap a whole number of INT8 groups AND matches the stored
                    # spelling. The zero-argument 'AS F' spelling (L1451/L1457
                    # of the same class) rides the x1a channel directly and is
                    # unaffected.
                    "F": 2,
                    # r42 I10 ORACLE-MEASURED (probes/oracle_harvest/
                    # round42_cast_streams.json): Q is varbinary. Bare AS Q
                    # (zero groups) already rode the stock closer; AS Q(n)
                    # compiles fb0100'Q' + ONE f8 width, same arity as C/B.
                    # s0005 'RETURN CAST(.NULL. AS Q(16))' <->
                    # 42fc43e4fb010051f80210e41a0f, byte-identical to
                    # 6c33aa10a70f595e:16 stmt3. Widths 1/8/16/254 all emit
                    # one f8 (s0009/s0010/s0002/s0011). s0013 'AS Q(8,2)'
                    # compiles TWO f8 groups and stays UNBOUND — one arity
                    # per letter, same rule as F(8).
                    "Q": 1}


def _fold_cast_args(stack):
    """CAST closer 1a 0f: consume the e4 Null marker and optional INT8 widths.

    Zero extra nums: any type letter, stock [value, Str, Null] -> [value, Str].
    One/two INT8 nums: only when ``_CAST_TYPE_ARITY[letter]`` matches that
    count; fold into the type text ('Q(16)', 'N(20,12)'). f9/e9/fa widths,
    a wrong count, and leftover values keep
    ``CAST argument/type marker shape``.
    """
    if not stack or not isinstance(stack[-1], Null):
        raise Unsupported("CAST argument/type marker shape")
    stack.pop()
    nums = []
    while stack and isinstance(stack[-1], Num) and stack[-1].op == S.INT8:
        nums.append(stack.pop())
    nums.reverse()
    if len(stack) != 2 or not isinstance(stack[-1], Str):
        raise Unsupported("CAST argument/type marker shape")
    if not nums:
        return
    typ = stack[-1].text
    if _CAST_TYPE_ARITY.get(typ) != len(nums):
        raise Unsupported("CAST argument/type marker shape")
    if len(nums) == 2:
        stack[-1] = Str("%s(%s,%s)" % (typ, nums[0].spelling, nums[1].spelling))
    else:
        stack[-1] = Str("%s(%s)" % (typ, nums[0].spelling))


def _dec_assign_cast_numeric(buf, lv, m, end, syms):
    """Round-34 lane C — the measured ``CAST(x AS N(w,d))`` assignment matrix,
    generalized by round-37 package P7 to the full measured AS-type family.

    Wire (all carriers are ASSIGN statements; r34 census blockers.jsonl +
    corpus bytes; H1-H8 fresh oracle compiles): ::

      54 <lvalue> 10 fc 43 <value> fb0100<letter> [f8<dg><w>] [f8<dg><d>]
      e4 1a 0f [tail]

    Measured arms (round37_findings.json C08 evidence rows — exactly these):
    N+width+decimals, C+width, D, T, Y, L, I, B+width. H1 'CAST(m.lnV AS
    N(14, 7))' <-> ...fb01004ef8020ef80107e41a0f; H2 C(254) rides ONE f8;
    H8 B(7) likewise; D/T/Y/L/I close straight after the letter.

    Carriers (VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx s34, stored
    METHODS alignment):

      stmt14 <-> L1424 'lnMSec  = CAST(c_cells.cellvalue AS N(20,12))'
             = 54F7070010FC43F40B00F70D00FB01004EF80214F8020CE41A0F
      stmt24 <-> L1435 'lnMSec  = CAST(c_cells.cellvalue AS N(20,12)) - lnDays'
             = same closer + F7050008 (the measured SUB tail)
      s64 stmt65 <-> L2283 'lnWidth = CAST(loColumn.getAttribute("width")
             AS N(14,7)) - 0.7109375' = same closer + FLOAT-literal SUB tail
             (the P7 tail arm below; releases predeclared key faa199b32ddf0b1c:64)

    Envelope discipline -- every check below rejects loudly via the caller
    re-raising the stock decoder's own Unsupported, so an unmeasured variant
    can neither lift nor change any blocked message:

      - exactly ONE ``e4 1a 0f`` closer occurrence in the statement;
      - the type marker is a SINGLE measured letter riding the string payload
        (P7); near-neighbour spellings ('n', F(8,2), multi-char markers)
        carry no measured binding and stay blocked;
      - width/decimals arrive as three-byte INT8 (f8) literal sub-groups
        counted by the per-letter arity table above -- missing or extra
        groups, or f9/e9/fa-encoded numbers in those slots stay rejected;
      - the value is ONE node decoded from inside the leading 43 group;
      - the statement tail is empty, exactly the 4-byte bare-symbol op form,
        or -- P7, the s64 stmt65 shape -- exactly ONE 11-byte FLOAT literal
        followed by ONE arithmetic operator byte; anything else stays
        rejected.

    The wire's trailing ``e4`` (.NULL.) argument slot is consumed by this
    matrix; emission re-uses the already-measured x1a CAST channel
    ("CAST(<value> AS <type>)"), namespace ('x1a_builtin', 0x0F) unchanged.
    """
    if not end > 16:
        raise Unsupported("cast assignment too short")
    k = buf.find(b"\xe4\x1a\x0f")
    if k < 0 or buf.find(b"\xe4\x1a\x0f", k + 1) >= 0:
        raise Unsupported("cast closer missing/ambiguous")
    # Type literal + measured width/decimal sub-groups: scan back from the
    # closer for a string payload whose declared length fills exactly up to a
    # whole number of INT8 groups before the closer, with the payload being a
    # single letter whose measured arity matches that count (same
    # nearest-to-closer candidate convention as the r34 lane).
    tpos = None
    tlit_end = None
    for cand in range(k - 4, max(k - 46, 0), -1):
        if buf[cand] not in (S.STR, S.STR2):
            continue
        cand_end = cand + 3 + S.u16(buf, cand + 1)
        gap = k - cand_end
        if gap < 0 or gap % 3:
            continue
        typ = _payload_text(buf[cand + 3:cand_end])
        if _CAST_TYPE_ARITY.get(typ) != gap // 3:
            continue
        if any(buf[p] != S.INT8 for p in range(cand_end, k, 3)):
            continue
        tpos, tlit_end = cand, cand_end
        break
    if tpos is None:
        raise Unsupported("cast type literal missing")
    nums = [str(buf[p + 2]) for p in range(tlit_end, k, 3)]
    typ = _payload_text(buf[tpos + 3:tlit_end])
    if len(nums) == 2:
        type_text = "%s(%s,%s)" % (typ, nums[0], nums[1])
    elif len(nums) == 1:
        type_text = "%s(%s)" % (typ, nums[0])
    else:
        type_text = typ
    if buf[m] != 0x10 or buf[m + 1] != S.FC:
        raise Unsupported("assignment marker missing")
    if buf[m + 2] != S.CALL_OPEN:
        raise Unsupported("cast group lead missing")
    ves, vk = _dec_expr(buf, m + 3, tpos, syms,
                        stop_bytes=frozenset({S.STR, S.STR2}))
    if len(ves) != 1 or vk != tpos:
        raise Unsupported("cast value unresolved")
    cast = Call(("x1a_builtin", 0x0F), [ves[0], Str(type_text)])
    cast_end = k + 3
    tail = buf[cast_end:end]
    if len(tail) == 4 and tail[0] == S.SYM and tail[3] in (
            S.ADD, S.SUB, S.MUL, S.DIV):
        rhs = Sym(_sym(syms, S.u16(buf, cast_end + 1)))
        opn = {S.ADD: "+", S.SUB: "-", S.MUL: "*", S.DIV: "/"}[tail[3]]
        return Assign(lv, Bin(opn, cast, rhs))
    if len(tail) == 12 and tail[0] == S.FLOAT and tail[11] in (
            S.ADD, S.SUB, S.MUL, S.DIV):
        # P7 measured FLOAT-op tail (s64 stmt65 '- 0.7109375'): one 11-byte
        # fa-literal in the same framing the expression reader consumes
        # (marker + two fingerprint bytes + little-endian double) followed by
        # ONE operator byte. A dangling FLOAT operand with no operator stays
        # rejected below.
        rhs = Flt(_fmt_float(_struct.unpack_from("<d", tail, 3)[0]),
                  tail[1], tail[2])
        opn = {S.ADD: "+", S.SUB: "-", S.MUL: "*", S.DIV: "/"}[tail[11]]
        return Assign(lv, Bin(opn, cast, rhs))
    if cast_end != end:
        raise Unsupported("unmeasured cast-statement tail")
    return Assign(lv, cast)


def _dec_assign_chain_twin(lv, buf, t, end, syms):
    """Round37 wave-2 P12 (W05, probes u07/u08) — the oracle-forced
    chain-assignment twins, reached ONLY from the ASSIGN reader's failure path.

    Corpus carriers pinned byte-exact in round37_wave2_carriers.json; fresh
    compiles of the authored witnesses u07/u08 compare
    equal_modulo_symbol_indexes against them (39/38 bytes):

        THIS.Columns(lnRelCol).Check1.Value =
                Not This.Columns(lnRelCol).Check1.Value   (ff363…:1  stmt 5)
            54 f40300 e50800 fc f70000 fd03 f40900 f70a00 10 fc
            43 00 f70000 f40300 e50800 f40900 f70a00 0a
        THIS.Columns(1).Check1.Value =
                Not This.Columns(1).Check1.Value          (ff363…:2  stmt 4)
            54 f40300 e50800 fc f80101 fd03 f40900 f70a00 10 fc
            43 f80101 f40300 e50800 f40900 f70a00 0a

    The lvalue already binds through the round-33 indexed-member arm (this
    exact carrier is cited there); what declined was the RHS — an args-first
    call-value chain whose POST-LINK f4 hop run `_dec_chain_group` declines
    (P8 boundary). W05 forces that hop ONLY in this twin topology with the
    IDENTICAL member-chain-with-mid-call on both sides:

        43 <one packet> f4 <root> e5 <link> f4 <hop>+ f7 <term> 0a

    packet forms measured (and the only two admitted):
      variable subscript   43 00 f7 <u16>
      literal subscript    43 f8 <digits> <u8 value>     (stock INT8 reading)

    postfix NOT rides byte 0a (required — the no-NOT spelling is unmeasured).
    Anything else — other packet shapes, extra roots/links/packets, missing
    NOT, trailing bytes, or sides whose decoded chains differ — declines and
    the stock rejection stands verbatim."""
    if not isinstance(lv, ObjectChain) or len(lv.calls) != 1:
        raise Unsupported("chain-twin lvalue family")
    link_l, args_l = lv.calls[0]
    if len(args_l) != 1 or not lv.recv or len(lv.tail) < 2:
        raise Unsupported("chain-twin lvalue arity")
    if t >= end or buf[t] != S.CALL_OPEN:
        raise Unsupported("chain-twin value frame")
    j = t + 1
    if j + 4 <= end and buf[j] == 0x00 and buf[j + 1] == S.SYM:
        arg = Sym(_sym(syms, S.u16(buf, j + 2)))
        j += 4
    elif j + 3 <= end and buf[j] == S.INT8:
        arg = Num(str(buf[j + 2]), op=S.INT8,
                  width=buf[j + 1])   # same construction as the stock reader
        j += 3
    else:
        raise Unsupported("chain-twin subscript frame")
    if j + 3 > end or buf[j] != S.MEMBER:
        raise Unsupported("chain-twin receiver run")
    root = _sym(syms, S.u16(buf, j + 1))
    j += 3
    if j + 3 > end or buf[j] != S.ARRAY_ELEM_CALL:
        raise Unsupported("chain-twin mid-call link")
    link_r = _sym(syms, S.u16(buf, j + 1))
    j += 3
    hops = []
    while j + 3 <= end and buf[j] == S.MEMBER:
        hops.append(_sym(syms, S.u16(buf, j + 1)))
        j += 3
    if not hops or j + 3 > end or buf[j] != S.SYM:
        raise Unsupported("chain-twin hop tail")
    term = _sym(syms, S.u16(buf, j + 1))
    j += 3
    if j >= end or buf[j] != S.NOT:
        raise Unsupported("chain-twin postfix NOT")
    j += 1
    if j != end:
        raise Unsupported("chain-twin trailing bytes")
    rhs = ObjectChain([root], [(link_r, [arg])], hops + [term])
    if (rhs.recv, rhs.calls, rhs.tail) != (lv.recv, lv.calls, lv.tail):
        raise Unsupported("chain-twin sides differ")
    return Assign(lv, Not(rhs))


def _dec_quad_vartype_read(buf, q, end, syms, terminal):
    """One `VARTYPE(<memvar-array element read>)` call of the round-37 wave-2
    P14 quad (W07; probes v02/v04/v05). Measured bytes, both spellings:

        43 43 00 f5 0d f7 <u16 sub> f5 0d (f6 | e5) <u16 arr> [f7 <u16 prop>]
        ea d9

    Outer frame = the VARTYPE call; inner frame = the element read whose sole
    argument is the ByVal-marked memvar subscript push. The alias-M run that
    follows carries the array reference and TERMINATES the read:
        terminal=True  — the read does NOT continue past its value: the ref
                         rides TERMINAL f6 verbatim (v04 conjunct 1,
                         '43 43 00 f50df7<sub> f50df6<arr> ead9'; the corpus
                         twins reuse these bytes exactly). No property.
        terminal=False — the value CONTINUES onto one member: P4's measured
                         e5 continuation with EXACTLY ONE property read
                         (the carriers' .X/.Y hops ride e5+f7).

    The ByVal marker 00 and the VARTYPE escape id d9 are part of every
    measured carrier of this envelope and are required. Returns the Call node
    and the position after 'ea d9'."""
    if q + 2 > end or buf[q] != S.CALL_OPEN or buf[q + 1] != S.CALL_OPEN:
        raise Unsupported("quad read frames")           # VT frame + read frame
    q += 2
    if q + 1 > end or buf[q] != 0x00:          # ByVal argument marker
        raise Unsupported("quad read ByVal marker")
    q += 1
    if q + 5 > end or buf[q] != 0xF5 or buf[q + 1] != 0x0D \
            or buf[q + 2] != S.SYM:            # m.<sub> subscript push
        raise Unsupported("quad read subscript")
    sub = MemvarRef(_sym(syms, S.u16(buf, q + 3)))
    q += 5
    if q + 2 > end or buf[q] != 0xF5 or buf[q + 1] != 0x0D:
        raise Unsupported("quad read memvar run")
    q += 2
    if q + 3 > end or buf[q] not in ((S.NAME,) if terminal
                                     else (S.ARRAY_ELEM_CALL,)):
        raise Unsupported("quad read array spelling")
    arr = _sym(syms, S.u16(buf, q + 1))
    q += 3
    if terminal:
        read = ArrayRef("m." + arr, [sub])
    else:
        if q + 3 > end or buf[q] != S.SYM:     # exactly one property hop
            raise Unsupported("quad read property hop")
        read = MidCall(["m"], arr, [sub], _sym(syms, S.u16(buf, q + 1)))
        q += 3
    if q + 2 > end or buf[q] != S.ESCAPE or buf[q + 1] != 0xD9:
        raise Unsupported("quad read VARTYPE closer")   # ea d9, W07 law
    return Call(("builtin", 0xD9), [read]), q + 2


def _dec_if_memvar_quad_cond(buf, p, end, syms):
    """Round38 P14 (round37 wave-2 W07, probes v01-v08) — the mixed memvar
    quad condition, reached ONLY from the IF reader's failure path.

    Corpus carriers byte-exact (round37_wave2_carriers.json
    '3f133997f6b20709:27#164', sha256 7dc1…e03; the other three keys are its
    ref/f9-target twins):

        IF VARTYPE(m.laPoints(m.j)) <> "O" OR ;
            VARTYPE(m.laPoints(m.j).X) + VARTYPE(m.laPoints(m.j).Y) <> "NN"

    compiles to a linear RPN stream over THREE VARTYPE calls — each an outer
    call frame around one inner element-read frame (v02's `43 43 <subpacket>
    f50df6<arr> ead9` shape) — joined by the measured comparison glue:

        43 43 00 f50df7<sub> f50df6<arr> ead9     VARTYPE, terminal f6
        d9 <len> <str>                            compared literal
        0f                                        <>
        f1 <u16 skip>                             short-circuit OR prefix
                                                  (skip = len(right)+1)
        43 43 00 f50df7<sub> f50de5<arr> f7<prop> ead9   VARTYPE, e5 hop
        43 43 00 f50df7<sub> f50de5<arr> f7<prop> ead9   VARTYPE, e5 hop
        06                                        + concat (postfix RPN)
        d9 <len> <str>
        0f                                        <>
        0b                                        OR apply

    W07's composition law: the round-30/31 SUPPRESSED mid-window f6 reading
    (mmid) and P4's e5 continuation compose INSIDE ONE statement only under
    this exact EA-wrapper/comparison-glue envelope — v04 is the oracle
    witness equal to all four byte-identical twins modulo symbol indexes,
    the f9 jump-target operand, and the one pinned trailing flag byte
    (offset 73, recorded delta). Anything else here declines and the stock
    rejection stands verbatim."""
    q = p
    vt1, q = _dec_quad_vartype_read(buf, q, end, syms, terminal=True)
    if q + 3 > end or buf[q] != S.STR2:                    # "O"
        raise Unsupported("quad literal truncated")
    n = S.u16(buf, q + 1)
    if q + 3 + n > end:
        raise Unsupported("quad literal payload truncated")
    s1 = Str(_payload_text(buf[q + 3:q + 3 + n]), dq=True)
    q += 3 + n
    if q + 1 > end or buf[q] != S.NE:                      # <>
        raise Unsupported("quad comparison glue")
    q += 1
    if q + 3 > end or buf[q] != S.SC_OR:                   # f1 <u16 skip>
        raise Unsupported("quad short-circuit prefix")
    skip = S.u16(buf, q + 1)
    q += 3
    right_start = q
    vt2, q = _dec_quad_vartype_read(buf, q, end, syms, terminal=False)
    vt3, q = _dec_quad_vartype_read(buf, q, end, syms, terminal=False)
    if q + 1 > end or buf[q] != S.ADD:                     # + concat glue
        raise Unsupported("quad concat glue")
    q += 1
    if q + 3 > end or buf[q] != S.STR2:                    # "NN"
        raise Unsupported("quad literal truncated")
    n = S.u16(buf, q + 1)
    if q + 3 + n > end:
        raise Unsupported("quad literal payload truncated")
    s2 = Str(_payload_text(buf[q + 3:q + 3 + n]), dq=True)
    q += 3 + n
    if q + 1 > end or buf[q] != S.NE:
        raise Unsupported("quad comparison glue")
    q += 1
    # measured wire law (schemas f5_lg2): the skip operand covers the right
    # side plus the apply byte that follows it
    if skip != q - right_start + 1:
        raise Unsupported("quad short-circuit skip mismatch")
    if q + 1 > end or buf[q] != S.OR_APPLY:                # 0b
        raise Unsupported("quad apply opcode")
    cond = ShortCircuit(
        "OR",
        Bin("!=", vt1, s1),
        Bin("!=", Bin("+", vt2, vt3), s2))
    return cond, q + 1                                     # at the fd


def _dec_if_memvar_quad(buf, p, end, syms):
    """Adapter for the IF reader's failure path: parse the measured quad
    condition AND its jump anchor; any decline raises Unsupported so the
    caller re-raises the ORIGINAL stock error verbatim (blocked messages
    cannot shift through this arm, including anchor-shape failures)."""
    cond, k = _dec_if_memvar_quad_cond(buf, p, end, syms)
    rel, _ = _jump_target(buf, k, end, "IF")
    return If(cond, [], rel_target=rel)


def _dec_exprstmt_comma_list(buf, i, end, syms):
    """Round37-wave2 P16: measured comma-list continuation of a lead-86 statement.

    Shape (oracle probes r38-p16 v1/v3/v4; carriers 3f133997f6b20709:28 /
    78429a71ad111792:28): the first `fc <expr>` unit resolves before an
    fd 07 separator and every further unit is spelled `fd 07 fc <expr>`;
    the statement ends exactly after the last unit. Returns the unit list,
    or None when the bytes are anything else — the caller re-raises its stock
    rejection verbatim, so non-carrier behavior is untouched. Hostile or
    truncated unit operands decline the same way (round38-p16 review F1:
    their sub-parses can escape as IndexError/_struct.error, which must not
    resurface as 'malformed statement: …')."""
    try:
        first, k = _dec_expr(buf, i, end, syms, stop_bytes=frozenset({S.FD}))
        if len(first) != 1 or k + 3 > end \
                or buf[k] != S.FD or buf[k + 1] != S.ARGJOIN or buf[k + 2] != S.FC:
            return None
        units = [first[0]]
        while k + 3 <= end and buf[k] == S.FD and buf[k + 1] == S.ARGJOIN \
                and buf[k + 2] == S.FC:
            more, k2 = _dec_expr(buf, k + 3, end, syms,
                                 stop_bytes=frozenset({S.FD}))
            if len(more) != 1 or k2 == k + 3:
                return None
            units.append(more[0])
            k = k2
    except (Unsupported, IndexError, _struct.error):
        # Review F1 hardening: a hostile/truncated unit tail (e.g. a
        # continuation ending fd07fcf7… with the operand u16 cut) can escape
        # the sub-parses above as IndexError/_struct.error instead of
        # Unsupported. Decline those too — the caller re-raises the ORIGINAL
        # stock exception verbatim, so this class keeps its exact historical
        # stock wording instead of being reworded downstream.
        return None
    if k != end:
        return None
    return units


def _try_sql_agg(buf, i, end, syms):
    """SELECT COUNT/SUM/AVG/MIN/MAX. None if the bytes are not that 43-group.

    COUNT(*)            43 04 ea fc
    COUNT(f1)           43 f7 <sym> ea fc
    COUNT(DISTINCT f1)  43 ea ff f7 <sym> ea fc
    SUM/AVG/MIN/MAX(f1) 43 f7 <sym> ea fa/fb/fd/fe
    (r42-tiera3). 04 is MUL elsewhere; these ids are SQL-local.

    r47-sqlagg: the argument is a full EXPRESSION, not only a bare field —
    `MAX(cel.sheet)` is `43 f4 <alias> f7 <field> ea fe`, `SUM(qty * price)`
    is `43 f7 f7 04 ea fa`, `SUM(INT(qty))` nests another call. The closing
    `ea <agg-id>` is the ea pair immediately before the column group's fd;
    nested ea escapes inside the argument are ordinary builtins. Reading only
    the bare-field shape stopped the projection walk at the first such column,
    and the INTO scanner then skipped the rest of the clause region — the
    statement lifted with a silently truncated column list.
    """
    if i >= end or buf[i] != S.CALL_OPEN:
        return None
    j = i + 1
    distinct = False
    if j + 1 < end and buf[j] == S.ESCAPE and buf[j + 1] == S.SQLSEL_AGG_DISTINCT:
        distinct = True
        j += 2
    arg_start = j
    if j < end and buf[j] == S.SQLSEL_AGG_STAR:
        inner = "*"
        j += 1
    elif j + 2 < end and buf[j] == S.SYM:
        inner = _sym(syms, S.u16(buf, j + 1))
        j += 3
    else:
        return _sql_agg_expr(buf, arg_start, end, syms, distinct)
    if j + 1 >= end or buf[j] != S.ESCAPE:
        return _sql_agg_expr(buf, arg_start, end, syms, distinct)
    name = S.SQLSEL_AGG.get(buf[j + 1])
    if name is None:
        return _sql_agg_expr(buf, arg_start, end, syms, distinct)
    j += 2
    if distinct:
        inner = "DISTINCT " + inner
    return SqlAgg(name, inner), j


def _dec_sql_cond(buf, i, end, syms):
    """A SELECT clause condition, which may open with an aggregate operand.

    r47-having: `HAVING COUNT(*) > 1` is `c0 fc 43 04 ea fc f8 01 01 11 fd` —
    the aggregate is an operand in the RPN run, and the generic expression
    decoder has no `ea <agg-id>` callee. Read the aggregate first and seed the
    operand stack with it; everything else is the ordinary decoder."""
    agg = _try_sql_agg(buf, i, end, syms)
    if agg is None:
        return _dec_expr(buf, i, end, syms, stop_bytes=_IF_COND_STOP)
    node, k = agg
    stack = [node]
    _ARENA.append(stack)
    try:
        return _dec_expr_run(buf, k, end, syms, stack,
                             stop_bytes=_IF_COND_STOP)
    finally:
        _ARENA.pop()


def _sql_agg_close(buf, i, end):
    """Index of the fd closing the column group this aggregate opened."""
    depth = 1
    j = i
    while j < end:
        if buf[j] == S.FC:
            depth += 1
        elif buf[j] == S.FD:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def _sql_agg_expr(buf, i, end, syms, distinct):
    """r47-sqlagg: aggregate over an arbitrary expression, or None.

    Stays inert on any mismatch so a stream that lifted before still lifts the
    same way."""
    fd_pos = _sql_agg_close(buf, i, end)
    if fd_pos is None or fd_pos < i + 3:
        return None
    if buf[fd_pos - 2] != S.ESCAPE:
        return None
    name = S.SQLSEL_AGG.get(buf[fd_pos - 1])
    if name is None:
        return None
    try:
        es, k = _dec_expr(buf, i, fd_pos - 2, syms, stop_bytes=_IF_COND_STOP)
    except Unsupported:
        return None
    if len(es) != 1 or k != fd_pos - 2:
        return None
    inner = _emit(es[0])
    if distinct:
        inner = "DISTINCT " + inner
    return SqlAgg(name, inner), fd_pos


def _dec_browse_fields(buf, t, end, syms):
    """The `11` FIELDS item list: `f7 <field> [attributes]` joined by 07.

    Round-28 W4 measured the items (pricelistdetail Command1 s0 stmt16,
    preorder Command4 s0 stmt35, bincode CdCost s0 stmt39): a name, an optional
    `c9 <int>` width and an optional `c2 10 fc<picture>[fd]` :P operand.
    Round-31 added `bf 10 fc<heading>fd` = :H (testrecord /
    attendancereadrecord frmattendancerecord s3 'code:10 :H = ..' and s4
    'code:h=..:10') and, having only those two carriers, closed the per-item
    grammar to the six sequences they spell: ∅ | W | P | W P | W H | H W.

    r53-browsefield authored all fifteen orderings of the three attributes and
    VFP9 compiled every one, so the set is closed by MULTIPLICITY and not by
    order: each attribute at most once, in whatever order the source wrote
    them, and a repetition raises. Unlike the statement's own clause list, a
    field spec stores the SOURCE's order (r49-menusweep), so each column
    records the order it was written in and the emitter writes it back.
    """
    fields = []
    while True:
        if t + 3 > end or buf[t] != S.SYM:
            raise Unsupported("BROWSE FIELDS name form")
        fname = _sym(syms, S.u16(buf, t + 1))
        t += 3
        width = None
        pic = None
        heading = None
        order = []              # measured-sequence state, reset per item
        while t < end:
            if buf[t] == 0xC9:
                order.append("w")
                t += 1
                # measured width operands are plain int tokens only
                if buf[t] == S.INT8 and t + 3 <= end:
                    width = str(buf[t + 2])
                    t += 3
                elif buf[t] == S.INT16 and t + 4 <= end:
                    width = str(_struct.unpack_from("<h", buf, t + 2)[0])
                    t += 4
                else:
                    raise Unsupported("BROWSE FIELDS width form")
            elif t + 1 < end and buf[t] == 0xC2 and buf[t + 1] == S.EQ:
                order.append("p")
                t += 2
                try:
                    pic, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("BROWSE FIELDS picture unresolved")
            elif buf[t] == 0xBF:
                # :H heading — only the measured sub-op 10 (the same EQ byte
                # the :P arm reads after c2) is admitted
                t += 1
                if t >= end or buf[t] != S.EQ:
                    raise Unsupported("BROWSE clause 0xbf unmeasured")
                order.append("h")
                try:
                    heading, t = _fc_group(buf, t + 1, end, syms)
                except Unsupported:
                    raise Unsupported("BROWSE FIELDS heading unresolved")
            else:
                break
        # closed by multiplicity: r53-browsefield compiled all fifteen
        # orderings, so any order lifts and only a REPEATED attribute — which
        # no frame carries, the compiler having refused every source that
        # writes one twice — raises.
        if len(order) != len(set(order)):
            raise Unsupported("BROWSE FIELDS attribute sequence unmeasured")
        fields.append((fname, width, pic, heading, tuple(order)))
        if t >= end:
            return fields, t
        if buf[t] == S.ARGJOIN:
            t += 1
            continue
        return fields, t


def _dec_browse_name(buf, t, end, syms, byte, *, literals=False):
    """A BROWSE clause operand that NAMES something. Returns (text, next).

    r53-browsename measured the spellings. FREEZE `c0`, IN WINDOW `16` and
    WINDOW `2c` store a bare `f7 <u16>` symbol, or an `fc <expr> 03` group when
    the source spelled parentheses — the same pair DEFINE WINDOW's own name
    takes, and `_fc_group` already reads the paren node. PREFERENCE `d1` adds
    the string literal it writes with no `fc` wrapper at all: `d9` for a
    double-quoted name, `fb` for a single-quoted or bracketed one. The quoting
    is on the wire, so the operand comes back as rendered TEXT and the emitter
    writes it as it stands.
    """
    if t < end and buf[t] == S.FC:
        node, t = _fc_group(buf, t, end, syms)
        return _emit(node), t
    if t + 3 <= end and buf[t] == S.SYM:
        return _sym(syms, S.u16(buf, t + 1)), t + 3
    if literals and t + 3 <= end and buf[t] in (S.STR, S.STR2):
        quote = '"' if buf[t] == S.STR2 else "'"
        text, k = _dec_str_arg(buf, t, end)
        if k <= end and quote not in text:
            return quote + text + quote, k
    raise Unsupported("BROWSE clause 0x%02x operand form" % byte)


def _dec_browse(buf, end, syms):
    """BROWSE: `09` and then a clause list in ONE canonical order.

    r53-browsehead measured the envelope over 45 authored programs. Two facts
    decide the reader's shape:

    * there is no mandatory head — a bare one-byte `09` is plain BROWSE
      (round-28 W4, corpus x71, getbom cdYes s0 stmt57) and any single clause
      may follow `09` directly, with no WINDOW or FIELDS in front of it;
    * the clause order on the wire is CANONICAL, not the source's. Every
      permutation pair in the matrix — flags, valued clauses, conditions,
      names, and one 28-clause statement written forwards and backwards —
      compiled to the byte-identical frame.

    So the reader walks `S.BROWSE_CLAUSES` once in that order, taking each
    clause when its byte is the next one on the wire. A byte the table does not
    name ends the walk and raises: that is what keeps every unmeasured clause
    refused, and the table grows only where a law measures a clause.

    The clauses the table holds today are round 24/28/31's: FOR `13`, FIELDS
    `11`, WINDOW `2c`, TITLE `27`, TIMEOUT `ce` — and the matrix measured that
    FOR composes with FIELDS (`BROWSE FIELDS a FOR z = 3` stores
    `13 fc..fd 11 f7..`), which the round-31 reader rejected for want of a
    carrier.
    """
    if end == 1:
        return ("BROWSE",)
    t = 1
    got = {}
    clauses = []
    for byte, kind, word, name in S.BROWSE_CLAUSES:
        if t >= end or buf[t] != byte:
            continue
        t += 1
        if kind == "flag":
            value = None
        elif kind.startswith("group"):
            # groupN reads at most n operands, fc groups joined by ARGJOIN —
            # r53-browseval measured KEY's range (1 or 2) and FONT's face,
            # size and style (1, 2 or 3). A group1 clause yields the operand
            # itself so the five named attributes keep their round-24 shape.
            most = int(kind[5:])
            operands = []
            while True:
                if t >= end or buf[t] != S.FC:
                    raise Unsupported(
                        "BROWSE clause 0x%02x operand form" % byte)
                operand, t = _fc_group(buf, t, end, syms)
                operands.append(operand)
                if len(operands) >= most or t >= end \
                        or buf[t] != S.ARGJOIN:
                    break
                t += 1
            value = operands[0] if most == 1 else operands
        elif kind in ("name", "litname"):
            value, t = _dec_browse_name(buf, t, end, syms, byte,
                                        literals=kind == "litname")
        elif kind == "valid":
            # r53-browsecond: VALID carries more than a condition — `c6` in
            # front of the group is the `:F` force marker, and `10` behind it
            # (the same EQ byte the :P and :H field attributes read) introduces
            # the ERROR message. The clause is rendered here so the emitter
            # writes back whichever pieces the frame holds.
            force = t < end and buf[t] == 0xC6
            t += 1 if force else 0
            if t >= end or buf[t] != S.FC:
                raise Unsupported("BROWSE clause 0x%02x operand form" % byte)
            cond, t = _fc_group(buf, t, end, syms)
            value = (":F " if force else "") + _emit(cond)
            if t < end and buf[t] == S.EQ:
                if t + 1 >= end or buf[t + 1] != S.FC:
                    raise Unsupported(
                        "BROWSE clause 0x%02x operand form" % byte)
                message, t = _fc_group(buf, t + 1, end, syms)
                value += " ERROR " + _emit(message)
        else:
            value, t = _dec_browse_fields(buf, t, end, syms)
        if name is None:
            clauses.append((word, value))
        else:
            got[name] = value
    if t != end:
        raise Unsupported("BROWSE clause 0x%02x unmeasured" % buf[t])
    words = [w for w, _ in clauses]
    if "LAST" in words and "PREFERENCE" in words:
        # VFP9 refuses 'BROWSE LAST PREFERENCE "p"' in either source order
        # (r53-browsehead), so no frame carries the pair and the one position
        # the two share is never occupied twice
        raise Unsupported("BROWSE clause 0xd1 unmeasured")
    return BrowseWindow(got.get("window"), title=got.get("title"),
                        timeout=got.get("timeout"),
                        fields=got.get("fields") or [],
                        for_cond=got.get("for_cond"), clauses=clauses)


def dec_statement(buf, syms):
    """Statement entry, STOCK-FIRST (r33 expression lane): decode with the stock
    grammar and only on Unsupported retry ONCE under the round-33 shared-
    expression-stack rules — arena (`_pop` falls back to the nearest enclosing
    live operand stack; the compiler emits one linear RPN stream per
    expression), fdclose (fd terminates an open 43-group iff exactly one value
    stands), mmid ('f5 0d f6 <arr>' closes its group args-first mid-window,
    round-30/31 terminal envelopes keep priority). A statement that lifts stock
    can therefore never change text by construction, and every conversion
    surfaces as an explicit blocked->lifted or blocked-message shift. The flag
    is module state because the gated arms sit deep inside `_pop`/
    `_dec_group_run`; statement decoding is single-threaded and never nested."""
    global _EXPR_RETRY_ACTIVE, _STMT_MIDWINDOW_FIRED, _SYM_STMT_HI
    global _SYM_TABLE_HI, _SYM_STMT_LO, _GROUP_EOW_CLOSE
    _reset_arg_byref_close()   # r38: no 18-f6 flag may cross a statement edge
    _GROUP_EOW_CLOSE = False   # r54: nor a window-closed 43 packet
    # r49-clauseorder: this statement's own symbol high-water, folded into the
    # section's only when the statement is DONE — both passes included, so a
    # retry decodes against the same "what did earlier statements use" the
    # stock pass saw.
    _SYM_STMT_HI = -1
    _SYM_STMT_LO = None
    try:
        try:
            return _dec_statement_checked(buf, syms)
        except Unsupported:
            pass
        _EXPR_RETRY_ACTIVE = True
        _STMT_MIDWINDOW_FIRED = False
        # r38 follow-up: pass 1 can die AFTER its reader armed _ARG_BYREF_CLOSE
        # ('18 f6' consumed where no group loop follows to read-and-clear it),
        # so the retry pass must start marker-clean exactly like the statement
        # edge above — otherwise a pass-2 success whose FIRST user-name close
        # precedes any freshly consumed '18' would inherit pass 1's stale marker
        # and spell an unmeasured '@'. Defense-in-depth: no reachable population
        # statement hits the window (drift audit: zero unexplained '@'), so this
        # line is output-neutral by construction and by measured replay.
        _reset_arg_byref_close()
        try:
            return _dec_statement_checked(buf, syms)
        finally:
            _EXPR_RETRY_ACTIVE = False
    finally:
        if _SYM_TABLE_HI is not None and _SYM_STMT_HI > _SYM_TABLE_HI:
            _SYM_TABLE_HI = _SYM_STMT_HI


def _dec_statement(buf, syms):
    end = len(buf)
    lead = buf[0]
    j = 1
    if lead == S.AT_LEAD:
        # r49-valsweep: `04 fc <row> fd 07 fc <col> fd
        #   [28 fc <row2> fd 07 fc <col2> fd] [c4 fc <expr> fd [c2 fc <pic>]]`
        row, j = _fc_group(buf, j, end, syms)
        if j >= end or buf[j] != S.ARGJOIN:
            raise Unsupported("@ column missing")
        col, j = _fc_group(buf, j + 1, end, syms)
        corner = say = picture = None
        if j < end and buf[j] == S.TO_MARK:
            r2, j = _fc_group(buf, j + 1, end, syms)
            if j >= end or buf[j] != S.ARGJOIN:
                raise Unsupported("@ TO corner incomplete")
            c2, j = _fc_group(buf, j + 1, end, syms)
            corner = (r2, c2)
        if j < end and buf[j] == S.AT_SAY_MARK:
            say, j = _fc_group(buf, j + 1, end, syms)
            if j < end and buf[j] == S.AT_PICTURE_MARK:
                picture, j = _fc_group(buf, j + 1, end, syms)
        if j != end:
            raise Unsupported("@ clause 0x%02x unmeasured" % buf[j])
        return AtCommand(row, col, corner=corner, say=say, picture=picture)
    if lead == S.ASSIGN:
        lv, j = _dec_lvalue(buf, j, end, syms)
        # no-marker method-call form: 54 <path> fc [args] fd [16] — cmdEnter
        # '.SetFocus'-style WITH-scoped calls (iter. 35). Distinguished from
        # assignment by FC where the 0x10 marker would sit.
        if buf[j] == S.FC:
            aes, ak = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(aes) != 1 or ak >= end or buf[ak] != S.FD:
                raise Unsupported("call-stmt args unresolved")
            ak += 1
            # Multi-dimension indexed references continue with further bracketed
            # lists: 'fd 07 fc <sub> fd' per extra dimension (ARGJOIN between the
            # fc..fd units, exactly the DIMENSION dims grammar). MEASURED corpus
            # alignment _reportlistener.vcx::_reportlistener
            # adjustreportpagesinfo stmts 8/10/13/15:
            #   54 f4<THIS> f6<REPORTPAGES> fc m.tiReportIndex fd 07 fc 2 fd 16 ...
            #   -> THIS.reportPages[m.tiReportIndex,2] = ...
            # Every measured carrier closes with the same 16 (then optional 10-fc
            # put tail) as the single-list form pinned by tests/test_call_tail.py,
            # so a continuation that does not reach that 16 stays rejected — the
            # acceptance envelope widens only along the measured axis.
            while ak + 6 <= end and buf[ak] == S.ARGJOIN and buf[ak + 1] == S.FC:
                more, ak2 = _dec_expr(buf, ak + 2, end, syms,
                                      stop_bytes=_IF_COND_STOP)
                if len(more) < 1 or ak2 >= end or buf[ak2] != S.FD:
                    raise Unsupported("call-stmt subscript list unresolved")
                aes.extend(more)
                ak = ak2 + 1
                # continuation lists are admitted exclusively as part of the
                # CLOSED indexed form: after each unit's fd the stream must
                # continue with another joiner or the closing bracket marker
                # (tests/test_misc_tail.py continuation guard)
                if ak >= end or buf[ak] not in (S.ARGJOIN, S.PAREN, 0x16):
                    raise Unsupported("call-stmt subscript list unresolved")
            if ak < end and buf[ak] == 0x03:
                # round-28 W3 INDEXED-MEMBER PUT, statement level: the bracketed
                # argument list closes with 03 (same contextual-closer family as
                # the DIM/REPLACE tails), optionally followed by ONE terminal
                # property read, then the standard assignment tail:
                #   fd 03 10 fc <rhs>          -> .M(args) = rhs      (x368)
                #   fd 03 f7 <P> 10 fc <rhs>   -> .M(args).P = rhs    (x76)
                # Measured lvalue spellings reaching here: e2 f6|e5 <M>
                # (WithMemberPath, WITH scope) and f4-run f6 <M> (MemberPath,
                # object path); aligned carriers foxcharts::foxcharts
                # '.APALETTECOLORS(1) = RGB(...)' and dashboard
                # '.FIELDS(1).FIELDVALUE = PXX'. Anything else in the tail
                # stays rejected. (Integration union: every viable 03 tail
                # returns here, so the W2 bracket-closer walk below carries the
                # 16 spelling alone.)
                t3 = ak + 1
                prop = None
                # Round37 P8 (C09/G3, retry pass only): between the closing 03
                # and the terminal property, '[f4 <hop>]*' may ride on the
                # WITH-scoped deep-put spelling (xfrxprop::lastinited stmts
                # 10/11 '.Columns(1).Header1.Caption=…'). The hop loop adds
                # zero iterations on every stock shape.
                post_hops = []
                if _EXPR_RETRY_ACTIVE:
                    while t3 + 3 <= end and buf[t3] == S.MEMBER:
                        post_hops.append(_sym(syms, S.u16(buf, t3 + 1)))
                        t3 += 3
                if t3 + 3 <= end and buf[t3] == S.SYM:
                    prop = _sym(syms, S.u16(buf, t3 + 1))
                    t3 += 3
                if t3 + 1 >= end or buf[t3] != 0x10 or buf[t3 + 1] != S.FC:
                    raise Unsupported("call-stmt trailing bytes")
                ves, vk = _dec_expr(buf, t3 + 2, end, syms)
                if len(ves) != 1 or vk != end:
                    raise Unsupported("indexed-put value unresolved")
                names = getattr(lv, "names", None)
                if names is None:
                    name = getattr(lv, "name", None)
                    names = [name] if name else None
                if not names:
                    raise Unsupported("call-stmt receiver unresolved")
                if isinstance(lv, WithMemberPath):
                    if prop is not None or post_hops:
                        if lv.chain_call or post_hops:
                            # Round37 P8 (C09/G3): the full scoped run renders
                            # before the call, post-call hops and the terminal
                            # property after it —
                            #   '.Tree.Nodes(VAL(.Tree.Tag)).Tag',
                            #   '.Columns(1).Header1.Caption'.
                            # Only retry-pass carriers reach this arm with a
                            # marked node or non-empty hops; the stock
                            # single-name spelling below stays byte-exact.
                            put = ObjectChain(
                                [""] + list(names[:-1]),
                                [(names[-1], list(aes))],
                                list(post_hops)
                                + ([prop] if prop is not None else []))
                        else:
                            put = MidCall([""], names[-1], aes, prop)
                    elif lv.chain_call:
                        raise Unsupported("unmeasured chain-put tail")
                    else:
                        # r42-withdot: e2 f6 <sym> … fd 03 is WITH-scope
                        # `.APALETTECOLORS(1) = RGB(...)`. Bare
                        # APALETTECOLORS(1)= is 54 f6 (no e2); THIS.APALETTECOLORS
                        # is 54 f4 THIS f6. The leading dot is on the wire.
                        put = MethodCall(list(names), "", aes, recv_with=True)
                elif prop is not None:
                    put = ObjectChain(list(names[:-1]),
                                      [(names[-1], list(aes))], [prop])
                else:
                    put = MethodCall(list(names[:-1]), names[-1], aes)
                return Assign(put, ves[0])
            # Round-28: the indexed reference closes with the source's own
            # bracket marker — 16 on the pinned carriers, and the shared paren
            # byte for '( … )' spellings (xfrxlib.vcx::xfcont stmt11/12
            # 'THIS.aSheets[m.lii, 2] = …' -> …fd07fc..fd03; foxcharts sec6
            # stmts6-13), same DIMENSION-tail provenance as ArrayRef.
            closer = None
            br_hops = []
            br_prop = None
            if ak < end and buf[ak] == 0x16:
                closer = buf[ak]
                ak += 1
                # r54-withindex: the bracket closer takes the SAME optional
                # property tail the paren closer takes — the closer records the
                # source's subscript spelling and nothing else.
                # `.nodes[.nodes.count - i + 1].expanded = .T.` is
                # dashboard.scx#1119's own statement and `o.nodes[1].expanded`
                # its explicit-receiver twin; both were measured beside their
                # paren spellings, which differ in this byte alone.
                if _EXPR_RETRY_ACTIVE:
                    while ak + 3 <= end and buf[ak] == S.MEMBER:
                        br_hops.append(_sym(syms, S.u16(buf, ak + 1)))
                        ak += 3
                if ak + 3 <= end and buf[ak] == S.SYM:
                    br_prop = _sym(syms, S.u16(buf, ak + 1))
                    ak += 3
            if closer is not None and ak + 1 < end and buf[ak] == 0x10 \
                    and buf[ak + 1] == S.FC:
                es, k = _dec_expr(buf, ak + 2, end, syms)
                if len(es) != 1 or k != end:
                    raise Unsupported("indexed-put value unresolved")
                recv = getattr(lv, "names", None)
                if recv is None:
                    name = getattr(lv, "name", None)
                    recv = [name] if name else None
                if not recv:
                    raise Unsupported("call-stmt receiver unresolved")
                if br_prop is not None or br_hops:
                    tail = list(br_hops) + (
                        [br_prop] if br_prop is not None else [])
                    if isinstance(lv, WithMemberPath):
                        if getattr(lv, "chain_call", False) or br_hops:
                            return Assign(ObjectChain(
                                [""] + list(recv[:-1]),
                                [(recv[-1], list(aes))], tail,
                                call_brackets=[True]), es[0])
                        return Assign(MidCall([""], recv[-1], aes, br_prop,
                                              bracket=True), es[0])
                    return Assign(ObjectChain(
                        list(recv[:-1]), [(recv[-1], list(aes))], tail,
                        call_brackets=[True]), es[0])
                # r48-witharray refutes the reading this arm carried, which was
                # that the wire encodes scoped and plain member array puts
                # identically: `.aList[1] = v` inside WITH is
                # `54 e2 f6 <sym> fc <sub> fd 16 10 fc <rhs>` and the unscoped
                # `aList[1] = v` is the same frame WITHOUT the e2. The marker
                # is the only difference, so the dot is on the wire here for
                # the same reason r42-withdot put it on the 03 closer above.
                # The SUBSCRIPT spelling is a different question and is
                # recorded: this arm is entered only on the 16 closer, i.e. on
                # a source that wrote '[ … ]' (_reportlistener's own stored
                # 'THIS.ReportPages[1] = 0' beside its paren-spelled
                # 'DIME THIS.reportPages(THIS.ReportFileNames.Count,2)').
                return Assign(MethodCall(list(recv), "", aes,
                                         bracket=closer == 0x16,
                                         recv_with=isinstance(lv, WithMemberPath)),
                              es[0])
            if ak != end:
                raise Unsupported("call-stmt trailing bytes")
            recv = getattr(lv, "names", None)
            if recv is None:
                name = getattr(lv, "name", None)
                recv = [name] if name else None
            if not recv:
                raise Unsupported("call-stmt receiver unresolved")
            return ExprStmt(MethodCall(list(recv), "", aes,
                                       bracket=closer == 0x16), bare=True)
        if buf[j] != 0x10 or buf[j + 1] != S.FC:
            raise Unsupported("assignment marker missing")
        # 10 opens the assignment, fc opens its expression; the reader already stripped the
        # trailing fd/fe, so the expression runs to end.
        try:
            es, k = _dec_expr(buf, j + 2, end, syms)
        except Unsupported as e:
            # Round-34 lane C: on exactly this stock failure, the measured
            # CAST(x AS ...) assignment family gets one additional acceptance
            # path (r34: N(w,d); round-37 P7 generalized to the measured
            # N/C/D/T/Y/L/I/B arms and their width/decimal arities). It is
            # strictly ADDITIVE: any envelope mismatch re-raises the original
            # error, so a non-carrier statement can neither lift nor change
            # its blocked message through this arm.
            if str(e) == "CAST argument/type marker shape":
                try:
                    return _dec_assign_cast_numeric(buf, lv, j, end, syms)
                except Unsupported:
                    raise e from None
            # Round37 wave-2 P12 (W05): the oracle-forced chain-assignment
            # twins get the one further measured acceptance path. Same
            # contract as the CAST arm above: any mismatch inside the twin
            # reader re-raises the ORIGINAL error verbatim.
            try:
                return _dec_assign_chain_twin(lv, buf, j + 2, end, syms)
            except Unsupported:
                raise e from None
        if len(es) != 1 or k != end:
            raise Unsupported("assignment expression unresolved")
        return Assign(lv, es[0])
    if lead == S.STORE:
        if buf[j] != S.FC:
            raise Unsupported("STORE expr unwrapped")
        es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or k >= end or buf[k] != S.FD:
            raise Unsupported("STORE expr shape")
        if k + 1 >= end or buf[k + 1] != 0x28:
            raise Unsupported("STORE TO marker missing")
        targets, t = [], k + 2
        while True:
            tv, t = _dec_lvalue(buf, t, end, syms)
            targets.append(tv)
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("STORE target joiner")
            t += 1
        return Store(es[0], targets)
    if lead in (S.PRINTQ, S.PRINTEE):
        # 02/03 f8 03 <count> <arg> [07 <arg>]* — HARVEST round-4 ('?' multi-arg:
        # args joined by 07, each wrapped fc..fd). Measured argument forms, each
        # forced by its own carrier's bytes + stored METHODS source:
        #   bare Sym            '? P_HRDEPT'   (oaremotion.scx::Command1)
        #   fc-wrapped expr     '?SQLEXEC(con,"...")' (buypricecheck - 副本.scx::
        #                       cdDelete; '?? CHR(7)' foxchartsbeta.vcx::foxcharts;
        #                       '?SYS(1037)' print.scx::cgPrint) — compound final
        #                       args ('? "URL: "+lcURL', _webview.vcx::_webbrowser4)
        #                       need the full-token parse, not stop-at-one
        #   unwrapped f4 path   '?DATETIME(),this.Parent.Name,"收到",lcData'
        #                       (winsock.vcx::Olecontrol1); '?thisform.tcpServer.
        #                       oBJECT.LocalIP' (oaserver.scx::oaserver)
        # The LAST fc-wrapped arg's fd is reader-stripped together with the
        # statement terminator (round-19 framing note, same precedent as
        # _fc_group), so it may arrive consumed or explicit; an INTERMEDIATE
        # arg must keep its own fd before the 07 joiner. Clause-bearing forms
        # (AT/FONT/STYLE) are UNMEASURED and stay Unsupported via the tail check.
        if j + 3 > end or buf[j] != S.INT8 or buf[j + 1] != 0x03:
            raise Unsupported("print count descriptor")
        n = buf[j + 2]
        t = j + 3
        args = []
        for k in range(n):
            last = k == n - 1
            if t >= end:
                raise Unsupported("print arg form")
            if buf[t] == S.SYM:
                if t + 3 > end:
                    raise Unsupported("print arg form")
                args.append(Sym(_sym(syms, S.u16(buf, t + 1)))); t += 3
            elif buf[t] == S.MEMBER:
                if t + 3 > end:
                    raise Unsupported("print arg form")
                node, t = _dec_path(buf, t, end, syms)
                args.append(node)
            elif buf[t] == S.FC:
                es, t2 = _dec_expr(buf, t + 1, end, syms,
                                   stop_bytes=_IF_COND_STOP)
                if len(es) != 1:
                    raise Unsupported("print arg shape")
                if t2 < end and buf[t2] == S.FD:
                    t2 += 1
                elif not (last and t2 == end):
                    raise Unsupported("print arg shape")
                args.append(es[0]); t = t2
            elif buf[t] == S.WORKAREA_REF:
                # r51-printroot: an argument may carry the `f5 <root>` prefix —
                # the `0d` memory-variable root or a workarea alias — in front
                # of the same symbol or path the unrooted spelling uses. The
                # rooted frame IS the unrooted frame with `f5 0d` inserted
                # (`? m.ox.Name` = `? ox.Name` plus the two bytes), the root is
                # per-ARGUMENT rather than per-statement, and `??` carries an
                # identical argument frame. The general value reader is the
                # reader for it and stops at the `07` joiner the list already
                # spends.
                es, t2 = _dec_expr(buf, t, end, syms,
                                   stop_bytes={S.ARGJOIN})
                if len(es) != 1:
                    raise Unsupported("print arg shape")
                args.append(es[0]); t = t2
            else:
                raise Unsupported("print arg form")
            if not last:
                if t >= end or buf[t] != S.ARGJOIN:
                    raise Unsupported("print arg joiner")
                t += 1
        if t != end:
            raise Unsupported("print trailing bytes")
        return Print(lead == S.PRINTEE, args)
    if lead in (S.PUBLIC_LEAD, 0x35):
        if lead == 0x35 and end >= 2 and buf[1] == 0x03:
            # r50-leadsweep: the bare ALL is `35 03` and the qualifier bank is
            # the same `18` LIKE / `bc` EXCEPT pair SAVE TO's own ALL tail
            # carries, so the three spellings are one frame family.
            if end == 2:
                return PrivateAllLike(None)
            if buf[2] not in (0x18, 0xBC):
                raise Unsupported("PRIVATE ALL qualifier 0x%02x unmeasured"
                                  % buf[2])
            word = "LIKE" if buf[2] == 0x18 else "EXCEPT"
            if end == 3:
                raise Unsupported("PRIVATE ALL %s pattern missing" % word)
            skeleton, t = _dec_str_arg(buf, 3, end)
            if t != end:
                raise Unsupported("PRIVATE ALL %s trailing bytes" % word)
            return PrivateAllLike(skeleton, word=word)
        names, t = [], j
        while True:
            if lead == 0x35 and t < end and buf[t] == S.FC:
                # PRIVATE (name-expression) — parenthesised indirect name,
                # c249ced60e160bd8:18 -> 35 fc f70700 03; same grouped
                # name-expression reader as every other lvalue position.
                lv, t = _dec_lvalue(buf, t, end, syms)
                names.append(_emit(lv))
            elif lead == 0x35:
                # measured PRIVATE names: f7 <sym> and the memvar-space spelling
                # '35 f5 0d f7' (foxchartsbeta _drawcone-family stmt4, x2);
                # r50-leadsweep adds the array declarator, which is the SAME
                # NAME-opcode reader PUBLIC's own declarator already used
                # ('PRIVATE pva[3]' -> 35 f6 <n> fc 3 fd 16, one and two
                # dimensions, and joined to a plain name by 07)
                if t < end and buf[t] == S.NAME:
                    lv, t2 = _dec_lvalue(buf, t, end, syms)
                    if not isinstance(lv, ArrayRef):
                        raise Unsupported("PRIVATE name form")
                    names.append(_emit(lv))
                    t = t2
                elif t + 3 <= end and buf[t] == S.SYM:
                    names.append(_sym(syms, S.u16(buf, t + 1)))
                    t += 3
                elif t + 5 <= end and buf[t] == S.WORKAREA_REF \
                        and buf[t + 1] == 0x0D and buf[t + 2] == S.SYM:
                    names.append("m." + _sym(syms, S.u16(buf, t + 3)))
                    t += 5
                else:
                    raise Unsupported("PRIVATE name form")
            else:
                if t < end and buf[t] == S.NAME:
                    # PUBLIC array declarator: 'PUBLIC pnMain(30)' ->
                    # 37 f60f00 fcf8021efd03 / 37 f61500 fcf80225fd03
                    # (saleswarehouse Init stmt3, cstta frmsalewarehouse stmt3);
                    # the subscript list rides the shared NAME-arm reader.
                    lv, t2 = _dec_lvalue(buf, t, end, syms)
                    if not isinstance(lv, ArrayRef):
                        raise Unsupported("PUBLIC/PRIVATE name list tail")
                    names.append(_emit(lv))
                    t = t2
                else:
                    nm, t = _dec_param_name(buf, t, end, syms)
                    # round-28: PUBLIC typed tails carry the same AS[-OF]
                    # extension as LPARAMETERS ('37 f7 8f00 51 fb 0500 IMAGE',
                    # dzreview frmchd stmt129; df207bebd92d49e7 x10+)
                    nm, t = _typed_extension(nm, buf, t, end, syms, "PUBLIC")
                    names.append(nm)
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("PUBLIC/PRIVATE name list tail")
            t += 1
        return PublicStmt(names, private=lead == 0x35)
    if lead == S.LOCAL:
        names, t = [], j
        while True:
            name, t = _dec_param_name(buf, t, end, syms)
            typ = None
            if t < end and buf[t] == 0x51:
                # Type clause per the f8_typ oracle probe (cases/f8_typ.hex):
                # `51 fb <u16len> <chars>` ('LOCAL x AS Integer' -> ae f7 0000
                # 51 fb 0700 INTEGER). Round-28 corpus adds the double-quoted
                # spelling: foxcharts 'Local loCollection As Collection' ->
                # ae f7 0f00 51 d9 0a00 COLLECTION (x4+ carriers). Bounds
                # BEFORE every byte read — the old u16(buf, t+1) swallowed the
                # fb marker into the length and ran past the buffer.
                if t + 1 == end:
                    # r50-sysapp: the mark alone, with no type behind it —
                    # the same unrecoverable annotation _typed_extension
                    # admits for LPARAMETERS and PUBLIC.
                    names.append((name, None, None, None))
                    break
                if t + 4 > end or buf[t + 1] not in (S.STR, S.STR2):
                    raise Unsupported("LOCAL type clause unwrapped")
                ln = S.u16(buf, t + 2)
                if t + 4 + ln > end:
                    raise Unsupported("LOCAL type clause truncated")
                typ = _as_class_name(buf[t + 1],
                                     _payload_text(buf[t + 4:t + 4 + ln]))
                t += 4 + ln
            # AS..OF extension: '<name> AS <type> OF <library>'. Round-28 corpus
            # census — TWO measured library spellings after c3:
            #   c3 fc <expr> [fd]    quoted-path expression (chartadjust.scx::
            #                        Command3 'AS FoxCharts OF "..\\class\\FoxCharts.
            #                        Vcx"' -> 51 fb FOXCHARTS c3 fc d9..); the trailing
            #                        fd is reader-stripped when statement-final, and a
            #                        multi-declarator list CONTINUES with 07 after it
            #                        (9008ca5de155bdc1 x6, f5c36217fbe1e362:0 — the old
            #                        end-of-stream requirement broke every such list)
            #   c3 fb <u16len> <txt> bare name string ('Local lo_MemberObject As
            #                        ChartNode Of org_chart', org_chart.vcx::Nodes
            #                        stmt1 -> c3 fb 0900 ORG_CHART; source spells it
            #                        unquoted, so the text re-emits verbatim)
            of_lib = None
            if t < end and buf[t] == S.LOCAL_OF_MARK and typ is not None:
                t += 1
                if t < end and buf[t] == S.FC:
                    oes, ok = _dec_expr(buf, t + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(oes) != 1:
                        raise Unsupported("LOCAL OF library unresolved")
                    if ok < end and buf[ok] == S.FD:
                        ok += 1
                    of_lib = _emit(oes[0])
                    t = ok
                elif t + 3 <= end and buf[t] == S.STR:
                    ln = S.u16(buf, t + 1)
                    if t + 3 + ln > end:
                        raise Unsupported("LOCAL OF library unresolved")
                    of_lib = _payload_text(buf[t + 3:t + 3 + ln])
                    t += 3 + ln          # bare fb: the source spelled it unquoted
                else:
                    raise Unsupported("LOCAL OF library unwrapped")
            # Array-declaration joiner. Full-population census (every ae-led statement
            # in the 10,241-section dev population, audited 2026-08-24): a declarator's
            # subscript list is `fc <expr> fd (07 fc <expr> fd)*` closed by ONE byte
            # that records the SOURCE's own bracket spelling —
            #   03 (S.PAREN, the shared closing-paren marker, FINDINGS F9) = '( ... )'
            #   16                                            = '[ ... ]'
            # Both spellings occur (267 vs 55 declarators); every aligned stored source
            # matches the closer ('laSteps(4)' -> 03, 'aIconFiles[1]' /
            # 'LOCAL ARRAY laTemp[1]' -> 16), and the spelling is NOT interchangeable on
            # the wire — re-emitting it verbatim is what keeps recompilation byte-equal.
            # The same fc..fd-per-dimension grammar as DIMENSION (FINDINGS F8); 07 joins
            # dimensions WITHIN one declarator and declarators WITHIN the statement, so
            # position relative to the closer disambiguates. Declarators without
            # subscripts carry no closer at all.
            dims = None
            dim_close = None
            if t < end and buf[t] == S.FC:
                dims = []
                while True:
                    if t >= end or buf[t] != S.FC:
                        raise Unsupported("LOCAL dimension unwrap")
                    # full-token parse (stop at the closing fd): compound dims
                    # are measured — 'aef63100 fc f40500 f73200 f8010106 fd'
                    # = 'lnTop + 1'-style subscripts (foxcharts.vcx::foxcharts
                    # sec65 stmt38) — which stop_at_one could never span.
                    des, dk = _dec_expr(buf, t + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(des) != 1 or dk >= end or buf[dk] != S.FD:
                        raise Unsupported("LOCAL dimension shape")
                    dims.append(_emit(des[0]))
                    t = dk + 1
                    if t < end and buf[t] == S.ARGJOIN:
                        t += 1
                        continue
                    if t < end and buf[t] in (S.PAREN, 0x16):
                        dim_close = ")" if buf[t] == S.PAREN else "]"
                        t += 1
                        break
                    raise Unsupported("LOCAL dimension tail")
            if dims is None:
                if of_lib is None:
                    names.append((name, typ))
                else:
                    names.append((name, typ, None, of_lib))
            else:
                if of_lib is None:
                    names.append((name, typ, (dims, dim_close)))
                else:
                    names.append((name, typ, (dims, dim_close), of_lib))
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("LOCAL joiner")
            t += 1
        return Local(names)
    if lead == S.LPARAMS:
        names, t = [], j
        while True:
            name, t = _dec_param_name(buf, t, end, syms)
            name, t = _typed_extension(name, buf, t, end, syms, "LPARAMETERS")
            names.append(name)
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("LPARAMETERS joiner")
            t += 1
        return LParams(names)
    if lead == S.PARAMETERS_LEAD:
        # PARAMETERS = 34 f7 <sym> (HARVEST.md round-3 additions: oracle-measured,
        # "distinct from LPARAMETERS af"). Continuation joins names with ARGJOIN,
        # the sibling declaration-list grammar (PRIVATE/REGIONAL rows `35 f7 07 f7`).
        names, t = [], j
        while True:
            name, t = _dec_param_name(buf, t, end, syms)
            name, t = _typed_extension(name, buf, t, end, syms, "PARAMETERS")
            names.append(name)
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("PARAMETERS name list tail")
            t += 1
        return ParametersStmt(names)
    if lead == S.DEFINE_LEAD:
        # round-24 oracle batch (round24_findings.json / round24_streams.json):
        # ONE construct family; the keyword byte selects the object.
        if end < 2:
            raise Unsupported("DEFINE truncated")
        kw = buf[1]
        if kw == S.DEFINE_WINDOW_KW:
            return _dec_define_window(buf, end, syms)
        if kw == S.DEFINE_POPUP_KW:
            return _dec_define_popup(buf, end, syms)
        if kw == S.DEFINE_BAR_KW:
            return _dec_define_bar(buf, end, syms)
        if kw == S.DEFINE_PAD_KW:
            return _dec_define_pad(buf, end, syms)
        raise Unsupported("DEFINE object 0x%02x unmeasured" % kw)
    if lead == S.ACTIVATE_POPUP_LEAD:
        # round-24 g5 byte-exact: 74 c6 f7<sym>; audit-B order-4: bare 74 26 =
        # ACTIVATE SCREEN (winsock.vcx::Olecontrol1 stmt[4] vs stored source
        # 'ACTIVATE SCREEN', 27 carriers identical) — exactly two bytes, no
        # clause form measured, so any trailing byte rejects.
        if end == 2 and buf[1] == S.ACTIVATE_SCREEN_KW:
            return ActivateScreen()
        if end == 5 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.SYM:
            return ActivatePopup(_sym(syms, S.u16(buf, 3)))
        if end >= 3 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.FC:
            # r36-D1c: 'ACTIVATE POPUP (m.lcMenuName)' — paren-name frame,
            # parens preserved (wire-distinguishable from the bare f7 <sym>
            # arm above). Corpus: systray.vcx::systray L629 <-> stmt
            # 74c6fcf50df7290003, both twin copies. PLAIN frame only: any
            # trailing byte (incl. an AT tail behind a paren name — unmeasured
            # combination) stays Unsupported below.
            nm, t = _fc_group(buf, 2, end, syms)
            if t != end:
                raise Unsupported("ACTIVATE POPUP frame shape")
            return ActivatePopup(_emit(nm))
        # Round-33 measured AT tail (mhxpcontrol.vcx::edit s1 stmt0
        # 'ACTIVATE POPUP MHGLMENUS AT MROW(),MCOL()' <->
        # 74c6f7000005fc43c7fd07fc43c5fd): exactly `05 <row-group> 07
        # <col-group>` after the name — the MOUSE-AT coordinate spelling.
        # Any other clause byte stays loud below.
        if end >= 9 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.SYM \
                and buf[5] == 0x05:
            row, t = _fc_group(buf, 6, end, syms)
            if t >= end or buf[t] != S.ARGJOIN:
                raise Unsupported("ACTIVATE POPUP frame shape")
            col, t = _fc_group(buf, t + 1, end, syms)
            if t != end:
                raise Unsupported("ACTIVATE POPUP trailing bytes")
            return ActivatePopup(_sym(syms, S.u16(buf, 3)), at=(row, col))
        # Round-33 ACTIVATE WINDOW under this lead (mhxpcontrol.vcx::extwindow
        # s2 stmt5 'ACTIVATE WINDOWS (THISFORM.NAME) IN WINDOWS (PARENTWIN)
        # NOSHOW' <-> 742cce16fcf7010003fdfcf40200f7040003): optional ce NOSHOW
        # flag, then the IN-WINDOW argument FIRST — SHOW WINDOW's (lead 0x80)
        # wire order; both operands parenthesised fc-groups. The WINDOW
        # keyword byte is context-local to this lead, as under 09/3c/80.
        if end >= 4 and buf[1] == S.DEFINE_WINDOW_KW \
                and buf[2] == S.ACTIVATE_WIN_SAME:
            # r40-H second WINDOW frame: `74 2c cf <name>` = ACTIVATE WINDOW
            # <name> SAME, with NO IN-WINDOW argument. Oracle f21
            # ('ACTIVATE WINDOW (lcWindow) SAME' -> 742ccffcf7010003) is
            # raw-equal to _reports.vcx::_output #110 modulo symbol index; d10
            # pins the bare-name spelling 742ccff70000. The suffix bytes TOP=29
            # and BOTTOM=36 were measured in the same batch and deliberately
            # NOT bound — no carrier spells them.
            if buf[3] == S.SYM:
                if end != 6:
                    raise Unsupported("ACTIVATE WINDOW trailing bytes")
                name = Sym(_sym(syms, S.u16(buf, 4)))
            else:
                name, t = _fc_group(buf, 3, end, syms)
                if t != end:
                    raise Unsupported("ACTIVATE WINDOW trailing bytes")
            return ActivateWindowStmt(name, None, same=True)
        if end >= 4 and buf[1] == S.DEFINE_WINDOW_KW:
            t = 2
            noshow = False
            if buf[t] == S.TEXT_FLAG_NOSHOW:
                noshow = True
                t += 1
            if t < end and buf[t] == S.GO_IN_CLAUSE:
                in_win, t = _fc_group(buf, t + 1, end, syms)
                name, t = _fc_group(buf, t, end, syms)
                if t != end:
                    raise Unsupported("ACTIVATE WINDOW trailing bytes")
                return ActivateWindowStmt(name, in_win, noshow)
            # r42-I7: clause-free 74 2c <name> — bare f7 <sym> or an fc-group
            # (paren / member path). Oracle r42-actwin s0001/s0003/s0005.
            # TOP=29, BOTTOM=36, and NOSHOW without IN stay this schema id
            # (r40-H f24/f25/f26).
            if (not noshow and t < end and buf[t] in (S.SYM, S.FC)):
                if buf[t] == S.SYM:
                    if t + 3 != end:
                        raise Unsupported("ACTIVATE WINDOW frame shape")
                    name = Sym(_sym(syms, S.u16(buf, t + 1)))
                else:
                    name, t = _fc_group(buf, t, end, syms)
                    if t != end:
                        raise Unsupported("ACTIVATE WINDOW frame shape")
                return ActivateWindowStmt(name, None)
            raise Unsupported("ACTIVATE WINDOW frame shape")
        raise Unsupported("ACTIVATE POPUP frame shape")
    if lead == S.DEACTIVATE_POPUP_LEAD:
        # 75 c6 f7<sym> — exactly four bytes, no clause form measured, so any
        # trailing byte rejects (round-40 e06; c79070eeff459e07:25#126).
        if end == 5 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.SYM:
            return DeactivatePopup(_sym(syms, S.u16(buf, 3)))
        raise Unsupported("DEACTIVATE POPUP frame shape")
    if lead == S.MOVE_POPUP_LEAD:
        # 7a c6 f7<sym> 28 <row-group> 07 <col-group> (round-40 e06;
        # c79070eeff459e07:25#121 'MOVE POPUP xfrxSHPopup TO this.MROW(""),
        # this.MCOL("")'). TO is mandatory: no other MOVE POPUP clause measured.
        if end >= 6 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.SYM \
                and buf[5] == S.TO_MARK:
            row, t = _fc_group(buf, 6, end, syms)
            if t >= end or buf[t] != S.ARGJOIN:
                raise Unsupported("MOVE POPUP TO coordinate list")
            col, t = _fc_group(buf, t + 1, end, syms)
            if t != end:
                raise Unsupported("MOVE POPUP trailing bytes")
            return MovePopup(_sym(syms, S.u16(buf, 3)), row, col)
        raise Unsupported("MOVE POPUP frame shape")
    if lead == S.BROWSE_LEAD:
        return _dec_browse(buf, end, syms)
    if lead == S.CREATE_CURSOR_LEAD:
        return _dec_create_cursor(buf, end, syms)
    if lead == S.CREATE_LEAD:
        return _dec_create(buf, end, syms)
    if lead == S.INSERT_LEAD:
        return _dec_insert_into(buf, end, syms)
    if lead == S.RETURN:
        if j == end:
            return Return(None)
        if buf[j] == S.TO_MARK:
            # r51-carriers: RETURN TO is the universal 28 TO mark with a WORD
            # behind it instead of an expression — `bc` MASTER, or an f7 symbol
            # naming a program. Measured at top level, inside a PROCEDURE and
            # inside an IF block, where the frame is byte-identical. Any other
            # word keeps its refusal.
            if end == j + 2 and buf[j + 1] == S.RETURN_TO_MASTER_WORD:
                return CommandLine("RETURN TO MASTER")
            if end == j + 4 and buf[j + 1] == S.SYM:
                return CommandLine("RETURN TO "
                                   + _sym(syms, S.u16(buf, j + 2)))
            raise Unsupported("RETURN TO target unmeasured")
        by_ref = False
        if buf[j] == S.RETURN_BYREF and j + 1 < end and buf[j + 1] == S.FC:
            # r50-sysapp: 'RETURN @<expr>' is `42 04 fc <expr>`. Measured over
            # a local array, a memvar and an object property, inside a class
            # method and outside one; every unmarked spelling of the same three
            # compiles to `42 fc <expr>`, so the marker IS the '@' and nothing
            # else produces it.
            by_ref = True
            j += 1
        if buf[j] != S.FC:
            raise Unsupported("RETURN expr unwrapped")
        # compound expressions need the full-token parse (stop_at_one stopped before
        # comparisons applied); the trailing fd may be reader-stripped
        es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("RETURN expr shape")
        if k < end and buf[k] == S.FD:
            k += 1
        if k != end:
            raise Unsupported("RETURN expr shape")
        return Return(es[0], by_ref=by_ref)
    if lead == S.DIM:
        # Name forms: f7 sym | path | f4 <sym> f6 <name> (member.name array id;
        # _checkbox/_reportlistener LOCAL..[n] token walks iter. 39) — all via
        # _dec_lvalue, whose inline MEMBER+NAME arm returns the MemberPath —
        # plus the round-28 ArrayRef form: '15 f6 <arr> fc..fd <closer>' where
        # the subscript list IS the dimension list ('DIMENSION MyKey(60)',
        # mainmenu3.scx::Timer1 stmt0 15 f60000 fcf8023cfd03; vfp_skins
        # sysmenupop stmt8 'DIMENSION aStr[512,2]' closes 16).
        # Round-28 declarator loop: several targets in ONE statement joined by
        # ARGJOIN (dashboard2.scx::frmcontrol stmt12 'DIMENSION This.laTextures(
        # lnLine), This.laFiles(lnLine)' -> ...fc..fd03 07 f4..f6.. fc..fd03).
        def _dim_dims(t):
            dims = []
            while True:
                if t >= end or buf[t] != S.FC:
                    raise Unsupported("DIMENSION dim unwrap")
                # full-token parse: compound dims are measured — resizable.vcx
                # addtoarray stmt7 'THIS.aControlStats[nLen + 1, 5]' spans an
                # addition inside the first dim (stop_at_one never could)
                es, k = _dec_expr(buf, t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) != 1 or k >= end or buf[k] != S.FD:
                    raise Unsupported("DIMENSION dim shape")
                dims.append(es[0])
                t = k + 1
                if t < end and buf[t] == S.ARGJOIN:
                    t += 1
                    continue
                if t < end and buf[t] in (S.PAREN, 0x16):
                    # the declarator's own closer records the SOURCE spelling
                    return dims, buf[t] == 0x16, t + 1
                raise Unsupported("DIMENSION tail")

        items = []
        t = j
        while True:
            lv, t2 = _dec_lvalue(buf, t, end, syms)
            if isinstance(lv, ArrayRef):
                items.append((lv.name, lv.subs, lv.bracket))
                t = t2
            elif isinstance(lv, (Sym, MemberPath, WithMemberPath)):
                if isinstance(lv, Sym):
                    name = lv.name
                elif isinstance(lv, WithMemberPath):
                    # WITH-scoped target: 'DIMENSION .aChoices[n]' inside a WITH
                    # frame (corpus alignment _dialogs.vcx::
                    # cmdEnter stmt41: 15 e2 f6<ACHOICES> fc <dim> fd 16). Leading
                    # dot marks the WITH scope exactly as the WithRef emitter does.
                    name = "." + ".".join(lv.names)
                else:
                    name = ".".join(lv.names)
                dims, bracket, t = _dim_dims(t2)
                items.append((name, dims, bracket))
            else:
                raise Unsupported("DIMENSION name form")
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("DIMENSION trailing bytes")
            t += 1
        if len(items) == 1:
            name, dims, bracket = items[0]
            return Dim(name, dims, bracket=bracket)
        return DimList(items)
    if lead == S.WITH:
        if buf[j] != S.FC:
            raise Unsupported("WITH expr unwrapped")
        es, k = _dec_expr(buf, j + 1, end, syms, stop_at_one=True)
        # optional AS clause: 51 fb <class-name uppercased on the wire> (round-23 w3)
        as_class = None
        t2 = k + 1
        if t2 < end and buf[t2] == S.AS_CLAUSE_MARK:
            t2 += 1
            if t2 + 3 > end or buf[t2] != S.STR:
                raise Unsupported("WITH AS class name missing")
            n = S.u16(buf, t2 + 1)
            as_class = _payload_text(buf[t2 + 3:t2 + 3 + n])
            t2 += 3 + n
        if len(es) != 1:
            raise Unsupported("WITH frame shape")
        # optional OF-library after the AS class (round-28 W3, foxcharts
        # carriers): c3 fb <library verbatim> | c3 fc d9 <library> [fd] — the
        # same two spellings the typed-LOCAL clause measures.
        of_library = None
        if as_class is not None and t2 < end and buf[t2] == S.PARAM_OF_MARK:
            t2 += 1
            if t2 < end and buf[t2] in (S.STR, S.STR2):
                of_library, t2 = _dec_str_arg(buf, t2, end)
            elif t2 < end and buf[t2] == S.FC:
                oes, ok = _dec_expr(buf, t2 + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(oes) != 1:
                    raise Unsupported("WITH OF library unresolved")
                if ok < end and buf[ok] == S.FD:
                    ok += 1
                of_library = _emit(oes[0])
                t2 = ok
            else:
                raise Unsupported("WITH OF library unresolved")
        # slot word after the fd: f9 05 <u16> dominant, e9 00 <u32> the
        # long-jump width of the same slot anchor (round-28 W3)
        if t2 + 4 == end and buf[t2] == S.INT16 and buf[t2 + 1] == 0x05:
            return With(es[0], [], as_class=as_class, of_library=of_library)
        if t2 + 6 == end and buf[t2] == S.INT32 and buf[t2 + 1] == 0x00:
            return With(es[0], [], as_class=as_class, of_library=of_library)
        raise Unsupported("WITH frame shape")
    if lead == S.ENDWITH:
        return ENDWITH_SENTINEL
    if lead == S.TEXT_LEAD:
        # TEXT frame opener — round-23 FORCED (bare '4d', else 4d 28 <target>
        # [flags]); round-62 r62-texthead generalised the TO clause bank. The
        # target is an alias-M run (m.x, f5 0d f7), a plain f7 name, a WITH-scoped
        # ref (e2, round-28 W4), a member path (f4.. terminal sym) OR a name
        # expression `fc <expr>` ('TEXT TO (nameExpr)'; corpus 28 fc f7 <sym>).
        # The flags ride the fixed wire order 60(TEXTMERGE) -> ce(NOSHOW) ->
        # 01(ADDITIVE) -> c3(PRETEXT) -> c4(FLAGS) whatever the source order — the
        # compiler normalises it (th_all_doc_order and th_all_scrambled compile to
        # the same frame) — and PRETEXT and FLAGS each carry an fc-wrapped
        # EXPRESSION argument (int, string or expr), closed by fd only when a
        # clause follows and reader-stripped when statement-final.
        if end == 1:
            return TextStmt(None, [])
        if end < 2 or buf[1] != S.TO_MARK:
            raise Unsupported("TEXT TO frame shape")
        t = 2
        if t >= end:
            raise Unsupported("TEXT TO target form")
        if buf[t] == S.FC:
            target, t = _fc_group(buf, t, end, syms)
        elif t + 5 <= end and buf[t] == S.WORKAREA_REF and buf[t + 1] == 0x0D \
                and buf[t + 2] == S.SYM:
            target = MemvarRef(_sym(syms, S.u16(buf, t + 3)))
            t += 5
        elif t + 3 <= end and buf[t] == S.SYM:
            target = Sym(_sym(syms, S.u16(buf, t + 1)))
            t += 3
        elif t + 3 <= end and buf[t] == S.WITHREF:
            target, t = _dec_withref(buf, t, end, syms)
        elif t + 3 <= end and buf[t] == S.MEMBER:
            names = []
            while t + 3 <= end and buf[t] == S.MEMBER:
                names.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            if t + 3 <= end and buf[t] == S.SYM:
                names.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            target = MemberPath(names) if len(names) > 1 \
                else MemberRef(names[0])
        else:
            raise Unsupported("TEXT TO target form")
        # The three plain flags, each at most once and only in the wire order;
        # then the two expression clauses, PRETEXT ahead of FLAGS. A repeat, a
        # reorder, or an unknown mark leaves a byte the trailing check rejects,
        # so the arm is no more permissive than the bytes the oracle produces.
        flags = []
        for mark, word in ((S.TEXT_FLAG_TEXTMERGE, "TEXTMERGE"),
                           (S.TEXT_FLAG_NOSHOW, "NOSHOW"),
                           (S.TEXT_FLAG_ADDITIVE, "ADDITIVE")):
            if t < end and buf[t] == mark:
                flags.append(word)
                t += 1
        for mark, word in ((S.TEXT_FLAG_PRETEXT, "PRETEXT"),
                           (S.TEXT_FLAG_FLAGS, "FLAGS")):
            if t < end and buf[t] == mark:
                if t + 1 >= end or buf[t + 1] != S.FC:
                    raise Unsupported("TEXT %s argument shape" % word)
                expr, t = _fc_group(buf, t + 1, end, syms)
                flags.append("%s %s" % (word, _emit(expr)))
        if t != end:
            raise Unsupported(
                "TEXT clause flag 0x%02x unmeasured" % buf[t])
        return TextStmt(target, flags)
    if lead == S.IF_LEAD:
        # 25 fc <cond> fd f9 05 <u16 rel-target> — the fd survives here because the u16
        # follows it before the statement's fe, so the reader strips only the fe.
        if buf[j] != S.FC:
            raise Unsupported("IF condition unwrapped")
        try:
            es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            # tail after the condition: fd f9 05 <u16> | fd e9 00 <u32> (shared
            # reader; walk-time verification pins the anchor either way)
            if len(es) != 1:
                raise Unsupported("IF frame shape")
            rel, _ = _jump_target(buf, k, end, "IF")
        except Unsupported as cond_err:
            # Round38 P14 (wave-2 W07): the mixed memvar quad gets one further
            # measured acceptance path. Same contract as the ASSIGN arms: any
            # mismatch inside the quad reader — including its jump-anchor
            # shape — re-raises the ORIGINAL stock error verbatim, so blocked
            # messages cannot shift through this arm.
            try:
                return _dec_if_memvar_quad(buf, j + 1, end, syms)
            except Unsupported:
                raise cond_err from None
        return If(es[0], [], rel_target=rel)
    if lead == S.DO_CASE_LEAD and len(buf) >= 2 \
            and buf[1] == S.DO_CASE_FRAME_MARK:
        if end == 10 and buf[2] == S.INT16 and buf[3] == 0x05 \
                and buf[6] == S.INT16 and buf[7] == 0x05:
            return DoCase([], S.u16(buf, 4), S.u16(buf, 8))
        if end == 14 and buf[2] == S.INT32 and buf[3] == 0x00 \
                and buf[8] == S.INT32 and buf[9] == 0x00:
            # round-33 long-jump width of the SAME frame: two e9 00 <u32>
            # words (oaremotion1.scx::rtx s14/s19, dashboardset.scx::Frmfood
            # s1). Length is exactly 14; anything else stays the loud
            # subtype rejection. Walk-time target verification below is
            # width-independent, so identity stays checked, never assumed.
            return DoCase([], int.from_bytes(buf[4:8], "little"),
                          int.from_bytes(buf[10:14], "little"))
        raise Unsupported("unsupported 0x18 frame subtype")
    if lead == S.FOR_LEAD:
        # 84 <lvalue> 10 fc <start> fd 28 fc <end> fd [c7 fc <step> fd] [f9 05 <t>]
        lv, t = _dec_lvalue(buf, j, end, syms)
        if buf[t] != 0x10 or buf[t + 1] != S.FC:
            raise Unsupported("FOR start unwrapped")
        ss, k = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(ss) != 1 or k >= end or buf[k] != S.FD or buf[k + 1] != S.TO_MARK:
            raise Unsupported("FOR start shape")
        k += 2
        if buf[k] != S.FC:
            raise Unsupported("FOR end unwrapped")
        ee, k2 = _dec_expr(buf, k + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(ee) != 1 or k2 >= end or buf[k2] != S.FD:
            raise Unsupported("FOR end shape")
        k2 += 1
        step = None
        if k2 < end and buf[k2] == S.STEP_MARK:
            if buf[k2 + 1] != S.FC:
                raise Unsupported("FOR step unwrapped")
            st_, k3 = _dec_expr(buf, k2 + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(st_) != 1 or k3 >= end or buf[k3] != S.FD:
                raise Unsupported("FOR step shape")
            step = st_[0]
            k2 = k3 + 1
        rel = -1
        if k2 + 4 == end and buf[k2] == S.INT16 and buf[k2 + 1] == 0x05:
            rel = S.u16(buf, k2 + 2)
            k2 = end
        elif k2 + 6 == end and buf[k2] == S.INT32 and buf[k2 + 1] == 0x00:
            # long-jump spelling of the same ENDFOR anchor (round-28 W3)
            rel = int.from_bytes(buf[k2 + 2:k2 + 6], "little")
            k2 = end
        elif k2 != end:
            raise Unsupported("FOR trailing bytes")
        return ForStmt(lv, ss[0], ee[0], step, [], rel_target=rel)
    if lead == S.FOR_EACH_LEAD:
        # b5 <loopvar> 16 <collection> [c2] (f9 05 <u16> | e9 00 <u32>):
        # FOR EACH <var> IN <collection> [FOXOBJECT] — corpus-forced, see
        # schemas provenance. Bounds BEFORE every byte read; unmeasured
        # shapes stay Unsupported.
        t = j
        if t + 5 <= end and buf[t] == S.WORKAREA_REF \
                and buf[t + 1] == 0x0D and buf[t + 2] == S.SYM:
            var = MemvarRef(_sym(syms, S.u16(buf, t + 3)))
            t += 5
        elif t + 3 <= end and buf[t] == S.SYM:
            var = Sym(_sym(syms, S.u16(buf, t + 1)))
            t += 3
        else:
            raise Unsupported("FOR EACH loop variable form")
        as_class = of_lib = None
        if t < end and buf[t] == S.AS_CLAUSE_MARK:
            # r50-sysapp: the loop variable takes the same AS clause LOCAL /
            # PUBLIC / LPARAMETERS carry — `51 <class> [c3 <library>]` — and it
            # sits in FRONT of the 16 IN mark, independent of FOXOBJECT:
            #   FOR EACH v AS Custom IN c            51 fb 'CUSTOM' 16 …
            #   FOR EACH v AS Custom IN c FOXOBJECT  the same, then c2
            #   FOR EACH v AS "Custom" IN c          51 d9 'Custom' 16 …
            #   FOR EACH v AS Custom OF zz.vcx IN c  … c3 fb 'zz.vcx' 16 …
            #   FOR EACH v AS Custom OF "zz.vcx"     … c3 fc d9 'zz.vcx' fd 16
            # A bare name is an identifier the compiler uppercases (fb) and a
            # quoted one keeps its case (d9) — r47-localas's own spelling rule.
            if t + 2 > end or buf[t + 1] not in (S.STR, S.STR2):
                raise Unsupported("FOR EACH AS clause without class")
            marker = buf[t + 1]
            cls, t = _dec_str_arg(buf, t + 1, end)
            as_class = _as_class_name(marker, cls)
            if t < end and buf[t] == S.PARAM_OF_MARK:
                t += 1
                grouped = t < end and buf[t] == S.FC
                if grouped:
                    t += 1
                if t + 2 > end or buf[t] not in (S.STR, S.STR2):
                    raise Unsupported("FOR EACH OF library unresolved")
                lib_marker = buf[t]
                lib, t = _dec_str_arg(buf, t, end)
                of_lib = _as_class_name(lib_marker, lib)
                if grouped and (t >= end or buf[t] != S.FD):
                    raise Unsupported("FOR EACH OF library unresolved")
                t += 1 if grouped else 0
        if t >= end or buf[t] != S.FOREACH_IN_MARK:
            raise Unsupported("FOR EACH IN clause missing")
        t += 1
        # Collection: the measured spellings only (round-28 W3 census, x41 fail
        # streams, each aligned to its stored source before admission):
        #   f7 <sym>                    plain array/collection variable
        #   f5 0d f7 <sym>              m.<var>                'FOR EACH x IN m.aRows'
        #   f5 0d f4-run f7 <term>      m.<var>.<hops>.<term>
        #   e2 [f4-run] f7 <term>       WITH-scoped reference  '.oItems.Item'
        #   e1 <sysobj> [f4-run] f7 <t> system-object path    '_SCREEN.Forms'
        #   f4-run f7 <term>            object path           'THIS.Controls'
        # Anything else stays Unsupported — one statement, never the module.
        coll = None
        if t + 3 <= end and buf[t] == S.MEMBER:
            coll, t = _dec_path(buf, t, end, syms)
            if not isinstance(coll, MemberPath):
                raise Unsupported("FOR EACH collection form")
        elif t + 3 <= end and buf[t] == S.SYM:
            coll = Sym(_sym(syms, S.u16(buf, t + 1)))
            t += 3
        elif t + 5 <= end and buf[t] == S.WORKAREA_REF \
                and buf[t + 1] == 0x0D:
            if buf[t + 2] == S.SYM:
                coll = MemvarRef(_sym(syms, S.u16(buf, t + 3)))
                t += 5
            elif buf[t + 2] == S.MEMBER:
                hops = []
                t += 2
                while t + 3 <= end and buf[t] == S.MEMBER:
                    hops.append(_sym(syms, S.u16(buf, t + 1)))
                    t += 3
                if t + 3 <= end and buf[t] == S.SYM:
                    hops.append(_sym(syms, S.u16(buf, t + 1)))
                    # same spelling as the alias-M lvalue arm: the m. root rides
                    # verbatim on the first hop ('m.oData.Items')
                    coll = MemberPath(["m." + hops[0]] + hops[1:])
                    t += 3
                else:
                    raise Unsupported("FOR EACH collection form")
            else:
                raise Unsupported("FOR EACH collection form")
        elif t < end and buf[t] == S.WITHREF:
            node, t = _dec_withref(buf, t, end, syms)
            if not isinstance(node, (WithRef, WithMemberPath)):
                raise Unsupported("FOR EACH collection form")
            coll = node
        elif t < end and buf[t] == 0xE1:
            if t + 2 > end or buf[t + 1] not in S.SYSTEM_OBJECT_REFS:
                raise Unsupported("FOR EACH collection form")
            names = [S.SYSTEM_OBJECT_REFS[buf[t + 1]]]
            t += 2
            while t + 3 <= end and buf[t] == S.MEMBER:
                names.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            if t + 3 <= end and buf[t] == S.SYM:
                names.append(_sym(syms, S.u16(buf, t + 1)))
                coll = MemberPath(names)
                t += 3
            else:
                raise Unsupported("FOR EACH collection form")
        else:
            raise Unsupported("FOR EACH collection form")
        fox = False
        if t < end and buf[t] == S.FOREACH_FOXOBJECT_MARK:
            fox = True
            t += 1
        # Jump tail sits after the collection / optional FOXOBJECT, not after
        # an fd-wrapped expression. Dominant f9 05 <u16>; e9 00 <u32> is the
        # long-jump width of the same ENDEACH anchor (round-28 W3 on FOR/IF/
        # DO WHILE/SCAN; this lane on FOR EACH). Unmeasured residue keeps
        # "FOR EACH frame shape".
        rel, t = _jump_target(buf, t, end, "FOR EACH", with_fd=False)
        return ForEachStmt(var, coll, fox, rel_target=rel,
                           as_class=as_class, of_lib=of_lib)
    if lead == S.ENDFOR_LEAD:
        if end != 1:
            raise Unsupported("ENDFOR trailing bytes")
        return ("ENDFOR",)
    if lead == S.ENDSCAN_LEAD:
        # Round-22 k1 (probes/oracle_harvest/round22_streams.json): the bare
        # one-byte statement closing the 7e-led SCAN frame. Frame accounting is
        # the walker's job (it pairs this sentinel with its opener exactly like
        # ENDFOR 85 and emits the block there); this standalone decode exists so
        # single-statement probing (foxlift.impact attribution) charges no
        # phantom schema against a correctly framed ENDSCAN.
        if end != 1:
            raise Unsupported("ENDSCAN trailing bytes")
        return ("ENDSCAN",)
    if lead in (S.ENDTEXT_LEAD, S.ENDEACH_LEAD):
        # Standalone decode of the two remaining frame sentinels — trio-7f/
        # ENDSCAN precedent. The TEXT frame consumes bare 1f and the FOR EACH
        # frame consumes bare b6 inside _walk_block, so a correctly FRAMED
        # statement never reaches this arm; the decode exists so single-
        # statement probing (foxlift.impact attribution) charges no phantom
        # "statement lead ..." schema against them. Corpus census at base:
        # bare 1f x67 / bare b6 x51 sightings, zero other shapes.
        if end != 1:
            raise Unsupported("frame sentinel trailing bytes")
        return ("ENDTEXT",) if lead == S.ENDTEXT_LEAD else ("ENDEACH",)
    if lead == S.STR:
        # r62-textline: a verbatim TEXT-frame body line decoded standalone —
        # `fb <u16 len excluding newline> <source bytes>` (round-23 FORCED,
        # round-47 measured; the round-62 matrix re-measured the format across
        # every body shape). A correctly FRAMED body line NEVER reaches this arm:
        # _walk_block's TEXT branch consumes the opener and every following body
        # line up to 1f, and a top-level fb still raises "verbatim text line
        # outside a TEXT frame" there. The decode exists so single-statement
        # decoding — the census's per-statement attribution and foxlift.impact —
        # identifies the line as its stored source instead of charging an
        # unmeasured lead against every body line of a section that failed to
        # lift for some other reason. The length is attacker-shaped and degrades
        # to Unsupported on any mismatch, exactly as the frame walk's body check.
        if end < 3 or 3 + S.u16(buf, 1) != end:
            raise Unsupported("verbatim text line length")
        return TextLine(_payload_text(buf[3:]))
    if lead == 0x0B or lead == 0xB7:
        # CANCEL / DOEVENTS: oracle-bound one-byte statements (CMD_SWEEP.md
        # bound-command rows CANCEL '0b' and DOEVENTS 'b7'). Corpus-aligned as
        # bare single bytes only: 0b x17 (charts.scx::CmdPrint s0 stmt13,
        # print.scx::cgPrint s4 stmt4, ...) and b7 x7 (_webview.vcx
        # refreshsource s17..s19, _webbrowser3 s45..s47).
        if end != 1:
            raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
        return ("CANCEL",) if lead == 0x0B else ("DOEVENTS",)
    if lead in (0x39, 0x3B, 0xB3):
        # r49-valsweep: three more bare one-byte statements, identified by
        # compiling every one-byte command the matrix could author — READ is
        # 39, REINDEX is 3b (with an optional COMPACT riding bf) and DEBUG is
        # b3. EJECT (1a) came out of the same sweep and round 49 left it
        # unadopted for want of a carrier; r50-leadsweep adopts it with the
        # rest of the one-byte bank (_R50_BARE_COMMANDS), because this round's
        # work order is the LANGUAGE rather than a carrier count.
        if end == 1:
            return ({0x39: "READ", 0x3B: "REINDEX", 0xB3: "DEBUG"}[lead],)
        if lead == 0x3B and end == 2 and buf[1] == 0xBF:
            return ("REINDEX COMPACT",)
        raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
    if lead == 0x0F:
        # CLOSE TABLES / CLOSE DATABASES [ALL]: oracle-bound two-byte form
        # (CMD_SWEEP.md row CLOSE '0f31'; corpus chartbillprint.scx::cdPrint
        # s0 stmt2). Round-29 census of all fifteen blocked representatives
        # binds the remaining spellings to stored source: c2 = DATABASES
        # ('CLOSE DATA[BASES]', frmSysinfo family x7 incl. erp.scx::frmAbout
        # s1/s2) and a trailing 03 = ALL scope clause, the same byte HIDE /
        # DEACTIVATE WINDOW ALL use ('87 2c 03'): 'CLOSE DATABASES ALL' <->
        # 0f c2 03 (supplyprice frmPrice s3 et al.), 'CLOSE TABLES ALL' <->
        # 0f 31 03 (adjusttable frmAdjustTable s7 stmt0). Anything else rejects.
        # r49-valsweep completes the keyword bank in one compile: ALL is the
        # same 03 scope byte every other verb uses, and INDEXES and PROCEDURE
        # have their own bytes. The trailing-03 ALL clause stays admitted only
        # behind TABLES and DATABASES, which are the measured carriers.
        words = {0x03: "ALL", 0x31: "TABLES", 0xC2: "DATABASES",
                 0xC1: "INDEXES", 0xBE: "PROCEDURE"}
        if end == 2 and buf[1] in words:
            return ("CLOSE " + words[buf[1]],)
        if end == 3 and buf[1] in (0x31, 0xC2) and buf[2] == S.PAREN:
            return ("CLOSE " + words[buf[1]] + " ALL",)
        raise Unsupported("statement lead 0x0f")
    if lead == 0x10:
        # CONTINUE: bare one-byte statement (CMD_SWEEP.md row CONTINUE;
        # corpus _reportlistener fxtherm s22 stmt28 / updatelistener s21
        # stmt11 inside LOCATE ... SKIP loops; bare-only, x4 statements).
        if end != 1:
            raise Unsupported("statement lead 0x10 trailing bytes")
        return ("CONTINUE",)
    if lead == 0x8D:
        # '\ <text>' merged-output line: fb envelope runs to end-of-statement
        # (CMD_SWEEP.md row '\' '8dfb11..'; census charts.scx::foxcharts1
        # s2 stmt73 carries the measured empty form '8dfb0000').
        if end < 4 or buf[1] != S.STR:
            raise Unsupported("statement lead 0x8d")
        n = S.u16(buf, 2)
        if 4 + n != end:
            raise Unsupported("statement lead 0x8d trailing bytes")
        return BackslashLine(_payload_text(buf[4:4 + n]))
    if lead == 0x24:
        # HELP [ID <expr> NOWAIT] <topic>: oracle bare form 'HELP' <->
        # 24 fb0000 (CMD_SWEEP.md row HELP); census _dialogs cmdHelp s0 stmt0
        # 'HELP ID (thisform.HelpContextID) NOWAIT' <-> 49 <group> 3a fb0000.
        # ID is measured only together with NOWAIT; the topic string is
        # REQUIRED and empty on every carrier.
        t = j
        id_expr = None
        nowait = False
        if t < end and buf[t] == 0x49:
            # r49-valsweep: the ID clause is independent of NOWAIT. Round 29
            # had only a carrier that spelled both and required the pair; the
            # matrix compiles `HELP ID 12`, `HELP ID (m.a)` and
            # `HELP ID (m.a) NOWAIT` and the first two carry no 3a at all.
            t += 1
            id_expr, t = _fc_group(buf, t, end, syms)
            # NOWAIT stays admitted only behind an ID clause: the matrix
            # measures HELP, HELP ID <x> and HELP ID <x> NOWAIT, and a bare
            # HELP NOWAIT has no measured producer, so round 29's guard on
            # that shape is untouched.
            if t < end and buf[t] == 0x3A:
                nowait = True
                t += 1
        if t >= end or buf[t] not in (S.STR, S.STR2):
            raise Unsupported("HELP topic string missing")
        topic, t = _dec_str_arg(buf, t, end)
        if t != end:
            raise Unsupported("statement lead 0x24 trailing bytes")
        return HelpStmt(id_expr, nowait, topic)
    if lead == 0x2B:
        # LIST: bare form oracle-measured (CMD_SWEEP.md row LIST '2b'); corpus
        # VFPxWorkbookXLSX s15 stmt21 'LIST TO FILE (lcFileName) NOCONSOLE' <->
        # 28 12 <group> 39 f80300 — target as one fc-group, NOCONSOLE bound to
        # that exact tail. Round-35 extends the arm along corpus-forced clause
        # bytes only, each aligned statement-exact to its stored line
        # (foxcharts s59 stmt79 <-> L3306, stmt83 <-> L3310):
        #   1b = MEMORY, cb = STATUS, 18 <fb-string> = LIKE skeleton; both
        # carriers end bare 39 — the same NOCONSOLE marker without the operand.
        # Only the attested clause/tail combinations are accepted; every other
        # spelling stays unmeasured and rejects.
        if end == 1:
            return ("LIST",)
        clause = None
        t = 1
        if buf[1] == 0x1B:
            clause = "MEMORY"
            t = 2
        elif buf[1] == 0xCB:
            clause = "STATUS"
            t = 2
        if end < t + 2 or buf[t] != S.TO_MARK or buf[t + 1] != S.COPY_FILE_MARK:
            raise Unsupported("statement lead 0x2b")
        target, k = _fc_group(buf, t + 2, end, syms)
        like = None
        if clause == "MEMORY":
            # LIKE consumes the pattern literal; only the single-token unquoted
            # skeleton is measured ('LIKE *'), mirroring the r29 bare-path guard.
            if k >= end or buf[k] != 0x18:
                raise Unsupported("statement lead 0x2b")
            like, k = _dec_str_arg(buf, k + 1, end)
            if like == "" or any(ch in like for ch in " \t\"'"):
                raise Unsupported("statement lead 0x2b unsafe LIKE skeleton")
        if clause is None:
            # Round-29 exactness preserved: on the bare form NOCONSOLE is the
            # full 39 f80300 tail; a bare statement-final 39 there is unmeasured.
            if k + 4 != end or buf[k] != 0x39 \
                    or buf[k + 1:k + 4] != bytes([0xF8, 0x03, 0x00]):
                raise Unsupported("statement lead 0x2b trailing bytes")
        else:
            if k + 1 != end or buf[k] != 0x39:
                raise Unsupported("statement lead 0x2b trailing bytes")
        return ListToFileStmt(target, True, clause, like)
    if lead == 0x45:
        # SEEK <expr>: fc-wrapped operand runs UNCLOSED to end of statement,
        # exactly like DEBUGOUT (CMD_SWEEP.md row SEEK '45fc..'; census
        # _internet _cookie s2 stmt2 'SEEK THIS.cCookie'). An explicit fd is
        # an unmeasured spelling and rejects.
        if j >= end or buf[j] != S.FC:
            raise Unsupported("SEEK expression unwrapped")
        es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or k != end:
            raise Unsupported("statement lead 0x45 trailing bytes")
        return SeekStmt(es[0])
    if lead == 0x5C:
        # KEYBOARD '<keys>' [PLAIN]: two measured spellings — 5c fc <expr>
        # fd 3b (CMD_SWEEP.md row '5cfcfb01006bfd3b'; census _urlcombobox
        # '{TAB}'/'{Ctrl+A}' d9 carriers, all spelling PLAIN in source) and
        # the bare statement-final group 5c fc <expr> with fd reader-stripped
        # (managecode Command1 '{ctrl+f10}', whose stored line carries no
        # PLAIN word). 3b is therefore bound to PLAIN and only ever follows
        # an explicit fd; every other clause combination rejects.
        if j >= end or buf[j] != S.FC:
            raise Unsupported("KEYBOARD keys unwrapped")
        es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("KEYBOARD keys unresolved")
        if k == end:
            return KeyboardStmt(es[0])
        if k + 2 == end and buf[k] == S.FD and buf[k + 1] == 0x3B:
            return KeyboardStmt(es[0], plain=True)
        raise Unsupported("statement lead 0x5c trailing bytes")
    if lead == S.ZOOM_WINDOW_LEAD:
        # ZOOM WINDOW <name> MAX|MIN|NORM — `8c 2c <name> <mode>`. The lead map
        # was corrected to 8c = ZOOM WINDOW in the round-37 gap findings, whose
        # probe D5 emitted 'ZOOM WINDOW (m.lcW) NORM' as 8c2cfcf50df7010003fdd6;
        # round-40 lane H measures the mode space (MAX be / MIN bf / NORM d6,
        # probes f20/f22/f23) and pins the carrier frame — f20's
        # 'ZOOM WINDOW (lcName) MAX' is 8c2cfcf7000003fdbe, raw-equal to
        # _reports.vcx::_output #92 modulo symbol index. The mode byte is
        # MANDATORY: the oracle refuses an unrecognised keyword outright (f30),
        # so there is no bare frame and no other keyword to admit.
        if end < 4 or buf[1] != S.DEFINE_WINDOW_KW:
            raise Unsupported("statement lead 0x8c")
        name, t = _dec_window_name(buf, 2, end, syms, verb="ZOOM")
        if t + 1 != end or buf[t] not in S.ZOOM_WINDOW_MODES:
            raise Unsupported("ZOOM WINDOW mode shape")
        return ZoomWindowStmt(name, S.ZOOM_WINDOW_MODES[buf[t]])
    if lead in (0x80, 0x87):
        # SHOW WINDOW (0x80) and HIDE WINDOW (0x87) share one frame:
        #   <lead> 2c [16 <parent-group>] [modifier] <name>
        # census fxtherm s16 stmt17 / updatelistener s29 'SHOW WINDOW (.Name)
        # IN WINDOW (m.lcParentFormName)' <-> 80 2c 16 <parent> <name> — the
        # wire carries the IN-WINDOW argument FIRST. r48-valsweep measured the
        # clause-free forms and the verb split (`SHOW WINDOW w` -> 802cf70000,
        # `HIDE WINDOW w` -> 872cf70000) and the SHOW modifiers REFRESH c4,
        # TOP 29, BOTTOM 36, SAME cf, which sit before the name.
        verb = "SHOW" if lead == 0x80 else "HIDE"
        if end < 3 or buf[1] != 0x2C:
            raise Unsupported("statement lead 0x%02x" % lead)
        t = 2
        in_win = None
        if buf[t] == 0x16:
            in_win, t = _fc_group(buf, t + 1, end, syms)
        modifier = ""
        if t < end and buf[t] in S.SHOW_WINDOW_MODIFIERS and lead == 0x80:
            modifier = S.SHOW_WINDOW_MODIFIERS[buf[t]]
            t += 1
        if t + 3 <= end and buf[t] == S.SYM:
            name, t = Sym(_sym(syms, S.u16(buf, t + 1))), t + 3
        elif t < end and buf[t] == S.FC:
            name, t = _fc_group(buf, t, end, syms)
        else:
            raise Unsupported("%s WINDOW name form" % verb)
        if t != end:
            raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
        return ShowWindowStmt(name, in_win, verb=verb, modifier=modifier)
    if lead == 0xAA:
        # DEBUGOUT <expr>: aa fc <expr> with NO closing fd — the group runs to
        # end-of-statement on every carrier (CMD_SWEEP.md row 'aafcf70000';
        # census xfrxhyperlink member path / xfcont d9 literal). The STRTRAN
        # carrier whose 43-group closes with bare 0xa8 stays blocked until
        # that closer joins an enabled set.
        if j >= end or buf[j] != S.FC:
            raise Unsupported("DEBUGOUT expression unwrapped")
        es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or k != end:
            raise Unsupported("statement lead 0xaa trailing bytes")
        return DebugoutStmt(es[0])
    if lead == 0xAD:
        # Round 29 measured the one corpus carrier — xfcont s16 stmt48
        # 'MOUSE AT liMTop,liMLeft WINDOW (Thisform.Name) PIXELS' <-> ad ca 2c
        # <w-group> 05 <r-group> 07 <c-group> — and required all five parts.
        # r49-valsweep compiled the clause bank: every clause is optional, the
        # actions are c3 CLICK / c5 DBLCLICK / c6 DRAG, and DRAG spells its
        # coordinates TO (28) rather than AT (05).
        t = 1
        pixels = False
        window = None
        action = ""
        if t < end and buf[t] == 0xCA:
            pixels = True
            t += 1
        if t < end and buf[t] == 0x2C:
            window, t = _fc_group(buf, t + 1, end, syms)
        if t < end and buf[t] in (0xC3, 0xC5, 0xC6):
            action = {0xC3: "CLICK", 0xC5: "DBLCLICK", 0xC6: "DRAG"}[buf[t]]
            t += 1
        if t >= end or buf[t] not in (0x05, S.TO_MARK):
            raise Unsupported("MOUSE AT clause missing")
        to_coords = buf[t] == S.TO_MARK
        row, t = _fc_group(buf, t + 1, end, syms)
        if t >= end or buf[t] != S.ARGJOIN:
            raise Unsupported("MOUSE coordinate pair malformed")
        col, t = _fc_group(buf, t + 1, end, syms)
        if t != end:
            raise Unsupported("statement lead 0xad trailing bytes")
        return MouseStmt(row, col, window, pixels=pixels, action=action,
                         to_coords=to_coords)
    if lead == 0xB0:
        # CD/CHDIR <path>: direct fb/d9 literal (census 'CD D:\', 'CD Dats',
        # 'CD ..') or one fc-group operand (CMD_SWEEP.md row CD 'b0fc..');
        # anything else stays rejected.
        path, t = _dec_r29_dir_literal(buf, j, end, lead)
        if path is not None:
            if t != end:
                raise Unsupported("statement lead 0xb0 trailing bytes")
            return CdStmt(path)
        if j < end and buf[j] == S.FC:
            node, t = _fc_group(buf, j, end, syms)
            if t != end:
                raise Unsupported("statement lead 0xb0 trailing bytes")
            return CdStmt(_emit(node))
        raise Unsupported("statement lead 0xb0")
    if lead in (0xB1, 0xB2):
        # MD|MKDIR / RD|RMDIR <dir>: direct literal (CMD_SWEEP.md rows
        # 'b1fb..', 'b2fb..') or one parenthesised fc-group whose PAREN
        # postfix 03 closes statement-final (census VFPxWorkbookXLSX s14
        # 'MKDIR (lcDir)' family x6 statements, s66 'RMDIR (tcDir)').
        path, t = _dec_r29_dir_literal(buf, j, end, lead)
        if path is not None:
            if t != end:
                raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
            return MkdirStmt(path, remove=(lead == 0xB2))
        if j < end and buf[j] == S.FC:
            node, t = _fc_group(buf, j, end, syms)
            if t != end:
                raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
            return MkdirStmt(_emit(node), remove=(lead == 0xB2))
        raise Unsupported("statement lead 0x%02x" % lead)
    if lead == S.LOOP_LEAD:
        if end != 1:
            raise Unsupported("LOOP trailing bytes")
        return LoopStmt()
    if lead == S.EXIT_LEAD:
        if end != 1:
            raise Unsupported("EXIT trailing bytes")
        return ExitStmt()
    if lead == S.DO_CASE_LEAD and len(buf) >= 2 and buf[1] == S.DOWHILE_MARK:
        if buf[2] != S.FC:
            raise Unsupported("DO WHILE condition unwrapped")
        es, k = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("DO WHILE frame shape")
        rel, _ = _jump_target(buf, k, end, "DO WHILE")
        return DoWhile(es[0], [], rel)
    if lead == S.ENDDO_LEAD:
        if end != 1:
            raise Unsupported("ENDDO trailing bytes")
        return ("ENDDO",)
    if lead == S.SKIP_LEAD:
        # round-28 W4: 48 [fc <expr> [fd]] [16 <area-sym>] — see SkipStmt.
        # Unmeasured clause bytes keep the loud trailing-bytes label.
        if end != 1 and buf[1] not in (S.FC, S.GO_IN_CLAUSE):
            raise Unsupported("SKIP trailing bytes")
        t = 1
        n_expr = None
        area = None
        # r48-valsweep: with an alias the wire puts it FIRST — `SKIP -1 IN t`
        # is 48 16 <alias> fc <n>, not the round-28 W4 order. Both are read.
        while t < end:
            if buf[t] == S.FC and n_expr is None:
                es, k = _dec_expr(buf, t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) != 1:
                    raise Unsupported("SKIP expression unresolved")
                if k < end and buf[k] == S.FD:
                    k += 1
                elif k != end:
                    raise Unsupported("SKIP expression unresolved")
                n_expr = es[0]
                t = k
                continue
            if buf[t] == S.GO_IN_CLAUSE and area is None:
                # r54-inalias: the same three alias spellings SET's and ZAP's
                # `16` mark carry. `SKIP IN (m.a)` is the corpus shape
                # `48 16 ( ~`; with a count the group closes on its own fd
                # and the count group follows.
                area, t = _dec_in_alias(buf, t + 1, end, syms,
                                        refusal="SKIP IN area unresolved")
                continue
            break
        if t != end:
            raise Unsupported("SKIP trailing bytes")
        return SkipStmt(n=n_expr, in_area=area)
    if lead == S.PUSH_KEY_LEAD or lead == S.POP_KEY_LEAD:
        # ORACLE-measured two-byte forms (CMD_SWEEP.md: 'PUSH KEY' -> 8a17,
        # 'POP KEY' -> 8b17); corpus-aligned as a save/restore pair in
        # _reports.vcx::_outputdialog sec24 (source lines 238/252). The second
        # byte 17 is part of the measured shape; other PUSH/POP variants
        # (PUSH MENU <name> ...) are unmeasured and stay Unsupported.
        # Round-28 W4: PUSH KEY CLEAR = 8a 17 0c (_reportlistener fxtherm
        # s19 stmt2 / updatelistener s23 stmt2, stored 'PUSH KEY CLEAR');
        # a POP-side CLEAR is unmeasured and stays rejected.
        if end == 2 and buf[1] != 0x17:
            raise Unsupported("PUSH/POP KEY trailing bytes")
        if lead == S.PUSH_KEY_LEAD and end == 3 and \
                buf[1] == 0x17 and buf[2] == 0x0C:
            return ("PUSH KEY CLEAR",)
        # r42-zapin: PUSH/POP MENU <sysmenu> = 8a/8b 1c ec <id>.
        # _MSYSMENU is id 0x02; _MFILE is 0x23. Other ids stay Unsupported.
        if end == 4 and buf[1] == S.ON_SELECTION_MENU \
                and buf[2] == S.MENU_BAR_ID_MARK:
            name = S.PUSH_POP_MENU_IDS.get(buf[3])
            if name is None:
                raise Unsupported("PUSH/POP MENU id 0x%02x unmeasured" % buf[3])
            verb = "PUSH" if lead == S.PUSH_KEY_LEAD else "POP"
            return ("%s MENU %s" % (verb, name),)
        if end != 2 or buf[1] != 0x17:
            raise Unsupported("PUSH/POP KEY trailing bytes")
        return ("PUSH KEY",) if lead == S.PUSH_KEY_LEAD else ("POP KEY",)
    if lead == S.PACK_LEAD:
        # ORACLE-measured bare PACK (CMD_SWEEP.md row PACK); corpus-aligned at
        # systeminfo.scx::frmSysinfo (source line 94, after a SELECT).
        if end != 1:
            raise Unsupported("PACK trailing bytes")
        return ("PACK",)
    if lead == S.COPY_LEAD:
        # COPY [FILE <from>] TO <to>: full form oracle-measured (CMD_SWEEP.md
        # row COPY); the TO-only form is corpus-aligned at frmSysinfo
        # ('COPY TO LU3', source line 75). Round-28 W4 measured widenings, each
        # carrier-aligned: FILE/TO operands admit fc-groups as well as fb/d9
        # literals ('COPY FILE (m.cSkel) TO (m.cOut)', foxcharts s17 stmt33);
        # trailing cc = STRUCTURE ('COPY STRUCTURE TO tmplhd', salesgenyc
        # fixdata s1 stmt4); trailing [d4] be d1 {bf <fb-char> | c4} =
        # [TYPE] DELIMITED WITH CHARACTER '<c>' | TAB (preorder1 Command3 s0
        # stmts4/11; APPEND's KQ.txt tail shares the be-d1 clause bytes).
        t = j
        name_from = None
        memo_field = None
        if t + 3 <= end and buf[t] == S.COPY_FILE_MARK:
            t += 1
            if t < end and buf[t] in (S.STR, S.STR2):
                name_from, t = _dec_str_arg(buf, t, end)
            else:
                try:
                    name_from, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("COPY FROM expression unresolved")
                name_from = _emit(name_from)
            name_from = str(name_from)
        elif t + 3 <= end and buf[t] == 0x1B:
            # Round-32: COPY MEMO <field> TO <target> — carrier _webview.vcx::
            # _webbrowser3 s21 stmt13 'COPY MEMO Text TO (tcFileName)' <->
            # 11 1b f7<field> 28 <target-group>. The memo field operand is
            # measured ONLY as an f7 symbol; the MEMO arm admits no further
            # clauses, so every other spelling/tail stays Unsupported.
            t += 1
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("COPY MEMO field form")
            memo_field = _sym(syms, S.u16(buf, t + 1))
            t += 3
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("COPY TO clause missing")
        t += 1
        structure = False
        delimited = None
        to_array = False
        fields = None
        type_word = False
        file_type = ""
        if memo_field is not None:
            # Round-32 hardening (post-review F2): the measured MEMO target is
            # EXACTLY fc f7<u16 symbol> 03 at statement end — the runtime-
            # parenthesised symbol spelling of the carrier (_webbrowser3 s21
            # stmt13). Left to the shared readers below, this arm also admitted
            # UNMEASURED spellings (direct fb/d9 literal targets, fc-wrapped
            # string literals, paren-less fc groups); they reject here before
            # any shared reader runs.
            if t + 5 != end or buf[t] != S.FC or buf[t + 1] != S.SYM \
                    or buf[t + 4] != S.PAREN:
                raise Unsupported("COPY MEMO target form")
        if t < end and buf[t] == 0x04:
            # Round-32: COPY TO ARRAY <arr> FIELDS <list> — carrier
            # mainmenu3.scx::msagent s0 stmt6 'COPY TO ARRAY gaTemp FIELDS
            # DATEID,TRUCKNO,REMOTION,NOTE' <-> 11 28 04 f7<arr> 11 f7<a>
            # [07 f7<b>]*. The lead byte reappears context-locally as the
            # FIELDS mark (same convention as its APPEND/INSERT precedents);
            # the array target and every field are measured ONLY as f7
            # symbols; the list runs to end-of-statement with ARGJOIN (07)
            # separators and NO terminator byte. A FIELDS-less COPY TO ARRAY
            # is unmeasured and rejects.
            to_array = True
            t += 1
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("COPY target form")
            name_to = _sym(syms, S.u16(buf, t + 1))
            t += 3
            if t >= end or buf[t] != S.COPY_LEAD:   # 11 FIELDS, context-local under 04
                raise Unsupported(
                    "COPY TO ARRAY without FIELDS unmeasured")
            t += 1
            fields = []
            while True:
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("COPY FIELDS list unresolved")
                fields.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
                if t < end and buf[t] == S.ARGJOIN:
                    t += 1
                    continue
                break
        elif t < end and buf[t] in (S.STR, S.STR2):
            name_to, t = _dec_str_arg(buf, t, end)
        elif t < end and buf[t] == S.FC:
            try:
                node, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("COPY target form")
            name_to = _emit(node)
        else:
            raise Unsupported("COPY target form")
        if memo_field is not None or to_array:
            # The MEMO/ARRAY arms carry no STRUCTURE/DELIMITED tail: anything
            # after the measured shape stays loudly Unsupported.
            if t != end:
                raise Unsupported("COPY trailing bytes")
            return CopyStmt(name_to, name_from, memo=memo_field,
                            to_array=to_array, fields=fields)
        if t < end and buf[t] == S.COPY_LEAD:
            # r48-valsweep: `COPY TO (m.x) FIELDS f TYPE SDF` puts the same
            # context-local 11 FIELDS mark after a plain target, not only after
            # the 04 ARRAY one.
            t += 1
            fields = []
            while True:
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("COPY FIELDS list unresolved")
                fields.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
                if t < end and buf[t] == S.ARGJOIN:
                    t += 1
                    continue
                break
        if t < end and buf[t] == 0xCC:
            structure = True
            t += 1
        elif t < end and (buf[t] == 0xD4 or buf[t] in S.FILE_TYPE_WORDS):
            # d4 is the source's TYPE word (r47-typeword: present exactly when
            # the source spells it, on COPY TO and APPEND FROM alike). r48-
            # valsweep: each file type is its own byte and only DELIMITED takes
            # the WITH tail [d1 bf {fb/d9 <char> | c4 TAB}] — goods.txt /
            # containers.txt carry the string form, attendanceforcheck cdget
            # s0[40] the TAB form.
            if buf[t] == 0xD4:
                type_word = True
                t += 1
            if t >= end or buf[t] not in S.FILE_TYPE_WORDS:
                raise Unsupported("COPY trailing bytes")
            file_type = S.FILE_TYPE_WORDS[buf[t]]
            t += 1
            if file_type == "DELIMITED" and t + 1 < end \
                    and buf[t] == 0xD1 and buf[t + 1] == 0xBF:
                t += 2
                if t < end and buf[t] == 0xC4:
                    delimited = ("TAB",)
                    t += 1
                elif t < end and buf[t] in (S.STR, S.STR2):
                    delim_char, t = _dec_str_arg(buf, t, end)
                    delimited = ("CHARACTER", delim_char)
                else:
                    raise Unsupported("COPY trailing bytes")
        if t != end:
            raise Unsupported("COPY trailing bytes")
        return CopyStmt(name_to, name_from, structure=structure,
                        delimited=delimited, type_word=type_word,
                        fields=fields, file_type=file_type)
    if lead == S.RELEASE_LEAD:
        if end == 2 and buf[1] == 0x03:
            return ReleaseAll()          # RELEASE ALL (frmmainform 3c 03)
        if end == 5 and buf[1] == S.DEFINE_WINDOW_KW and buf[2] == S.SYM:
            # RELEASE WINDOW <name> (round-24 m6 byte-exact; corpus
            # mainmenur.scx::cdtj 'RELEASE WINDOW wbrowse'). This is the shape
            # the lvalue reader mis-charged as "lvalue opcode 0x2c".
            return ReleaseStmt(["WINDOW " + _sym(syms, S.u16(buf, 3))])
        if end >= 4 and buf[1] == S.ON_SELECTION_BAR:
            # r49-menusweep: `RELEASE BAR <n> OF <popup>` shares DEFINE BAR's
            # own frame — 3c 06 fc <n> fd c3 <popup> — with the same three
            # popup operand spellings. The lvalue reader mis-charged it as
            # "lvalue opcode 0x06".
            bar, t = _fc_group(buf, 2, end, syms)
            if t >= end or buf[t] != S.ON_SELECTION_OF:
                raise Unsupported("RELEASE BAR OF clause missing")
            popup, t = _menu_popup_operand(buf, t + 1, end, syms)
            if popup is None or t != end:
                raise Unsupported("RELEASE BAR popup missing")
            return ReleaseStmt(["BAR %s OF %s" % (_emit(bar), popup)])
        if end >= 4 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.FC:
            # the parenthesised popup name, same operand the OF clauses take
            popup, t = _menu_popup_operand(buf, 2, end, syms)
            if popup is None or t != end:
                raise Unsupported("RELEASE POPUP name form")
            return ReleaseStmt(["POPUP " + popup])
        if end >= 5 and buf[1] == S.DEFINE_POPUP_KW and buf[2] == S.SYM:
            # RELEASE POPUP <name>[, <name>...] — round-37 G2 probes b01/b02
            # ('RELEASE POPUP pp,qq,rr' -> 3cc6f7000007f7010007f70200). The c6
            # marks the popup-name list ONCE, at its head; a plain memvar
            # RELEASE (b03) has no marker and keeps the lvalue path below. This
            # is the shape the lvalue reader mis-charged as "lvalue opcode
            # 0xc6".
            t, names = 2, []
            while True:
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("RELEASE POPUP name form")
                names.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
                if t == end:
                    break
                if buf[t] != S.ARGJOIN:
                    raise Unsupported("RELEASE POPUP name list tail")
                t += 1
            return ReleaseStmt(["POPUP " + ", ".join(names)])
        # Round-33 (lane R33-3): the measured corpus also carries the LIBRARY
        # and CLASSLIB clause words plus fc-grouped operands for all three
        # words, each bound to its own stored METHODS line —
        #   3c 2c fc <expr> 03 [fd]  RELEASE WINDOW (<expr>)
        #       (_webview.vcx::_webbrowser3/_webbrowser4 s0 stmt15
        #       'RELEASE WINDOW (lcFileName2)' <-> 3c2cfcf7010003fd)
        #   3c bf fc <expr> 03 [fd]  RELEASE LIBRARY (<expr>)
        #       (_webview.vcx::_webbrowser3 s34 stmt12
        #       'RELEASE LIBRARY (lcFileName)' <-> 3cbffcf7030003fd)
        #   3c 52 fc <expr> 03 [fd]  RELEASE CLASSLIB (<expr>)
        #       (xfrxlib.vcx::xfcont s48 stmt23
        #       'RELEASE CLASSLIB (This.XPath+"xfrxlib_"+lcLang+".vcx")' <->
        #       3c52fcf40100f70700d90800…06d904002e7663780603fd)
        # The words are CONTEXT-LOCAL to lead 0x3c: bf doubles as a bare
        # group-closer id (registry BARE_IDS WOUTPUT) and 52 is WAIT_CLEAR as a
        # statement lead — position decides, never a global token map. The
        # f7-symbol spellings keep the stock readers above/below untouched, so
        # RELEASE ALL and the plain name-list grammar behave byte-identically.
        if end >= 3 and buf[1] in (S.DEFINE_WINDOW_KW, S.RELEASE_LIBRARY_KW,
                                   S.RELEASE_CLASSLIB_KW) \
                and buf[2] != S.SYM:
            word = {S.DEFINE_WINDOW_KW: "WINDOW", S.RELEASE_LIBRARY_KW: "LIBRARY",
                    S.RELEASE_CLASSLIB_KW: "CLASSLIB"}[buf[1]]
            if buf[2] != S.FC:
                raise Unsupported(f"RELEASE {word} operand unwrapped")
            es, k = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or not isinstance(es[0], Paren):
                # the source's parentheses ARE the operand: they ride the group
                # as the trailing PAREN postfix (same framing as SET-value /
                # STORE-name groups), so an unparenthesised group has no
                # measured producer and stays loudly Unsupported.
                raise Unsupported(f"RELEASE {word} operand unresolved")
            if k < end and buf[k] == S.FD:
                k += 1                   # non-statement-final groups keep their fd
            if k != end:
                raise Unsupported("RELEASE trailing bytes")
            return ReleaseStmt([f"{word} {_emit(es[0])}"])
        names = []
        t = j
        while True:
            lv, t = _dec_lvalue(buf, t, end, syms)
            names.append(_emit(lv))
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("RELEASE name list tail")
            t += 1
        return ReleaseStmt(names)
    if lead == S.LOCATE_LEAD:
        # CORPUS round-30 (readiness.json 'bare-LOCATE one-byte statement (2d)');
        # wire `04 00 2d fe` is a bare LOCATE line (_internet.vcx::_urlcombobox
        # s0/s11, _webview.vcx::_webbrowser3 s28/s29, _dialogs.vcx::_keywords s0;
        # stored sources carry the literal 'LOCATE' lines). Same admission class
        # as measured bare ZAP below (round-25 c1).
        if end == 1:
            return ("LOCATE",)
        # Round-32: optional ALL scope byte 03, measured only immediately in
        # front of the FOR group `13 fc` (see LocateFor). Context-local to this
        # branch; every other shape after the lead keeps the unwrapped label.
        # r49-valsweep widens round 32's single ALL byte to the whole bank
        # SCAN carries (r48 law 11) and separates the two clauses:
        #     2d [03 ALL | 24 REST | 1e fc <n> fd NEXT]
        #        [13 fc <FOR> fd] [2b fc <WHILE>]
        # `LOCATE REST FOR`, `LOCATE NEXT 3 FOR`, `LOCATE WHILE` with no FOR
        # and `LOCATE REST WHILE` are each their own compile.
        t = 1
        all_scope = False
        scope_word = None
        scope_expr = None
        if buf[t] == 0x03:
            all_scope = True
            t += 1
        elif buf[t] == 0x24:
            scope_word = "REST"
            t += 1
        elif buf[t] == 0x1E:
            scope_word = "NEXT"
            scope_expr, t = _fc_group(buf, t + 1, end, syms)
        if t + 1 >= end or buf[t] not in (0x13, 0x2B) or buf[t + 1] != S.FC:
            raise Unsupported("LOCATE FOR unwrapped")
        if buf[t] == 0x2B:
            # a WHILE clause with no FOR runs to the end of the statement
            ws0, k0 = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ws0) != 1 or k0 != end:
                raise Unsupported("LOCATE WHILE unresolved")
            return LocateFor(None, all_scope=all_scope, while_cond=ws0[0],
                             scope_word=scope_word, scope_expr=scope_expr)
        # Round-33 (locate_while lane): the FOR window stops at its own fd so a
        # trailing clause unit can follow it. A top-level fd never had an
        # expression arm — stock always raised 'expression opcode 0xfd' there —
        # so the stop byte cannot change the parse of any already-lifting
        # shape: with no fd in its window this decodes exactly as before.
        with _sym_tap() as for_tap:
            es, k = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("LOCATE FOR expression unresolved")
        while_cond = None
        while_tap = None
        if k < end and buf[k] == S.FD:
            k += 1
        elif k != end:
            raise Unsupported("LOCATE FOR expression unresolved")
        if k < end and buf[k] == 0x2B:
            # optional WHILE clause unit `2b fc <rpn>`; the FINAL clause runs
            # to stream end and carries no fd of its own. Measured trio
            # xfrxlib.vcx::xfrxie s0 stmt30 <-> stored L54 'LOCATE WHILE
            # XX000==liPage FOR XX001==""' and xfcont twins s15/s46; anything
            # else after the fd (junk, a second fd, an unwrapped or truncated
            # unit) keeps the loud rejection.
            if not (k + 2 < end and buf[k + 1] == S.FC):
                raise Unsupported("LOCATE WHILE unwrapped")
            with _sym_tap() as while_tap:
                ws, k2 = _dec_expr(buf, k + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(ws) != 1 or k2 != end:
                raise Unsupported("LOCATE WHILE unresolved")
            while_cond = ws[0]
            k = k2
        if k != end:
            raise Unsupported("LOCATE FOR expression unresolved")
        # r49-clauseorder: the ALL spelling with a WHILE clause is unmeasured
        # in either order, so the scope word keeps the canonical emission.
        return LocateFor(es[0], all_scope=all_scope, while_cond=while_cond,
                         scope_word=scope_word, scope_expr=scope_expr,
                         while_first=(while_tap is not None and not all_scope
                                      and scope_word is None
                                      and _written_first(while_tap, for_tap)))
    if lead == S.USE_LEAD:
        if end == 1:
            return UseStmt()
        # Clause forms. Iter-36 token walk ('USE LU3 IN 0 EXCLUSIVE',
        # 'USE Formula IN 0', 'USE IN x') plus corpus-aligned clauses (each cites
        # the artifact::method whose stored source forced it):
        #   mode flags BEFORE the name: bc=EXCLUSIVE (systeminfo 'USE LU3 IN 0
        #     EXCLUSIVE'), c2=SHARED + be=NOUPDATE in this order ('USE (e) SHARED
        #     NOUPDATE ALIAS …', _reportlistener s36 stmts 25/43);
        #   name = fb/d9 literal (existing) or fc..fd expression whose explicit
        #     Paren nodes carry the source parentheses ('USE (THIS.CommandClauses.File)',
        #     fxlistener s38);
        #   AFTER the name the same bc byte = AGAIN — different slot, its own
        #     alignment ('USE (e) AGAIN SHARED NOUPDATE ALIAS FRX', fxlistener s38);
        #   02 = ALIAS marker; measured operand is an f7 symbol ('ALIAS FRX').
        #     Expression aliases exist in the corpus but are NOT admitted here.
        # Unknown clause bytes still raise "USE trailing bytes" (label unchanged).
        name = None
        in_area = None
        exclusive = False
        shared = False
        noupdate = False
        again = False
        alias = None
        norequery = False
        nodata = False
        order = None
        seen_name = False
        j = 1
        while j < end:
            op = buf[j]
            if op == 0x16:                      # IN
                j += 1
                if j < end and buf[j] == S.INT16 and j + 4 <= end and buf[j + 1] == 0x01:
                    in_area = str(S.u16(buf, j + 2))
                    j += 4
                    # round-26 u2 ('USE IN 3' = 5116f9010300): the numeric area
                    # literal carries a trailing 00 byte (unexplained in the
                    # round; recorded raw and consumed here)
                    if j < end and buf[j] == 0x00:
                        j += 1
                elif j + 3 <= end and buf[j] == S.SYM:
                    in_area = _sym(syms, S.u16(buf, j + 1))
                    j += 3
                elif j < end and buf[j] == S.FC:
                    # round-26 u1/u4 + corpus stmts[39]/[46]/[50]:
                    # 'USE IN (m.lcAlias)' groups its runtime expression
                    # (fc .. [03], final fd reader-stripped); a grouped call
                    # like SELECT('scx') closes with its own bare closer 57.
                    try:
                        es, k = _dec_expr(buf, j + 1, end, syms,
                                          stop_bytes=_IF_COND_STOP)
                    except (IndexError, _struct.error) as e:
                        raise Unsupported("USE IN area unresolved") from e
                    if len(es) != 1:
                        raise Unsupported("USE IN area unresolved")
                    if k < end and buf[k] == S.FD:
                        k += 1
                    elif k != end:
                        raise Unsupported("USE IN area unresolved")
                    # the runtime-paren marker (03) inside the group already
                    # renders as parentheses — same convention as the USE file
                    # expression path above
                    in_area = _emit(es[0])
                    j = k
                else:
                    raise Unsupported("USE IN area unresolved")
            elif op == 0xBC and not seen_name:  # EXCLUSIVE (pre-name slot)
                exclusive = True
                j += 1
            elif op == 0xBC and seen_name and not again:  # AGAIN (post-name slot)
                again = True
                j += 1
            elif op == S.USE_SHARED_FLAG and not seen_name:
                shared = True
                j += 1
            elif op == S.USE_NOUPDATE_FLAG and not seen_name:
                noupdate = True
                j += 1
            elif op in (S.STR, S.STR2) and not seen_name:
                n = int.from_bytes(buf[j + 1:j + 3], "little")
                name = buf[j + 3:j + 3 + n].decode("utf-8", "replace")
                seen_name = True
                j += 3 + n
            elif op == S.FC and not seen_name:  # parenthesized name expression
                try:
                    es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
                except (IndexError, _struct.error) as e:
                    # truncated stream inside the name expression: one Unsupported,
                    # never a leak (standing decoder rule 1)
                    raise Unsupported("USE trailing bytes") from e
                if len(es) != 1:
                    raise Unsupported("USE trailing bytes")
                # the FINAL clause's fd is reader-stripped when it ends the statement;
                # mid-statement expressions keep theirs before the next clause byte
                if k < end and buf[k] == S.FD:
                    j = k + 1
                elif k == end:
                    j = k
                else:
                    raise Unsupported("USE trailing bytes")
                name = _emit(es[0])
                seen_name = True
            elif op == 0xC5 and seen_name:
                # round-28 W4: NOREQUERY ('USE TMPORDER IN 0 NOREQUERY',
                # checkmatinput Command2 s0 stmt6; adjusttable frmAdjustTable
                # s0 stmt2 'USE AdjustTable IN 0 NODATA NOREQUERY' wire c5c6)
                norequery = True
                j += 1
            elif op == 0xC6 and seen_name:
                # round-28 W4: NODATA ('USE ShapeNo IN 0 NODATA', temp
                # Command5 s0 stmt3 et al.; supplyprice frmPrice s2[4])
                nodata = True
                j += 1
            elif op == 0xC3 and seen_name and order is None:
                # round-28 W4: ORDER <tag> ('Use Employee Order reports_to',
                # workerchart Form1 s4[7]; _cookie s? 'ORDER 1' as a string)
                j += 1
                if j + 3 > end or buf[j] not in (S.STR, S.STR2):
                    raise Unsupported("USE trailing bytes")
                order, j = _dec_str_arg(buf, j, end)
            elif op == S.USE_ALIAS_MARK and seen_name and alias is None:
                j += 1
                if j + 3 <= end and buf[j] == S.SYM:
                    alias = _sym(syms, S.u16(buf, j + 1))
                    j += 3
                elif j + 3 <= end and buf[j] in (S.STR, S.STR2):
                    # round-28 W4: quoted-string alias operand
                    # ('USE (THIS.ConfigurationTable) ALIAS "OutputConfig" ..',
                    # utilityreportlistener; _keywords 'ALIAS "keywords"').
                    # r48-usealias: the QUOTES are part of the spelling. A bare
                    # alias is an identifier the compiler uppercases into the
                    # symbol table (`02 f7 <sym>`), so re-emitting a stored
                    # string unquoted writes the symbol frame and loses the
                    # case with it.
                    n = S.u16(buf, j + 1)
                    alias = _emit(Str(_payload_text(buf[j + 3:j + 3 + n]),
                                      dq=buf[j] == S.STR2))
                    j += 3 + n
                elif j < end and buf[j] == S.FC:
                    # round-26 u5/u6 (byte-exact replicas of _reportlistener
                    # preparefrxswapcopy stmts[25]/[43]): 'ALIAS (JUSTSTEM(…))'
                    # carries a GROUPED call expression whose final fd may be
                    # reader-stripped
                    try:
                        aes, ak = _dec_expr(buf, j + 1, end, syms,
                                            stop_bytes=_IF_COND_STOP)
                    except (IndexError, _struct.error) as e:
                        raise Unsupported("USE trailing bytes") from e
                    if len(aes) != 1:
                        raise Unsupported("USE trailing bytes")
                    if ak < end and buf[ak] == S.FD:
                        ak += 1
                    elif ak != end:
                        raise Unsupported("USE trailing bytes")
                    alias = _emit(aes[0])
                    j = ak
                else:
                    raise Unsupported("USE trailing bytes")
            else:
                raise Unsupported("USE trailing bytes")
        if (shared or noupdate) and not seen_name:
            # the mode flags only occur before a table name; a flag-only stream is a
            # truncation, never a measured shape
            raise Unsupported("USE trailing bytes")
        return UseStmt(name=name, in_area=in_area, exclusive=exclusive,
                       shared=shared, noupdate=noupdate, again=again, alias=alias,
                       norequery=norequery, nodata=nodata, order=order)
    if lead == S.EXTERNAL_LEAD:
        # FORCED subset: 90 4f fb <len> <name> = EXTERNAL CLASS <file>
        # (_reportlistener.vcx::fxlistener s0, 'EXTERNAL CLASS _GDIPLUS.VCX').
        # Bounds-check before every byte read; unmeasured clause bytes (04 ARRAY,
        # be PROCEDURE) raise the UNCHANGED lead label so blocker attribution
        # for the methods that need them does not churn.
        if end >= 2 and buf[1] == S.EXTERNAL_CLASS_CLAUSE:
            k = 2
            if k + 3 > end or buf[k] != S.STR:
                raise Unsupported("statement lead 0x90")
            n = int.from_bytes(buf[k + 1:k + 3], "little")
            if k + 3 + n != end:
                raise Unsupported("statement lead 0x90")
            return ExternalStmt("CLASS", _payload_text(buf[k + 3:k + 3 + n]))
        if end >= 2 and buf[1] == 0x04:
            # round-28 W4: EXTERNAL ARRAY <names> — 90 04 f7<sym> [07 f7]*
            # (CMD_SWEEP row EXTERNAL '9004f70000'; workerchart Form1 s4
            # carries the two-name form)
            t = 2
            names = []
            while True:
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("statement lead 0x90")
                names.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
                if t == end:
                    break
                if buf[t] != S.ARGJOIN:
                    raise Unsupported("statement lead 0x90")
                t += 1
            return ExternalStmt("ARRAY", ", ".join(names))
        if end >= 2 and buf[1] in S.EXTERNAL_NAME_KINDS:
            # round-28 W4 measured PROCEDURE (be) with a bare fb name
            # ('EXTERNAL PROCEDURE _XFPRINTERPROPERTIES', xfrxlib Xfrxcmd1 s0
            # stmt6). r49-valsweep compiled the whole kind bank in one matrix —
            # FILE 12, FORM 14, SCREEN 26, REPORT 33 beside PROCEDURE be — and
            # measured what the two name spellings do: an UNQUOTED name rides
            # bare `fb <str>` and a quoted one a grouped `fc d9 <str> fd`, the
            # same distinction REPORT FORM's own name operand carries.
            kind = S.EXTERNAL_NAME_KINDS[buf[1]]
            t = 2
            if t < end and buf[t] in (S.STR, S.STR2):
                nm, t = _dec_str_arg(buf, t, end)
                if t != end:
                    raise Unsupported("statement lead 0x90")
                return ExternalStmt(kind, nm)
            if t < end and buf[t] == S.FC:
                es, t = _dec_expr(buf, t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) != 1:
                    raise Unsupported("statement lead 0x90")
                if t < end and buf[t] == S.FD:
                    t += 1
                if t != end:
                    raise Unsupported("statement lead 0x90")
                return ExternalStmt(kind, _emit(es[0]))
            raise Unsupported("statement lead 0x90")
        raise Unsupported("statement lead 0x90")
    if lead == S.OPEN_DATABASE_LEAD:
        # FORCED shape: 95 c2 fb <len> <name> [c2] (see schemas.OPEN_DATABASE_LEAD
        # for the 7/7 alignment). Bounds-check before every byte read; anything but
        # the measured shape raises the UNCHANGED lead label.
        if end < 3 or buf[1] != S.ODB_NAME_MARK:
            raise Unsupported("statement lead 0x95")
        if end < 5 or buf[2] != S.STR:
            raise Unsupported("statement lead 0x95")
        n = int.from_bytes(buf[3:5], "little")
        k = 5 + n
        if k > end:
            raise Unsupported("statement lead 0x95")
        name = _payload_text(buf[5:k])
        shared = False
        if k < end:
            if k + 1 != end or buf[k] != S.ODB_SHARED_FLAG:
                raise Unsupported("statement lead 0x95")
            shared = True
        return OpenDatabaseStmt(name=name, shared=shared)
    if lead == S.SCATTER_LEAD:
        return _dec_scatter_gather(
            buf, end, syms, verb="SCATTER",
            what="SCATTER variant outside measured round-17 forms")
    if lead == S.GATHER_LEAD:
        return _dec_scatter_gather(
            buf, end, syms, verb="GATHER",
            what="GATHER variant outside measured round-17 forms")
    if lead == S.ERROR_LEAD:
        # Round-18 oracle-measured (probes/oracle_harvest/round18_streams.json):
        #   ERROR <expr>          a8 fc <expr-to-stmt-end>, NO fd closer (e01/e02/e05)
        #   ERROR <e1>[, <e2>...] a8 fc <e1> fd 07 fc <e2> [fd 07 fc ...]; only the
        #                         FINAL expression runs unclosed to statement end (e04)
        # The argument is required (e03: bare ERROR is compiler-rejected), and e06
        # shows the next statement following with no intervening fd. Anything
        # outside these measured shapes stays Unsupported.
        # Bounds first, byte second: a bare `a8` (end == 1) must demote this one
        # statement to Unsupported, never leak an IndexError past the scorer.
        if j >= end or buf[j] != S.FC:
            raise Unsupported("ERROR argument unwrapped")
        args = []
        t = j + 1
        while True:
            es, k = _dec_expr(buf, t, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("ERROR expression unresolved")
            args.append(es[0])
            if k == end:
                break                     # final argument: runs unclosed
            if buf[k] != S.FD or k + 3 > end \
                    or buf[k + 1] != S.ARGJOIN or buf[k + 2] != S.FC:
                raise Unsupported("ERROR trailing bytes")
            t = k + 3
        return ErrorStmt(args)
    if lead == S.SCAN_LEAD:
        # 7e [03] [13|2b fc <cond> fd] [f9 05 <u16> | e9 00 <u32>] :
        #   SCAN [ALL] [FOR cond | WHILE cond]. Clause selectors measured:
        #   13 = FOR (round-22 k2), 2b = WHILE (round-32: org_chart.vcx::
        #   organizationchart s1 stmt12 'Scan While rownum = ln_MaxRow').
        #   ALL+WHILE is unmeasured and stays Unsupported. The trailing locator
        #   word's value rides ScanStmt.rel_target; on the measured 2b frames it
        #   binds as the paired ENDSCAN prefix - code_base and _walk_block
        #   verifies it (corruption guard) -- legacy frames keep their historical
        #   consume-without-verify behavior.
        j = 1
        scan_all = False
        scan_cond = None
        scan_while = None
        rel_target = None
        clause_while = False
        # r48-valsweep: `7e [30 NOOPTIMIZE] [scope] [13 FOR] [2b WHILE] <word>`,
        # scope one of 03 ALL / 24 REST / 1e NEXT <n> / 23 RECORD <n>. The three
        # positions are independent — FOR and WHILE can both be present, and the
        # scope word never forbids either.
        nooptimize = False
        scope_word = ""
        scope_expr = None
        if j < end and buf[j] == 0x30:
            nooptimize = True
            j += 1
        if j < end and buf[j] == 0x03:
            scan_all = True
            j += 1
        elif j < end and buf[j] == 0x24:
            scope_word = "REST"
            j += 1
        elif j < end and buf[j] in (0x1E, 0x23):
            scope_word = "NEXT" if buf[j] == 0x1E else "RECORD"
            if j + 1 >= end or buf[j + 1] != S.FC:
                raise Unsupported("SCAN %s count unwrapped" % scope_word)
            ses, sk = _dec_expr(buf, j + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ses) != 1 or sk >= end or buf[sk] != S.FD:
                raise Unsupported("SCAN %s count unresolved" % scope_word)
            scope_expr = ses[0]
            j = sk + 1
        for _clause in (0x13, 0x2B):
            if j >= end or buf[j] != _clause:
                continue
            is_while = _clause == 0x2B
            clause_while = clause_while or is_while
            j += 1
            if j < end and buf[j] == S.FC:
                ces, ck = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                    raise Unsupported("SCAN WHILE clause unresolved" if is_while
                                      else "SCAN FOR clause unresolved")
                if is_while:
                    scan_while = ces[0]
                else:
                    scan_cond = ces[0]
                j = ck + 1
            else:
                raise Unsupported("SCAN WHILE clause unwrapped" if is_while
                                  else "SCAN FOR clause unwrapped")
        while j < end:
            if j + 4 <= end and buf[j] == S.INT16 and buf[j + 1] == 0x05:
                # the word BINDS as ENDSCAN prefix - code_base on the measured
                # 2b frames; legacy frames keep consume-without-verify (ScanStmt)
                if clause_while and rel_target is None:
                    rel_target = S.u16(buf, j + 2)
                j += 4
            elif j + 6 <= end and buf[j] == S.INT32 and buf[j + 1] == 0x00:
                # long-jump spelling of the same SKIP/locator word (round-28 W3)
                if clause_while and rel_target is None:
                    rel_target = int.from_bytes(buf[j + 2:j + 6], "little")
                j += 6
            else:
                break
        if j != end:
            raise Unsupported(f"SCAN trailing bytes ({end - j})")
        if clause_while and rel_target is None:
            # hardening F1: every MEASURED 2b frame carries the trailing locator
            # word (4/4 population carriers); a complete WHILE frame without one
            # is an unmeasured shape -- reject loudly instead of returning a
            # ScanStmt whose rel_target None would skip walk verification.
            # Legacy bare/FOR frames keep lifting without any word.
            raise Unsupported("SCAN WHILE frame without ENDSCAN-distance word")
        return ScanStmt(scan_cond, scan_all, while_cond=scan_while,
                        rel_target=rel_target, scope_word=scope_word,
                        scope_expr=scope_expr, nooptimize=nooptimize)
    if lead == S.TRY_LEAD:
        # ba f9 05 <u16> | ba e9 00 <u32>: same next-clause-mark anchor, two
        # widths (the walker picks which mark: CATCH, else FINALLY, else ENDTRY)
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x05:
            return TryStmt([], target=S.u16(buf, 3))
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            return TryStmt([], target=int.from_bytes(buf[3:7], "little"))
        raise Unsupported("TRY frame shape")
    if lead == S.CATCH_LEAD:
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x05:
            return CatchWhen(None, target=S.u16(buf, 3))
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            return CatchWhen(None, target=int.from_bytes(buf[3:7], "little"))
        if end >= 2 and buf[1] == 0xD2:
            # CATCH WHEN: d2 requires its condition -- bb d2 fc <cond> fd
            # f9 05 <tgt>. A d2 without the fc condition is malformed and must
            # reject as Unsupported, never leak an unbound parse variable.
            j = 2
            if j >= end or buf[j] != S.FC:
                raise Unsupported("CATCH WHEN without condition")
            ces, ck = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                raise Unsupported("CATCH WHEN clause unresolved")
            cond = ces[0]
            j = ck + 1
            if (j + 4 == end and buf[j] == S.INT16
                    and buf[j + 1] == 0x05):
                return CatchWhen(cond, target=S.u16(buf, j + 2))
            if (j + 6 == end and buf[j] == S.INT32
                    and buf[j + 1] == 0x00):
                return CatchWhen(cond,
                                 target=int.from_bytes(buf[j + 2:j + 6], "little"))
            raise Unsupported("CATCH WHEN tail")
        if end == 9 and buf[1] == S.TO_MARK and buf[2] == S.SYM \
                and buf[5] == S.INT16 and buf[6] == 0x05:
            # CATCH TO <var>, plain-symbol spelling: bb 28 f7 <sym> f9 05 <tgt>
            # (measured: fxlistener 'CATCH TO err', sym ERR)
            return CatchWhen(None, target=S.u16(buf, 7),
                             var=_sym(syms, S.u16(buf, 3)))
        if end == 11 and buf[1] == S.TO_MARK and buf[2] == S.SYM \
                and buf[5] == S.INT32 and buf[6] == 0x00:
            # same CATCH TO spelling on the long-jump width (round-28 W3)
            return CatchWhen(None, target=int.from_bytes(buf[7:11], "little"),
                             var=_sym(syms, S.u16(buf, 3)))
        if end == 11 and buf[1] == S.TO_MARK and buf[2] == S.WORKAREA_REF \
                and buf[3] == 0x0D and buf[4] == S.SYM \
                and buf[7] == S.INT16 and buf[8] == 0x05:
            # CATCH TO <var>, explicit memvar-space spelling:
            # bb 28 f5 0d f7 <sym> f9 05 <tgt>
            # (measured: _reportlistener 'CATCH TO m.oError')
            return CatchWhen(None, target=S.u16(buf, 9),
                             var="m." + _sym(syms, S.u16(buf, 5)))
        if end == 13 and buf[1] == S.TO_MARK and buf[2] == S.WORKAREA_REF \
                and buf[3] == 0x0D and buf[4] == S.SYM \
                and buf[7] == S.INT32 and buf[8] == 0x00:
            # same memvar CATCH TO spelling on the long-jump width (round-28 W3)
            return CatchWhen(None,
                             target=int.from_bytes(buf[9:13], "little"),
                             var="m." + _sym(syms, S.u16(buf, 5)))
        # CATCH TO <var> WHEN <cond>, both clauses in ONE statement:
        #   bb 28 (f7 <sym> | f5 0d f7 <sym>) d2 fc <cond> fd f9 05 <u16>
        #   | e9 00 <u32>
        # Measured on foxchartsbeta::foxcharts sec14 stmt7 ('Catch To m.loErr
        # When m.loErr.ErrorNo=1426'; class/ + Source/ twins): the
        # variable spellings are exactly the stock TO forms above, d2 opens
        # WHEN as in the bare WHEN arm, and the jump target keeps both widths.
        if buf[1] == S.TO_MARK and end >= 12:
            j = 2
            if end >= 7 and buf[2] == S.WORKAREA_REF and buf[3] == 0x0D \
                    and buf[4] == S.SYM:
                var = "m." + _sym(syms, S.u16(buf, 5))
                j = 7
            elif end >= 5 and buf[2] == S.SYM:
                var = _sym(syms, S.u16(buf, 3))
                j = 5
            else:
                var = None
            if var is not None and j < end and buf[j] == 0xD2:
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("CATCH WHEN without condition")
                ces, ck = _dec_expr(buf, j + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                    raise Unsupported("CATCH WHEN clause unresolved")
                j = ck + 1
                if j + 4 == end and buf[j] == S.INT16 \
                        and buf[j + 1] == 0x05:
                    return CatchWhen(ces[0], target=S.u16(buf, j + 2),
                                     var=var)
                if j + 6 == end and buf[j] == S.INT32 \
                        and buf[j + 1] == 0x00:
                    return CatchWhen(ces[0],
                                     target=int.from_bytes(
                                         buf[j + 2:j + 6], "little"),
                                     var=var)
                raise Unsupported("CATCH WHEN tail")
        # measured CATCH forms are bare, WHEN, the two TO spellings above, and
        # their combined TO..WHEN form; everything else in this namespace stays
        # explicitly unsupported
        raise Unsupported("unsupported CATCH form (TO / FINALLY-adjacent)")
    if lead == S.FINALLY_LEAD:
        # bc f9 05 <u16>: target = matching ENDTRY prefix - code_base (measured
        # on _reportlistener: FINALLY@1276 -> ENDTRY@1349); e9 00 <u32> is the
        # long-jump width of the same anchor (round-28 W3)
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x05:
            return FinallyClause(S.u16(buf, 3))
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            return FinallyClause(int.from_bytes(buf[3:7], "little"))
        raise Unsupported("FINALLY frame shape")
    if lead == S.ENDTRY_LEAD:
        if end != 1:
            raise Unsupported("ENDTRY trailing bytes")
        return ("ENDTRY",)
    if lead == S.RUN_LEAD:
        # ORACLE round-25 BOUND (r1/r2; corpus alignment
        # txtcollectqichachaclean.scx::frmtxtcollectclean s0 stmts[173]/[176]):
        # 43 fb <len> <command line> — the WHOLE line verbatim as ONE fb string,
        # switches and casing preserved. Bounds: the fb length is attacker-shaped;
        # an overrun must degrade to Unsupported, never slice past end.
        if end < 4 or buf[1] != S.STR:
            raise Unsupported("RUN form unmeasured")
        n = int.from_bytes(buf[2:4], "little")
        if 4 + n != end:
            raise Unsupported("RUN form unmeasured")
        return RunStmt(_payload_text(buf[4:4 + n]))
    if lead == S.ON_BARE_LEAD:
        # Bare/placeholder ON family. Selector map lives ONLY here and is
        # deliberately disjoint from lead 0x31's (test_tail_group pins the
        # non-leakage in both directions). Measured shapes ONLY:
        #   7b 10 fb 00 00 / 7b cd fb 00 00  (ORACLE round-25 o2/o1)
        #   7b be                            (round-13 HARVEST, ON PAGE — no tail)
        #   7b 17 32 fb <u16 label> fb 00 00 (CORPUS round-30: bare ON KEY LABEL;
        #                                     mhxpcontrol.vcx::text s1 stmt[1]
        #                                     'CTRL+C', xfrxlib.vcx::xfcont s80
        #                                     'CTRL+F' — selector 17 + mark 32
        #                                     are the round-20-measured tokens)
        # Empty-handler placeholders re-emit as bare 'ON <name>' / 'ON KEY LABEL
        # <label>'; non-empty handlers ride lead 0x31's grammar per the
        # CMD_SWEEP-era o08 row and stay Unsupported under this lead.
        if end == 5 and buf[1] in (S.ON_SELECTOR_ERROR, S.ON_SELECTOR_SHUTDOWN) \
                and buf[2] == S.STR and buf[3] == 0x00 and buf[4] == 0x00:
            return OnBareStmt("ERROR" if buf[1] == S.ON_SELECTOR_ERROR
                              else "SHUTDOWN")
        if end >= 9 and buf[1] == S.ON_SELECTOR_KEY_LABEL \
                and buf[2] == S.ON_KEY_LABEL_MARK and buf[3] == S.STR:
            n = int.from_bytes(buf[4:6], "little")
            j = 6 + n                       # label bytes end; handler placeholder follows
            if j + 3 != end or buf[j] != S.STR \
                    or buf[j + 1] != 0x00 or buf[j + 2] != 0x00:
                raise Unsupported("ON 0x7b form unmeasured")
            return OnBareStmt("KEY LABEL", label=_payload_text(buf[6:j]))
        if end == 2 and buf[1] == S.ON_PAGE_SELECTOR:
            return OnBareStmt("PAGE")
        raise Unsupported("ON 0x7b form unmeasured")
    if lead == S.ZAP_LEAD:
        # ORACLE round-25 BOUND (c1; corpus cboHierarchy s1 stmt[7]): bare ZAP.
        if end == 1:
            return ("ZAP",)
        # r42-zapin: ZAP IN <alias> = 53 16 f7 <u16>. Alias is symbols[0]
        # (errlist vs other are both f70000; names ride the table). Bare
        # ZAP is 53. Unmeasured tails stay Unsupported.
        # r54-inalias: the alias takes all three spellings of the shared `16`
        # clause — bare symbol, work-area number, or its own fc..fd group with
        # the 03 runtime-paren postfix. `ZAP IN (m.a)` is the corpus shape
        # `53 16 ( ~` that left four gridtree.vcx#41 sections untouched.
        if end >= 3 and buf[1] == S.GO_IN_CLAUSE:
            alias, t = _dec_in_alias(buf, 2, end, syms,
                                     refusal="ZAP trailing bytes")
            if t != end:
                raise Unsupported("ZAP trailing bytes")
            return ("ZAP IN %s" % alias,)
        raise Unsupported("ZAP trailing bytes")
    if lead == S.RECALL_LEAD:
        # ORACLE CMD_SWEEP.md row RECALL (probes/oracle_harvest/CMD_SWEEP.md
        # line 141: authored 'RECALL' -> bare `3a`). CORPUS round-30 followup
        # carries the matching one-byte form: _dialogs.vcx::_keywords s0
        # stmt[32] (`04 00 3a fe`), inside the same method as a bare-`2d`
        # LOCATE. Same admission class as bare ZAP/LOCATE above: end==1 ONLY;
        # any tail stays Unsupported (the NOWAIT clause byte 3a and all other
        # uses live under their own leads and are untouched).
        if end != 1:
            raise Unsupported("RECALL trailing bytes")
        return ("RECALL",)
    if lead == S.INSERT_BLANK_LEAD:
        # r47-insertforms: INSERT BLANK is `28 08`; INSERT BEFORE BLANK
        # appends the BEFORE byte. The lead doubles as the TO mark elsewhere,
        # which is why it is read in statement position only.
        # r54-insertblank: the bank is CLOSED at four frames — the bare verb
        # and `INSERT BEFORE` are the two round 47 did not read — and BLANK's
        # `08` rides in front of BEFORE's `be` whichever order the source
        # spells them. 88 authored spellings were compiled against this lead
        # and no other one produces a frame, so anything else stays refused.
        if end == 1:
            return ("INSERT",)
        if end == 2 and buf[1] == S.INSERT_BEFORE_MARK:
            return ("INSERT BEFORE",)
        if end == 2 and buf[1] == S.INSERT_BLANK_MARK:
            return ("INSERT BLANK",)
        if end == 3 and buf[1] == S.INSERT_BLANK_MARK \
                and buf[2] == S.INSERT_BEFORE_MARK:
            return ("INSERT BEFORE BLANK",)
        raise Unsupported("statement lead 0x28")
    if lead == S.SUSPEND_LEAD and end == 1:
        return ("SUSPEND",)      # r47-suspend; RESUME is 41 and CANCEL is 0b
    if lead == S.APPEND_LEAD:
        if end == 1:
            return ("APPEND",)
        if end == 2 and buf[1] == 0x08:
            return ("APPEND BLANK",)   # BLANK=0x08 clause; aligned dashboard.scx etc.
        if end >= 3 and buf[1] == S.GO_IN_CLAUSE and buf[end - 1] == 0x08:
            # r48-valsweep: `APPEND BLANK IN <alias>` = 06 16 <alias> 08 — the
            # alias rides the IN byte the whole reader shares and BLANK stays
            # last, bare name or parenthesised group alike.
            alias, j = _dec_window_name(buf, 2, end - 1, syms, verb="APPEND IN")
            if j != end - 1:
                raise Unsupported("APPEND IN trailing bytes")
            return ("APPEND BLANK IN %s" % alias,)
        if end >= 3 and buf[1] == 0xD5:
            # round-28 W4: APPEND GENERAL <field> [CLASS <e>] [DATA <e>]
            # ('APPEND GENERAL msgraph DATA lcData' stock cboMonth s0 stmt18;
            # 'APPEND GENERAL GEN1 CLASS "msgraph.chart" DATA m.CGDATA'
            # chart TJTX s0 stmt21). Clause values arrive fc-grouped.
            j = 2
            if j + 3 > end or buf[j] != S.SYM:
                raise Unsupported("APPEND GENERAL field form")
            fld = _sym(syms, S.u16(buf, j + 1))
            j += 3
            cls_e = data_e = None
            for mark in (0x4F, 0xC2):
                if j < end and buf[j] == mark:
                    try:
                        node, k = _fc_group(buf, j + 1, end, syms)
                    except Unsupported:
                        raise Unsupported("APPEND GENERAL clause unresolved")
                    if mark == 0x4F:
                        cls_e = node
                    else:
                        data_e = node
                    j = k
            if j != end:
                raise Unsupported("APPEND GENERAL trailing bytes")
            return AppendGeneralStmt(fld, cls_e, data_e)
        if end >= 3 and buf[1] == 0x1B:
            # round-28 W4: APPEND MEMO <field> FROM <file> [OVERWRITE]
            # (_webview refreshsource s0 stmt21 / _reports.vcx line 743);
            # c5 = OVERWRITE flag.
            j = 2
            if j + 3 > end or buf[j] != S.SYM:
                raise Unsupported("APPEND MEMO field form")
            fld = _sym(syms, S.u16(buf, j + 1))
            j += 3
            if j >= end or buf[j] != S.APPEND_FROM_MARK:
                raise Unsupported("APPEND MEMO FROM missing")
            j += 1
            if j < end and buf[j] in (S.STR, S.STR2):
                fname, j = _dec_str_arg(buf, j, end)
            else:
                try:
                    fname, j = _fc_group(buf, j, end, syms)
                except Unsupported:
                    raise Unsupported("APPEND MEMO file expression unresolved")
            overwrite = False
            if j < end and buf[j] == 0xC5:
                overwrite = True
                j += 1
            if j != end:
                raise Unsupported("APPEND MEMO trailing bytes")
            return AppendMemoStmt(fld, fname, overwrite)
        if end >= 3 and buf[1] == S.APPEND_FROM_MARK:
            # ORACLE round-25 BOUND (c4/c5) + corpus alignment
            # xfrxlib.vcx::cboHierarchy s1 stmts[18]/[23]:
            #   06 15 fc <from-expr> [03] fd [13 fc <FOR> fd] [11 <fields>]
            # Even plain-string FROM args arrive GROUPED (c5 REFUTED the
            # ungrouped guess). Round-28 W4: ungrouped fb/d9 literals ARE
            # measured too (CMD_SWEEP row APPEND 'apf1.txt'; outmat matcalc
            # s1 stmt185 'TmpLHB'), and the measured clause tail
            # [d4] be d1 bf {fb <char> | c4} renders
            # DELIMITED WITH CHARACTER '<c>' | TAB (attendanceforcheck cdget
            # s0 stmt40; d4 = traceless TYPE word).
            j = 2
            delimited = None
            bare_name = False
            if j < end and buf[j] in (S.STR, S.STR2):
                # r47-appendfrom: ungrouped is the unquoted filename spelling
                nm, j = _dec_str_arg(buf, j, end)
                es = [Str(nm)]
                bare_name = True
            elif j < end and buf[j] == S.FC:
                es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(es) != 1:
                    raise Unsupported("APPEND FROM unresolved")
                if k < end and buf[k] == S.PAREN:
                    k += 1                  # runtime-paren marker inside the FROM group
                if k < end and buf[k] == S.FD:
                    k += 1                  # final fd reader-stripped when last clause
                elif k != end:
                    raise Unsupported("APPEND FROM unresolved")
                es = [es[0]]
                j = k
            else:
                raise Unsupported("APPEND FROM unwrapped")
            cond = None
            if j < end and buf[j] == 0x13:      # FOR clause (same marker as LOCATE FOR)
                if j + 1 >= end or buf[j + 1] != S.FC:
                    raise Unsupported("APPEND FOR unwrapped")
                fs, k2 = _dec_expr(buf, j + 2, end, syms, stop_bytes=_IF_COND_STOP)
                if len(fs) != 1:
                    raise Unsupported("APPEND FOR unresolved")
                if k2 < end and buf[k2] == S.FD:
                    k2 += 1
                elif k2 != end:
                    raise Unsupported("APPEND FOR unresolved")
                cond = fs[0]
                j = k2
            fields = []
            if j < end and buf[j] == S.COPY_LEAD:   # 0x11 FIELDS, context-local under 06
                j += 1
                while True:
                    if j + 3 > end or buf[j] != S.SYM:
                        raise Unsupported("APPEND FIELDS unresolved")
                    fields.append(_sym(syms, S.u16(buf, j + 1)))
                    j += 3
                    if j == end:
                        break
                    if buf[j] != S.ARGJOIN:
                        raise Unsupported("APPEND FIELDS separator")
                    j += 1
            type_word = False
            file_type = ""
            if j < end and buf[j] == 0xD4:
                type_word = True         # r47-typeword: the source spelled TYPE
                j += 1
            if j < end and buf[j] in S.FILE_TYPE_WORDS:
                file_type = S.FILE_TYPE_WORDS[buf[j]]
                j += 1
                # only DELIMITED takes a WITH tail: `d1 bf {c4 | <string>}`
                if file_type == "DELIMITED" and j + 1 < end \
                        and buf[j] == 0xD1 and buf[j + 1] == 0xBF:
                    j += 2
                    if j < end and buf[j] == 0xC4:
                        delimited = ("TAB",)
                        j += 1
                    elif j < end and buf[j] in (S.STR, S.STR2):
                        delim_char, j = _dec_str_arg(buf, j, end)
                        delimited = ("CHARACTER", delim_char)
                    else:
                        raise Unsupported(
                            "APPEND trailing bytes (variants unforced)")
            elif type_word:
                raise Unsupported("APPEND TYPE without a file type")
            if j != end:
                raise Unsupported("APPEND trailing bytes (variants unforced)")
            return AppendFromStmt(es[0], cond=cond, fields=fields,
                                  delimited=delimited, bare_name=bare_name,
                                  type_word=type_word, file_type=file_type)
        raise Unsupported("APPEND trailing bytes (variants unforced)")
    if lead == S.NODEFAULT_LEAD:
        if end != 1:
            raise Unsupported("NODEFAULT trailing bytes")
        return NodefaultStmt()
    if lead == S.DO_CASE_LEAD or lead == 0x18:
        # DO <program>: file-literal or parenthesised name-expression; optional
        # d1-introduced WITH-argument list (d1 = compiled WITH, cf. REPLACE).
        # Lead 0x18 = alternate DO spelling for the paren+WITH form
        # (_checkbox cSetObjRefProgram call, iter. 43).
        # Round-28 W4: 14 as second byte = the DO FORM spelling — name literal
        # or fc-group expression ('DO FORM LOCFILE("Pie.scx") WITH This,1',
        # dashboardxx foxcharts1 s0 stmts9..49), optional TO lvalue (shape
        # CmdTexture s0[3]), WITH args admitting bare sym/member paths beside
        # fc-groups. The plain-fc DO arm also admits the runtime-paren marker
        # (03) before its closer ('DO ("system.app")' imgcanvas s19 stmts5/7/9,
        # systray s7 stmts50/62).
        if end >= 2 and buf[1] == 0x14:      # DO FORM
            t = 2
            if t < end and buf[t] in (S.STR, S.STR2):
                prog, t = _dec_str_arg(buf, t, end)
            elif t < end and buf[t] == S.FC:
                try:
                    node, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("DO FORM program expression unresolved")
                prog = _emit(node)
            else:
                raise Unsupported("DO FORM name missing")
            args, to_target, name_target, flags, t = _dec_do_form_clauses(
                buf, t, end, syms)
            if t != end:
                raise Unsupported("DO FORM trailing bytes")
            return DoStmt(prog, args, form=True, to_target=to_target,
                          name_target=name_target, flags=flags)
        prog = None
        t = 1
        if buf[1] in (S.STR, S.STR2):
            nm, j = _dec_str_arg(buf, 1, end)
            prog = nm
            t = j
            # r49-menusweep: `DO <name> WITH <a>[, <b>]` adds `d1 f7 <sym>
            # (07 f7 <sym>)*` to the bare frame — the same bare-symbol WITH
            # list round 32 measured under the symbol-named DO. r68-dotail
            # adds IN (16 <str> or 16 <group>) interned before WITH.
            args, in_target, t = _dec_do_tail(buf, t, end, syms)
            if t != end:
                raise Unsupported("DO trailing bytes")
            return DoStmt(prog, args, in_target=in_target)
        if buf[1] == S.FC:
            es, k = _dec_expr(buf, 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("DO program expression unresolved")
            # round-28 W4: the runtime-paren marker may precede the closer
            # ('DO ("system.app")' imgcanvas s19 stmts5/7/9; systray s7
            # stmts50/62 'DO (m.lcPopup)')
            if k < end and buf[k] == S.PAREN:
                k += 1
            if k < end and buf[k] == S.FD:
                k += 1
            args, in_target, k = _dec_do_tail(buf, k, end, syms)
            if k != end:
                raise Unsupported("DO trailing bytes")
            return DoStmt(es[0], args, in_target=in_target)
        if end >= 2 and buf[1] == S.SYM:
            # DO <program-name-by-symbol>: the payload is a SYMBOL PUSH, not a
            # jump word — ORACLE round-25 BOUND (d1 'DO someloc' -> 18 f7<sym>,
            # d2 local-procedure identical; corpus alignment
            # txtcollectqichachaclean.scx::frmtxtcollectclean s0 stmt[426]
            # 'DO ReduceMemory' = 18 f7 8800 with REDUCEMEMORY that section's
            # last symbol).
            # LOOP(2e)/EXIT(21) are standalone one-byte statements, NOT 18-led
            # (round-25 REFUTED the 18-led hypothesis).
            # Round-32 measured the bare-symbol WITH list; round-33 added
            # fc-groups; r68-arglist is the same list on every 0x18 spelling
            # (MEMBER path, string/number/array/omitted groups, stripped
            # final fd). r68-dotail reads IN (16) interned before WITH.
            # An inner _dec_expr refusal keeps its own class.
            t3 = 4
            eargs, in_target, t3 = _dec_do_tail(buf, t3, end, syms)
            if t3 != end:
                raise Unsupported("unsupported 0x18 frame subtype")
            return DoStmt(_sym(syms, S.u16(buf, 2)), eargs,
                          in_target=in_target)
        # other subtypes: WHILE(2b)/CASE(48) handled above via dedicated branches;
        # anything else is unforced
        raise Unsupported("unsupported 0x18 frame subtype")
    if lead == S.CASE_CLAUSE:
        if buf[1] != S.FC:
            raise Unsupported("CASE condition unwrapped")
        es, k = _dec_expr(buf, 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("CASE clause shape")
        # round-33 long-jump width: past the condition (and its optional fd)
        # the false-jump target lands as e9 00 <u32> with NOTHING behind it
        # (oaremotion1.scx::rtx s14 clauses); any other landing keeps the
        # stock short-width shape below
        kt = k + 1 if k < end and buf[k] == S.FD else k
        if kt + 6 == end and buf[kt] == S.INT32 and buf[kt + 1] == 0x00:
            return CaseClause(es[0], [],
                              int.from_bytes(buf[kt + 2:kt + 6], "little"))
        if k + 5 != end or buf[k] != S.FD \
                or buf[k + 1] != S.INT16 or buf[k + 2] != 0x05:
            raise Unsupported("CASE clause shape")
        return CaseClause(es[0], [], S.u16(buf, k + 3))
    if lead == S.OTHERWISE_LEAD:
        # 32 f9 05 <u16> — target verified against ENDCASE at walk time
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x05:
            return OtherwiseClause(S.u16(buf, 3))
        # round-42 long-jump width of the same slot: 32 e9 00 <u32> with
        # nothing behind it (length exactly 7). listener.vcx methods
        # (fxmemberdatascript s3/s6, utilityreportlistener s1) and oracle
        # s0004/s0006. Anything else keeps the pinned schema id.
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            return OtherwiseClause(int.from_bytes(buf[3:7], "little"))
        raise Unsupported("OTHERWISE frame shape")
    if lead == S.ENDCASE_LEAD:
        if end != 1:
            raise Unsupported("ENDCASE trailing bytes")
        return ("ENDCASE",)
    if lead == S.WAIT_CLEAR:
        # r49-valsweep: a bare WAIT is the one-byte statement `52`. The arm
        # indexed buf[1] unconditionally, so the shortest frame of all raised
        # an IndexError-shaped "malformed statement" instead of lifting.
        if end == 1:
            return ("WAIT",)
        if end == 2 and buf[1] == 0x0C:
            return WaitStmt(None, clear=True)
        # WAIT CLEAR (52 0c) and the WINDOW family (oracle matrix, HARVEST.md):
        #   52 2c [05 fc row fd 07 fc col fd] [d0] [3a] [ce fc n fd] fc <msg>
        # Bytecode clause order is AT -> NOCLEAR -> NOWAIT -> TIMEOUT -> msg.
        # The compiler CANONICALISES it: the order the author wrote is destroyed and
        # is not recoverable from any wire byte. Measured twice (round 41 lane R41-D,
        # probes/oracle_harvest/round41_waitwin_batch.py, tests/test_round41_waitwin.py):
        #   * ten permutation pairs compiled side by side on VFP9 -- e.g.
        #     'WAIT WINDOW ''hello'' TIMEOUT 2 NOCLEAR AT 10,20 NOWAIT' and
        #     'WAIT WINDOW AT 10,20 NOCLEAR NOWAIT TIMEOUT 2 ''hello''' BOTH give
        #     522c05fcf8020afd07fcf80214fdd03acefcf80102fdfcfb050068656c6c6f;
        #   * 5,204 corpus WAIT WINDOW statements, zero deviations from that order,
        #     against stored sources that disagree about it (dashboard2.scx::frmcontrol
        #     s12 spells 'WAIT windows nowait NOCLEAR ...' and compiles to 52 2c d0 3a).
        # So emission renders WIRE order, and any fixed source order is equally exact:
        # 29/29 carrier WAIT frames recompile byte-identically from the text below.
        # The order emitted is msg NOCLEAR NOWAIT AT TIMEOUT, which is also the one the
        # corpus most often spells. Unmeasured modifiers stay Unsupported.
        if buf[1] == 0xFC:
            es, k = _dec_expr(buf, 2, end, syms)
            if len(es) != 1 or k != end:
                raise Unsupported("WAIT expression unresolved")
            return WaitStmt(es[0], bare_wait=True)
        if buf[1] == 0xCE:
            if end < 4 or buf[2] != S.FC:
                raise Unsupported("WAIT TIMEOUT unwrapped")
            # Optional trailing message group AFTER the timeout group: wire order
            # is timeout-first (HARVEST round-15 n05/n06 measured ce=TIMEOUT with
            # the msg group last), and corpus carrier autolutec.scx::Timer1
            # stmt322 '52 ce fc f80103 fd fc fb0000' <-> stored L355
            # "WAIT '' TIMEOUT 3" pins the bare-WAIT spelling and the canonical
            # source order msg-then-TIMEOUT. Without a message group the timeout
            # expression runs to end-of-statement ('WAIT TIMEOUT 1' =
            # 52 ce fc f80101, unchanged). A timeout group that does not close
            # on fd, or any bytes left after the message group, stays rejected.
            ts, tk = _dec_expr(buf, 3, end, syms,
                               stop_bytes=frozenset({S.FD}))
            if len(ts) != 1:
                raise Unsupported("WAIT TIMEOUT unresolved")
            if tk == end:
                return WaitStmt(None, bare_wait=True, timeout=ts[0])
            if tk + 1 >= end or buf[tk] != S.FD or buf[tk + 1] != S.FC:
                raise Unsupported("WAIT TIMEOUT unresolved")
            mes, mk = _dec_expr(buf, tk + 2, end, syms)
            if len(mes) != 1 or mk != end:
                raise Unsupported("WAIT message unresolved")
            return WaitStmt(mes[0], bare_wait=True, timeout=ts[0])
        if buf[1] != 0x2C:
            raise Unsupported("WAIT WINDOW unwrapped")
        j = 2
        at_clause = None
        noclear = nowait = False
        timeout = None
        while j < end and buf[j] != S.FC:
            op = buf[j]
            if op == 0x05:                       # AT row, col (joined by 07)
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("WAIT AT row unwrapped")
                rs, rk = _dec_expr(buf, j + 1, end, syms,
                                   stop_bytes=frozenset({S.FD}))
                if len(rs) != 1 or rk >= end or buf[rk] != S.FD:
                    raise Unsupported("WAIT AT row unresolved")
                j = rk + 1
                if j >= end or buf[j] != S.ARGJOIN:
                    raise Unsupported("WAIT AT joiner missing")
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("WAIT AT col unwrapped")
                cs, ck = _dec_expr(buf, j + 1, end, syms,
                                   stop_bytes=frozenset({S.FD}))
                if len(cs) != 1 or ck >= end or buf[ck] != S.FD:
                    raise Unsupported("WAIT AT col unresolved")
                at_clause = (rs[0], cs[0])
                j = ck + 1
            elif op == 0xD0:                     # NOCLEAR
                noclear = True
                j += 1
            elif op == 0x3A:                     # NOWAIT
                nowait = True
                j += 1
            elif op == 0xCE:                     # TIMEOUT <expr>
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("WAIT TIMEOUT unwrapped")
                ts, tk = _dec_expr(buf, j + 1, end, syms,
                                   stop_bytes=frozenset({S.FD}))
                if len(ts) != 1 or tk >= end or buf[tk] != S.FD:
                    raise Unsupported("WAIT TIMEOUT unresolved")
                timeout = ts[0]
                j = tk + 1
            else:
                raise Unsupported(
                    "WAIT modifier 0x%02X unmeasured" % op)
        if j >= end or buf[j] != S.FC:
            raise Unsupported("WAIT message missing")
        mes, mk = _dec_expr(buf, j + 1, end, syms)
        if len(mes) != 1 or mk != end:
            raise Unsupported("WAIT message unresolved")
        return WaitStmt(mes[0], at=at_clause, timeout=timeout,
                        noclear=noclear, nowait=nowait)
    if lead == S.SQL_SELECT_LEAD:
        # grammar (forced subset): 6f 15 <FROM-str> c7 [c6 fc <where> fd]
        #   c3 fc <order> fd [3c] bc bd <cursor-str> [d7]
        # d7 = the measured READWRITE tag (r37 C12/sw9); emitted exactly once
        # by _emit_line via the readwrite flag. Column units ride '51 f7 <u16>'
        # alias refs (four bytes, C11) separated by 07; bare-c6 WHERE groups
        # are preserved wherever the compiler puts them relative to INTO.
        # HAVING stays unforced. GROUP BY is r42-selgroup (`bf`).
        j = 1
        if buf[j] == S.SQL_UNION_SUBLEAD:
            # r74-union: UNION ALL is `c4 03 e8 <u24>`; plain UNION is
            # `c4 e8 <u24>`. The 03 is ALL. The u24 is not the round-37
            # sum of table-name lengths (cursor excluded or included);
            # it is consumed and the arms are walked by grammar. Arms
            # are stored in reverse source order. A nested `c4` header
            # after an arm is another UNION of the remaining arms.
            arms = []
            all_flag = True
            while True:
                if j < end and buf[j] == S.SQL_UNION_SUBLEAD:
                    j += 1
                    all_flag = False
                    if j < end and buf[j] == S.SQL_UNION_ALL_MARK:
                        all_flag = True
                        j += 1
                    if j >= end or buf[j] != S.SQL_UNION_LEN_MARK:
                        raise Unsupported("SQL SELECT header mismatch")
                    j += 1
                    if j + 3 > end:
                        raise Unsupported("SQL SELECT header mismatch")
                    j += 3
                elif not arms:
                    raise Unsupported("SQL SELECT header mismatch")
                distinct = False
                if j < end and buf[j] == S.SQL_DISTINCT_MARK:
                    distinct = True
                    j += 1
                if j >= end or buf[j] != 0x15:
                    raise Unsupported("SQL SELECT header mismatch")
                j += 1
                if j < end and buf[j] == S.FC:
                    tes, tk = _dec_expr(buf, j + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(tes) != 1 or tk >= end or buf[tk] != S.FD:
                        raise Unsupported("SQL FROM table unresolved")
                    tbl_a = tes[0].text if isinstance(tes[0], Str) \
                        else _emit(tes[0])
                    j = tk + 1
                else:
                    tbl_a, j = _dec_str_arg(buf, j, end)
                if j + 3 <= end and buf[j] == S.SQLSEL_FROM_ALIAS \
                        and buf[j + 1] == S.SYM:
                    tbl_a = tbl_a + " " + _sym(syms, S.u16(buf, j + 2))
                    j += 4
                arm_cols = []
                while j < end and buf[j] == S.FC:
                    ces, ck = _dec_expr(buf, j + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                        raise Unsupported("SQL SELECT column unresolved")
                    ck += 1
                    alias = None
                    if ck + 4 <= end and buf[ck] == 0x51 \
                            and buf[ck + 1] == S.SYM:
                        alias = _sym(syms, S.u16(buf, ck + 2))
                        ck += 4
                    arm_cols.append((ces[0], alias))
                    if ck < end and buf[ck] == 0x07:
                        j = ck + 1
                        continue
                    j = ck
                    break
                if not arm_cols and j < end and buf[j] == 0xC7:
                    nxt = buf[j + 1] if j + 1 < end else None
                    if nxt != 0xC6:
                        j += 1
                arms.append((all_flag, distinct, tbl_a, arm_cols))
                if j < end and buf[j] == 0xC7 and j + 1 < end \
                        and buf[j + 1] in (0x15, S.SQL_DISTINCT_MARK,
                                           S.SQL_UNION_SUBLEAD):
                    j += 1
                    continue
                if j < end and buf[j] in (0x15, S.SQL_DISTINCT_MARK,
                                          S.SQL_UNION_SUBLEAD):
                    continue
                break
            where_expr = None
            if j < end and buf[j] == 0xC7:
                j += 1
                if j < end and buf[j] == 0xC6:
                    j += 1
                    wes, wk = _dec_sql_cond(buf, j, end, syms)
                    if len(wes) != 1 or wk >= end or buf[wk] != S.FD:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    j = wk + 1
                elif j < end and buf[j] == S.C3_ORDER:
                    pass
                else:
                    raise Unsupported("SQL WHERE unwrapped")
            order_expr = None
            desc = False
            if j < end and buf[j] == S.C3_ORDER:
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("SQL ORDER unwrapped")
                oes, ok = _dec_expr(buf, j + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(oes) != 1 or ok >= end or buf[ok] != S.FD:
                    raise Unsupported("SQL ORDER unresolved")
                order_expr = oes[0]
                j = ok + 1
                if j < end and buf[j] == S.SQLSEL_DESC_MARK:
                    desc = True
                    j += 1
            cur = None
            for scan in range(j, end - 1):
                if buf[scan:scan + 2] == bytes(S.SQLSEL_INTOCURSOR_MARK):
                    cur, j = _dec_str_arg(buf, scan + 2, end)
                    break
            if cur is None and j != end:
                raise Unsupported("SQL INTO CURSOR section missing")
            readwrite = False
            if j < end:
                if buf[j] == 0xD7 and j + 1 == end:
                    readwrite = True
                else:
                    raise Unsupported("SQL SELECT trailing bytes")
            # r74-union: two-arm reverse is last-then-first; three-arm nested
            # is last then the others in wire order, which restores source
            # order (A ∪ B ∪ C from wire B, C, A). The ALL flag on each
            # arm is the header that introduced it.
            ordered = [arms[-1]] + list(arms[:-1])
            segs = []
            ops = []
            for all_flag, distinct, tbl_a, arm_cols in ordered:
                seg = "SELECT "
                if distinct:
                    seg += "DISTINCT "
                if arm_cols:
                    seg += ", ".join(_emit(e) + (" AS %s" % a if a else "")
                                     for e, a in arm_cols)
                else:
                    seg += "*"
                seg += " FROM " + tbl_a
                if segs:
                    ops.append(" UNION ALL " if all_flag else " UNION ")
                segs.append(seg)
            text = segs[0]
            for op, seg in zip(ops, segs[1:]):
                text += op + seg
            if where_expr is not None:
                text += " WHERE " + _emit(where_expr)
            if order_expr is not None:
                text += " ORDER BY " + _emit(order_expr) + (" DESC" if desc else "")
            if cur is not None:
                text += " INTO CURSOR " + cur
            return SqlSelectColumns(text, readwrite=readwrite)
        distinct = False
        if buf[j] == S.SQL_DISTINCT_MARK:
            # r42-seldistinct: SELECT DISTINCT is 6f be 15 … [bc bd INTO].
            # Bare SELECT is 6f 15. No-INTO DISTINCT is 6f be 15 … (no bc bd).
            # The old no-INTO prefix is this same 0xBE mark.
            distinct = True
            j += 1
        no_cursor = distinct
        if buf[j] != 0x15:
            raise Unsupported("SQL SELECT header mismatch")
        j += 1
        if j < end and buf[j] == S.FC:
            # FROM table as an fc-wrapped expression (chartadjust.scx::Command3:
            # 'SELECT * FROM (m.loChart._datacursor) INTO CURSOR MainCursor' ->
            # 6f 15 fc f5 0d f4.. f7.. 03 fd ...). The member form f5 0d f4 X
            # f7 Y 03 does not resolve through the generic expression decoder,
            # so it is folded here, locally to this statement grammar. String
            # tables keep the raw unquoted spelling used everywhere else.
            if j + 12 <= end and buf[j + 1] == S.WORKAREA_REF \
                    and buf[j + 2] == 0x0D and buf[j + 3] == S.MEMBER:
                names = ["m." + _sym(syms, S.u16(buf, j + 4))]
                p = j + 6
                while p + 3 <= end and buf[p] == S.MEMBER:
                    names.append(_sym(syms, S.u16(buf, p + 1)))
                    p += 3
                if p + 3 <= end and buf[p] == S.SYM:
                    names.append(_sym(syms, S.u16(buf, p + 1)))
                    p += 3
                    if p >= end or buf[p] != 0x03:
                        raise Unsupported("SQL FROM table unresolved")
                    tbl = "(%s)" % ".".join(names)
                    j = p + 1
                else:
                    raise Unsupported("SQL FROM table unresolved")
            else:
                tes, tk = _dec_expr(buf, j + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(tes) != 1 or tk >= end or buf[tk] != S.FD:
                    raise Unsupported("SQL FROM table unresolved")
                tbl = tes[0].text if isinstance(tes[0], Str) else _emit(tes[0])
                j = tk + 1
        else:
            tbl, j = _dec_str_arg(buf, j, end)
        # optional FROM alias: 51 f7 <u16> (r42-tiera3). Same 51 as column AS.
        if j + 3 <= end and buf[j] == S.SQLSEL_FROM_ALIAS and buf[j + 1] == S.SYM:
            tbl = tbl + " " + _sym(syms, S.u16(buf, j + 2))
            j += 4
        # JOIN: <kind> d2 fb <table> [51 f7 alias] 20 fc <on> fd
        # r74-join: nested JOIN JOIN ON ON stores every JOIN table first
        # and the ON conditions after the chain; a flat chain stores each
        # ON behind its JOIN. INNER/bare JOIN are d4, LEFT 58, RIGHT 59,
        # FULL d3. OUTER is not on the wire.
        _JOIN_KW = {
            S.SQLSEL_JOIN_INNER: "INNER JOIN",
            S.SQLSEL_JOIN_LEFT: "LEFT JOIN",
            S.SQLSEL_JOIN_RIGHT: "RIGHT JOIN",
            S.SQLSEL_JOIN_FULL: "FULL JOIN",
        }
        join_specs = []
        on_exprs = []
        saw_on = False
        interleaved = False
        while True:
            if j + 1 < end and buf[j + 1] == S.SQLSEL_JOIN_MARK \
                    and buf[j] in _JOIN_KW:
                if saw_on:
                    interleaved = True
                kw = _JOIN_KW[buf[j]]
                j += 2
                jtbl, j = _dec_str_arg(buf, j, end)
                if j + 3 <= end and buf[j] == S.SQLSEL_FROM_ALIAS \
                        and buf[j + 1] == S.SYM:
                    jtbl = jtbl + " " + _sym(syms, S.u16(buf, j + 2))
                    j += 4
                join_specs.append((kw, jtbl))
                continue
            if j < end and buf[j] == S.SQLSEL_JOIN_ON:
                saw_on = True
                j += 1
                if j >= end or buf[j] != S.FC:
                    raise Unsupported("SQL JOIN ON unwrapped")
                oes, ok = _dec_expr(buf, j + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(oes) != 1 or ok >= end or buf[ok] != S.FD:
                    raise Unsupported("SQL JOIN ON unresolved")
                j = ok + 1
                on_exprs.append(oes[0])
                continue
            break
        if join_specs and len(on_exprs) != len(join_specs):
            raise Unsupported("SQL JOIN ON missing")
        if interleaved:
            for (kw, jtbl), on in zip(join_specs, on_exprs):
                tbl = "%s %s %s ON %s" % (tbl, kw, jtbl, _emit(on))
        else:
            for kw, jtbl in join_specs:
                tbl = "%s %s %s" % (tbl, kw, jtbl)
            for on in on_exprs:
                tbl = "%s ON %s" % (tbl, _emit(on))
        # UNIFIED SQL SELECT grammar: 6f 15 <FROM-str> [columns] [c7 [c6 where]]
        #   [bf group] [c3 order] [29 top] bc bd <cursor-str> [d7]. Columns are
        #   fc-wrapped expressions optionally aliased via 51; both star-form
        #   (no columns) and column-list forms may carry WHERE/GROUP/ORDER.
        cols = []
        star_extra = False
        star_leading = False
        t2 = j
        if t2 + 1 < end and buf[t2] == 0xC7 and buf[t2 + 1] == S.ARGJOIN:
            # r48-sqlproj: `SELECT *, <col> …` stores the star as c7 and the
            # rest of the projection behind an 07 separator. The same c7 opens
            # the optional WHERE, so the two are told apart by what follows:
            # `c7 07` is more columns, `c7 c6` is the WHERE. Without this arm
            # the walk found no fc at t2, took none of the columns, and the
            # INTO scanner skipped every clause behind them.
            star_leading = True
            t2 += 2
        while t2 < end and buf[t2] == S.FC:
            agg = _try_sql_agg(buf, t2 + 1, end, syms)
            if agg is not None:
                node, k = agg
                es = [node]
            else:
                try:
                    with _sql_agg_scope():
                        es, k = _dec_expr(buf, t2 + 1, end, syms,
                                          stop_bytes=_IF_COND_STOP)
                except Unsupported:
                    break
            if len(es) != 1:
                raise Unsupported("SQL SELECT column unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            elif _clause_group_close(buf, k, end) == end:
                # r42-seldistinct no-INTO: 6f be 15 … fc <col> with the
                # statement-final fd reader-stripped. r54-selnointo: every
                # destination-less SELECT closes its last column the same way,
                # and so does a SELECT spliced into an INSERT.
                cols.append((es[0], None))
                t2 = k
                break
            else:
                raise Unsupported("SQL SELECT column unresolved")
            alias = None
            if k + 4 <= end and buf[k] == 0x51 and buf[k + 1] == S.SYM:
                # r37 P3 (C11): alias unit = marker 51 + f7 <u16>, FOUR bytes;
                # the stock three-byte consumption stranded the index's high
                # byte, so the column walk halted right after the first
                # aliased column (the measured 169-key truncation class) and
                # the stray byte masked a following bare-c6 WHERE. Column
                # units between aliased columns ride the 07 separator handled
                # below (sa3).
                alias = _sym(syms, S.u16(buf, k + 2))
                k += 4
            elif k + 3 <= end and buf[k] == 0x51 and buf[k + 1] in (S.STR, S.STR2):
                # r48-sqlproj: a QUOTED alias is a string, not a symbol —
                # `AS "z"` is `51 d9 <len> z`. The symbol-only reader stopped
                # the walk there and the INTO scanner skipped the rest.
                n = S.u16(buf, k + 2)
                alias = _emit(Str(_payload_text(buf[k + 4:k + 4 + n]),
                                  dq=buf[k + 1] == S.STR2))
                k += 4 + n
            cols.append((es[0], alias))
            if k + 1 < end and buf[k] == S.ARGJOIN and buf[k + 1] == 0xC7:
                # r37 P3 follow-up (review F1): '07 c7' directly after a
                # column unit is the additional ', *' projection riding
                # before the WHERE opener — NOT the optional-c7 WHERE
                # joiner (which never follows a 07 separator; sw9 rides a
                # bare c7 with no column units at all). Bound to this exact
                # measured placement: the whole population carries it in
                # exactly four 6f-statements, each immediately before c6.
                star_extra = True
                t2 = k + 2
                break
            if k < end and buf[k] == 0x07:
                t2 = k + 1
                continue
            t2 = k
            break
        # after columns: optional WHERE (c7+c6; c7 PROVEN OPTIONAL round-34),
        # GROUP BY (bf, r42-selgroup), ORDER BY (c3), then INTO CURSOR / INTO ARRAY
        where_expr = None
        order_terms = []
        desc = False
        readwrite = False
        nofilter = False
        pos = t2
        # r49-clauseorder: the symbols this clause introduces, against which the
        # INTO clause's own table entry says which of the two the source wrote
        # first
        where_tap = _sym_tap()
        if pos < end and buf[pos] == 0xC7:
            pos += 1
            if pos < end and buf[pos] == 0xC6:
                pos += 1
                if buf[pos] != S.FC:
                    raise Unsupported("SQL WHERE unwrapped")
                # round-34 lane A: the measured LIKE matrix takes priority;
                # a non-matching condition falls through to the generic
                # expression decoder exactly as before (messages preserved).
                try:
                    with where_tap:
                        wnode, wk = _dec_sql_like_cond(buf, pos + 1, end, syms)
                    where_expr = wnode
                    pos = wk
                except Unsupported:
                    with where_tap:
                        wes, wk = _dec_expr(buf, pos + 1, end, syms,
                                            stop_bytes=_IF_COND_STOP)
                    wk = _clause_group_close(buf, wk, end)
                    if len(wes) != 1 or wk is None:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    pos = wk
            elif pos < end and buf[pos] == S.C3_ORDER:
                pass  # no WHERE, go to ORDER
        elif pos < end and buf[pos] == 0xC6 and pos + 1 < end \
                and buf[pos + 1] == S.FC:
            # round-34 lane A: the c7 opener joiner is OPTIONAL — extwindow s0
            # stmt3 opens its WHERE with bare `c6 fc` while text s6 stmt10
            # spells `c7 c6 fc` (minimal pair). The bare spelling enters WHERE
            # decoding ONLY under the measured LIKE matrix above; a non-match
            # leaves this branch inert so every previously-decoded stream keeps
            # its byte-for-byte behavior (and its exact blocking message).
            try:
                with where_tap:
                    wnode, wk = _dec_sql_like_cond(buf, pos + 2, end, syms)
                where_expr = wnode
                pos = wk
            except Unsupported:
                # r37 P3 (C12): the bare-c6 WHERE group is emitted WHERE THE
                # SOURCE PUTS IT — including after the INTO CURSOR tokens in
                # source (carrier 108ef3cf; the compiler normalizes it to this
                # pre-INTO wire position). Behind the measured LIKE matrix,
                # decode it with the SAME generic expression decoder the
                # c7-c6 branch uses. A non-matching condition stays INERT so
                # every previously-blocked stream keeps its exact message.
                try:
                    with where_tap:
                        wes, wk = _dec_expr(buf, pos + 2, end, syms,
                                            stop_bytes=_IF_COND_STOP)
                    wk = _clause_group_close(buf, wk, end)
                    if len(wes) != 1 or wk is None:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    pos = wk
                except Unsupported:
                    pass
        # r42-selgroup: GROUP BY is bf fc <n> fd [07 fc <n> fd]* after WHERE
        # and before ORDER BY. The INTO scanner used to skip bf and drop it.
        group_terms = []
        if pos < end and buf[pos] == S.SQLSEL_GROUP_MARK:
            pos += 1
            if pos >= end or buf[pos] != S.FC:
                raise Unsupported("SQL GROUP BY unwrapped")
            ges, gk = _dec_expr(buf, pos + 1, end, syms,
                                stop_bytes=_IF_COND_STOP)
            gk = _clause_group_close(buf, gk, end)
            if len(ges) != 1 or gk is None:
                raise Unsupported("SQL GROUP BY unresolved")
            pos = gk
            group_terms.append(ges[0])
            while pos + 1 < end and buf[pos] == S.ARGJOIN \
                    and buf[pos + 1] == S.FC:
                try:
                    mes, mk = _dec_expr(buf, pos + 2, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                except Unsupported:
                    break
                if len(mes) != 1 or mk >= end or buf[mk] != S.FD:
                    break
                pos = mk + 1
                group_terms.append(mes[0])
        # r47-having: HAVING is `c0 fc <cond> fd`, between GROUP BY and ORDER
        # BY. With no c0 arm the INTO scanner skipped the group AND every
        # clause behind it, so the statement lifted without its HAVING and
        # without its ORDER BY.
        having_expr = None
        if pos < end and buf[pos] == S.SQLSEL_HAVING_MARK:
            if pos + 1 >= end or buf[pos + 1] != S.FC:
                raise Unsupported("SQL HAVING unwrapped")
            hes, hk = _dec_sql_cond(buf, pos + 2, end, syms)
            hk = _clause_group_close(buf, hk, end)
            if len(hes) != 1 or hk is None:
                raise Unsupported("SQL HAVING unresolved")
            having_expr = hes[0]
            pos = hk
        # ORDER BY section. r37 sql-closure: a comma-separated term list rides
        # 'c3 fc <term> fd [3c] (07 fc <term> fd [3c])*' — measured fresh
        # (oracle s0101-s0105) and on the 'ORDER BY 1 desc,2' carriers
        # testrecord/attendancereadrecord s16; per-term DESC flag 3c. A
        # non-parsing continuation keeps the stock inert skip-behavior so no
        # statement flips lifted->blocked.
        order_terms = []
        if pos < end and buf[pos] == S.C3_ORDER:
            pos += 1
            if buf[pos] != S.FC:
                raise Unsupported("SQL ORDER unwrapped")
            oes, ok = _dec_expr(buf, pos + 1, end, syms, stop_bytes=_IF_COND_STOP)
            ok = _clause_group_close(buf, ok, end)
            if len(oes) != 1 or ok is None:
                raise Unsupported("SQL ORDER unresolved")
            pos = ok
            tdesc = False
            if pos < end and buf[pos] == S.SQLSEL_DESC_MARK:
                tdesc = True
                pos += 1
            order_terms.append((oes[0], tdesc))
            while pos + 1 < end and buf[pos] == S.ARGJOIN \
                    and buf[pos + 1] == S.FC:
                try:
                    mes, mk = _dec_expr(buf, pos + 2, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                except Unsupported:
                    break
                if len(mes) != 1 or mk >= end or buf[mk] != S.FD:
                    break
                pos = mk + 1
                mdesc = False
                if pos < end and buf[pos] == S.SQLSEL_DESC_MARK:
                    mdesc = True
                    pos += 1
                order_terms.append((mes[0], mdesc))
        else:
            order_terms = []
        # DESC flag
        if pos < end and buf[pos] == S.SQLSEL_DESC_MARK:
            desc = True
            pos += 1
        # r42-seltop: SELECT TOP n is 29 fc <n> [fd] immediately before INTO.
        # The INTO scanner used to skip this clause and drop TOP.
        top_n = None
        if pos < end and buf[pos] == S.SQLSEL_TOP_MARK:
            pos += 1
            if pos >= end or buf[pos] != S.FC:
                raise Unsupported("SQL TOP unwrapped")
            tes, tk = _dec_expr(buf, pos + 1, end, syms,
                                stop_bytes=_IF_COND_STOP)
            if len(tes) != 1:
                raise Unsupported("SQL TOP unresolved")
            pos = tk
            if pos < end and buf[pos] == S.FD:
                pos += 1
            top_n = tes[0]
        # INTO CURSOR / INTO TABLE marker + name; scan forward past unknown
        # clauses if needed. round-26: INTO TABLE = bc 31 beside bc bd; the
        # name operand may be an fb/d9 string OR a grouped expression
        # (fc <expr-with-03>, final fd reader-stripped).
        # round-34 lane A: `bc 04 f7 <u16 sym>` = INTO ARRAY <sym> (same two
        # carriers). round-40 lane F: the tail is independent of the WHERE
        # form. Oracle a01-a06 emit the identical five bytes with no WHERE,
        # with a plain `==` WHERE, with an aggregate projection, with an
        # ORDER BY and on a star projection; the corpus agrees on five
        # further carriers whose stored
        # source spells `into array` (frmopr.SCX::FRMOPR L36/L39/L94,
        # aatest.scx::frstestharn L169/L380).
        # The tail must occupy the FINAL five bytes AND abut the clause region
        # this parser actually consumed. The abut test is what keeps a projection
        # the column walk could not read from being silently re-rendered as '*':
        # aatest's 'SELECT MAX(id) FROM aascripts INTO ARRAY aTestId' leaves its
        # aggregate column group unconsumed, so it keeps its existing
        # INTO-CURSOR-missing rejection instead of lifting without the column.
        into_txt = None
        cur = None
        # r49-clauseorder: only a LITERAL cursor/table name has a symbol-table
        # entry of its own to be found by name; a name expression's symbols are
        # ordinary operands and an INTO ARRAY target has no measured carrier
        cur_literal = None
        for scan in range(pos, end - 1):
            pair = buf[scan:scan + 2]
            if scan == pos and pair == bytes(S.SQL_INTOARRAY_MARK) \
                    and scan + 5 == end and buf[scan + 2] == S.SYM:
                arr_sym = _sym(syms, S.u16(buf, scan + 3))
                pos = scan + 5
                into_txt = " INTO ARRAY " + arr_sym
                break
            if pair == bytes(S.SQLSEL_INTOCURSOR_MARK) \
                    or pair == bytes(S.SQL_INTOTABLE_MARK):
                into_word = "CURSOR" if pair == bytes(S.SQLSEL_INTOCURSOR_MARK) \
                    else "TABLE"
                k = scan + 2
                if k < end and buf[k] in (S.STR, S.STR2):
                    cur, k = _dec_str_arg(buf, k, end)
                    cur_literal = cur
                elif k < end and buf[k] == S.FC:
                    es, k = _dec_expr(buf, k + 1, end, syms,
                                      stop_bytes=_IF_COND_STOP)
                    if len(es) != 1:
                        raise Unsupported("SQL INTO section unresolved")
                    if k < end and buf[k] == S.FD:
                        k += 1
                    cur = _emit(es[0])
                else:
                    raise Unsupported("SQL INTO CURSOR section missing")
                pos = k
                into_txt = f" INTO {into_word} {cur}"
                break
        # r54-selnointo: a SELECT with no destination is a legal statement that
        # simply ENDS where its `bc bd` INTO clause would begin — it opens a
        # browse window instead of keeping a cursor. Nothing on the wire marks
        # the absence, so the only safe admission is the round-40 abut test:
        # the clause walk must have consumed EVERY byte in front of the tail.
        # A projection the column walk could not read leaves bytes behind and
        # keeps its refusal rather than re-rendering as `*`.
        tail = S.SQLSEL_TAILS.get(tuple(buf[pos:end]))
        if into_txt is None:
            # r54-selnointo: with NOTHING behind it the last clause group's
            # closer is stripped in every measured row, so a group that closed
            # on its own `fd` and then ended is a shape this compiler does not
            # write and keeps its refusal. Behind a display tail the group does
            # close, which is the same rule read the other way — and so does
            # every group of an `e8` subquery body, whose own length ends it.
            closed_at_end = (pos > 0 and not tail and buf[pos - 1] == S.FD
                             and not _SQL_SUBQUERY_BODY)
            if distinct or (tail is not None and not closed_at_end):
                into_txt = ""
            else:
                raise Unsupported("SQL INTO CURSOR section missing")
        if tail is None:
            raise Unsupported("SQL SELECT trailing bytes")
        readwrite = "READWRITE" in tail
        nofilter = "NOFILTER" in tail
        display = tuple(w for w in tail
                        if w not in ("READWRITE", "NOFILTER"))
        # build result
        sel_kw = ["SELECT"]
        if distinct:
            sel_kw.append("DISTINCT")
        if top_n is not None:
            sel_kw.append("TOP %s" % _emit(top_n))
        top_txt = " ".join(sel_kw) + " "
        if cols:
            parts = [_emit(e) + (f" AS {a}" if a else "") for e, a in cols]
            # review F1: a mixed projection renders its additional star too;
            # r48-sqlproj: a LEADING star renders before the column list
            if star_leading:
                parts.insert(0, "*")
            head = top_txt + ", ".join(parts) \
                + (", *" if star_extra else "") + f" FROM {tbl}"
        else:
            # star-form: no explicit columns means SELECT * FROM ...
            head = top_txt + ("* FROM %s" % tbl)
        rest = ""
        if where_expr is not None:
            rest += " WHERE " + _emit(where_expr)
        if group_terms:
            rest += " GROUP BY " + ", ".join(_emit(t) for t in group_terms)
        if having_expr is not None:
            rest += " HAVING " + _emit(having_expr)
        if order_terms:
            rest += " ORDER BY " + ", ".join(
                _emit(t) + (" DESC" if d else "") for t, d in order_terms)
        # r49-clauseorder: the compiler stores the INTO clause behind the WHERE
        # whichever order the source wrote them in, and the cursor name is a
        # symbol-table entry even though the frame spells it as a string — so
        # the table says which came first. Measured for a WHERE alone; a
        # GROUP BY / HAVING / ORDER BY in the same statement gives the clause a
        # third possible position and none of those orders is measured.
        into_first = (
            where_expr is not None and not group_terms and not order_terms
            and having_expr is None
            and _written_first(_table_new_index(syms, cur_literal),
                               where_tap.first_new()))
        # r37 P3 (C13): the d7 tag is emitted ONCE, by _emit_line via the
        # readwrite flag — appending it here too doubled the tag on the
        # wire-visible text ('READWRITE READWRITE', rejected by VFP). The tag
        # belongs to the INTO clause, so what the source wrote after that
        # clause travels in tail_text and the emitter still places the tag.
        if into_first:
            return SqlSelectColumns(head + into_txt, readwrite=readwrite,
                                    nofilter=nofilter, tail_text=rest,
                                    display=display)
        return SqlSelectColumns(head + rest + into_txt, readwrite=readwrite,
                                nofilter=nofilter, display=display)
        j += 1
        where = None
        if buf[j] == 0xC6:
            j += 1
            if buf[j] != S.FC:
                raise Unsupported("SQL WHERE unwrapped")
            wes, wk = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(wes) != 1 or wk >= end or buf[wk] != S.FD:
                raise Unsupported("SQL WHERE unresolved")
            where = wes[0]
            j = wk + 1
        order_present = buf[j] == S.C3_ORDER
        if not order_present and buf[j:j+2] != bytes(S.SQLSEL_INTOCURSOR_MARK):
            raise Unsupported("SQL SELECT ORDER section unforced")
        es = None
        k = j
        if order_present:
            j += 1
            if buf[j] != S.FC:
                raise Unsupported("SQL SELECT ORDER unwrapped")
            es, k = _dec_expr(buf, j + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("SQL SELECT ORDER unresolved")
            k += 1
        desc = False
        if order_present and k < end and buf[k] == S.SQLSEL_DESC_MARK:
            desc = True
            k += 1
        if no_cursor and k >= end:
            tbl_txt = tbl if isinstance(tbl, str) else str(tbl)
            col_txt = ", ".join(_emit(e) for e in es)
            return SqlSelectColumns("SELECT %s FROM %s" % (col_txt, tbl_txt),
                                    readwrite=False)
        if buf[k:k+2] != bytes(S.SQLSEL_INTOCURSOR_MARK):
            raise Unsupported("SQL SELECT INTO-CURSOR section unforced")
        cur, k2 = _dec_str_arg(buf, k + 2, end)
        readwrite = False
        if k2 < end:
            if buf[k2] == 0xD7 and k2 + 1 == end:
                readwrite = True      # trailing flag: aligned READWRITE 13/13 methods
                k2 += 1
            else:
                raise Unsupported("SQL SELECT trailing bytes")
        order_expr = es[0] if order_present else None
        return SqlSelectIntoCursor(tbl, order_expr, desc, cur, where=where,
                                   readwrite=readwrite)
    if lead == S.SET_LEAD:
        # FORCED subsets (Guineu SetToken ids + corpus alignments):
        #   DATASESSION TO (<expr>) : 47 80 28 fc <expr> fd
        #   <name> ON | OFF         : 47 <id> 20 | 1f     (names: SET_ONOFF_NAMES)
        #   FILTER TO / PROCEDURE TO: 47 1a 28 / 47 2b 28  (bare TO, corpus-aligned)
        if buf[1] == 0x80 and end >= 4 and buf[2] == S.TO_MARK and buf[3] == S.FC:
            es, k = _dec_expr(buf, 4, end, syms, stop_bytes=_IF_COND_STOP)
            # final pair's fd may be reader-stripped; accept both spellings
            if len(es) != 1:
                raise Unsupported("SET DATASESSION expression unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            paren = False
            if k < end and buf[k] == 0x03:
                paren = True
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetDatasessionTo(es[0], paren=paren)
        # SET RELATION — r36-sim, r52-setin, r71-relation. One bank: optional
        # leading ADDITIVE 01, optional IN 16, then TO pairs or OFF. Bare
        # `47 2d 28` (end == 3) stays on the SET_BARE_TO path below.
        if buf[1] == S.SET_RELATION_ID and end > 3:
            return _dec_set_relation(buf, end, syms)
        # SET SKIP / SET MARK OF <object> — ONE clause chain, all four
        # objects. Round 37 measured the BAR arm; r52-setof measured the rest:
        #   SET SKIP OF BAR 6 OF pp .T.      47 4e c3 06 fc f8 0106 fd
        #                                       c3 f7 <pp> fc 61
        #   SET SKIP OF MENU _MSYSMENU .T.   47 4e c3 1c ec 02 fc 61
        #   SET SKIP OF PAD xx OF _MSYSMENU  47 4e c3 bc f7 <xx> c3 ec 02 fc 61
        #   SET SKIP OF POPUP pp .T.         47 4e c3 c6 f7 <pp> fc 61
        # `c3` is OF, the object keyword follows it, and where the object has
        # an OWNER a second `c3` carries it. BAR names its bar with its own
        # fc..fd group and every other object with a bare symbol or a system
        # id behind `ec`. The value rides a final group whose closer is
        # reader-stripped at statement end. The source's own TO word survives
        # as a `28` in front of that group on MARK, the only verb whose syntax
        # has one — VFP9 refuses `SET SKIP … TO` outright.
        if buf[1] in S.SET_OF_BAR_NAMES and end >= 6 \
                and buf[2] == S.SET_OF_MARK \
                and buf[3] in S.SET_OF_OBJECT_WORDS:
            word = S.SET_OF_OBJECT_WORDS[buf[3]]
            obj, k = _dec_set_of_operand(buf, 4, end, syms,
                                         grouped=(word == "BAR"))
            owner = ""
            if k < end and buf[k] == S.SET_OF_MARK:
                name, k = _dec_set_of_operand(buf, k + 1, end, syms)
                owner = " OF %s" % name
            to = ""
            if k < end and buf[k] == S.TO_MARK:
                if buf[1] not in S.SET_OF_BAR_TO_IDS:
                    raise Unsupported("SET variant outside forced subset")
                to = "TO "
                k += 1
            if k >= end or buf[k] != S.FC:
                raise Unsupported("SET variant outside forced subset")
            ves, k = _dec_expr(buf, k + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ves) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET %s OF %s %s%s %s%s"
                           % (S.SET_OF_BAR_NAMES[buf[1]], word, obj, owner,
                              to, _emit(ves[0])))
        # SET SYSMENU — r43-sysmenu (Main.MPX:0 residuals 47 59 28 / 47 59 bc).
        # Pad-list TO _MFILE / _MEDIT is 47 59 28 fc ec <id> [fd 07 fc ec <id>].
        if buf[1] == S.SET_SYSMENU_ID:
            if end == 3 and buf[2] == S.TO_MARK:
                return SetStmt("SET SYSMENU TO")
            if end == 4 and buf[2] == S.TO_MARK \
                    and buf[3] == S.SET_PRINTER_DEFAULT_MARK:
                return SetStmt("SET SYSMENU TO DEFAULT")
            if end == 3 and buf[2] == S.SET_SYSMENU_AUTOMATIC_MARK:
                return SetStmt("SET SYSMENU AUTOMATIC")
            if end == 3 and buf[2] == 0x20:
                return SetStmt("SET SYSMENU ON")
            if end == 3 and buf[2] == 0x1F:
                return SetStmt("SET SYSMENU OFF")
            if end == 3 and buf[2] == S.SET_SYSMENU_SAVE_MARK:
                return SetStmt("SET SYSMENU SAVE")
            if end == 3 and buf[2] == S.SET_SYSMENU_NOSAVE_MARK:
                return SetStmt("SET SYSMENU NOSAVE")
            if end > 4 and buf[2] == S.TO_MARK:
                pads, k = [], 3
                while k < end:
                    if pads:
                        if buf[k] == S.FD:
                            k += 1
                            if k >= end:
                                break
                        if buf[k] != S.ARGJOIN:
                            raise Unsupported("SET SYSMENU pad-list joiner")
                        k += 1
                    if k >= end or buf[k] != S.FC:
                        raise Unsupported("SET SYSMENU pad-list form")
                    k += 1
                    if k + 1 >= end or buf[k] != S.MENU_BAR_ID_MARK:
                        raise Unsupported("SET SYSMENU pad-list form")
                    pid = buf[k + 1]
                    k += 2
                    if k < end and buf[k] == S.FD:
                        k += 1
                    name = S.SET_SYSMENU_PAD_IDS.get(pid)
                    if name is None:
                        raise Unsupported(
                            "SET SYSMENU pad id 0x%02x unmeasured" % pid)
                    pads.append(name)
                if not pads or k != end:
                    raise Unsupported("SET SYSMENU pad-list trailing bytes")
                return SetStmt("SET SYSMENU TO " + ", ".join(pads))
            raise Unsupported("SET variant outside forced subset")
        if end == 3:
            if buf[1] in S.SET_BARE_TO_NAMES and buf[2] == S.TO_MARK:
                return SetStmt("SET %s TO" % S.SET_BARE_TO_NAMES[buf[1]])
            name = S.SET_ONOFF_NAMES.get(buf[1])
            if name is None:
                raise Unsupported("SET variant outside forced subset")
            if buf[2] == 0x20:
                return SetStmt("SET %s ON" % name)
            if buf[2] == 0x1F:
                return SetStmt("SET %s OFF" % name)
        # r71-small: SET PRINTER ON|OFF PROMPT — the PROMPT mark DEVICE
        # already spends, behind the toggle.
        if buf[1] == S.SET_PRINTER_ID and end == 4 \
                and buf[2] in (0x20, 0x1F) \
                and buf[3] == S.SET_DEVICE_PROMPT_MARK:
            return SetStmt("SET PRINTER %s PROMPT"
                           % ("ON" if buf[2] == 0x20 else "OFF"))
        # SET DATE TO <value>: '47 0b 28 fb <str>' — the value rides as an fb string
        # literal; trailing source words (e.g. 'SET DATE TO ANSI LONG') leave no
        # bytecode trace, so the emitted spelling is 'SET DATE TO <str>'
        # (oaremotionweb.scx::rtx Init alignment).
        if end >= 6 and buf[1] == S.SET_DATE_ID and buf[2] == S.TO_MARK \
                and buf[3] == S.STR:
            n = int.from_bytes(buf[4:6], "little")
            if 6 + n != end:
                raise Unsupported("SET variant outside forced subset")
            return SetStmt("SET DATE TO %s" % _payload_text(buf[6:6 + n]))
        # SET DECIMALS TO <group>: '47 0d 28 fc <expr> [03] [fd]' — ORACLE
        # round-25 BOUND (c2 literal / c3 paren-memvar; corpus alignment
        # xfrxlib.vcx::cboHierarchy s1 stmts[25]/[27]). The runtime-paren marker
        # 03 rides INSIDE the TO-value group on parenthesized forms ('SET
        # DECIMALS TO (m.liDeci)'); admitted here and in the APPEND FROM group
        # only — generalising it stays OPEN.
        if end >= 5 and buf[1] == S.SET_DECIMALS_ID and buf[2] == S.TO_MARK \
                and buf[3] == S.FC:
            es, k = _dec_expr(buf, 4, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.PAREN:
                k += 1              # runtime-paren marker inside the value group
            if k < end and buf[k] == S.FD:
                k += 1              # final fd reader-stripped when statement-final
            if k != end:
                raise Unsupported("SET variant outside forced subset")
            return SetStmt("SET DECIMALS TO %s" % _emit(es[0]))
        # ---- population-lane SET extensions (offline-forced carriers only) ----
        # TEXTMERGE beyond plain ON/OFF: '20 ce' = ON NOSHOW (x9, GBK-free
        # carriers), '28' bare TO closes output, '28 c2 f5 0d f7 <u16> ce' =
        # TO MEMVAR m.<name> NOSHOW (_reportlistener.vcx::htmllistener s0,
        # stmt1 <-> stored 'SET TEXTMERGE TO MEMVAR m.lcResult NOSHOW').
        if buf[1] == S.SET_TEXTMERGE_ID and end >= 4 \
                and buf[2] in (0x20, 0x1F) and buf[3] == S.SET_NOSHOW_MARK:
            if buf[2] != 0x20:
                raise Unsupported("SET variant outside forced subset")
            if end != 4:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET TEXTMERGE ON NOSHOW")
        if buf[1] == S.SET_TEXTMERGE_ID and end >= 7 \
                and buf[2] == S.TO_MARK and buf[3] == S.SET_TEXTMERGE_MEMVAR_MARK:
            # r71-small: c2 then a bare f7 symbol or the m. spelling
            # (f5 0d f7), then optional ON/OFF and NOSHOW.
            t = 4
            if t + 4 < end and buf[t] == S.WORKAREA_REF and buf[t + 1] == 0x0D \
                    and buf[t + 2] == S.SYM:
                nm = "m.%s" % _sym(syms, S.u16(buf, t + 3))
                t += 5
            elif t + 3 <= end and buf[t] == S.SYM:
                nm = _sym(syms, S.u16(buf, t + 1))
                t += 3
            else:
                raise Unsupported("SET variant outside forced subset")
            additive = ""
            if t < end and buf[t] == S.SET_ADDITIVE_MARK:
                additive = " ADDITIVE"
                t += 1
            onoff = ""
            if t < end and buf[t] in (0x20, 0x1F):
                onoff = " ON" if buf[t] == 0x20 else " OFF"
                t += 1
            noshow = ""
            if t < end and buf[t] == S.SET_NOSHOW_MARK:
                noshow = " NOSHOW"
                t += 1
            if t != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET TEXTMERGE TO MEMVAR %s%s%s%s"
                           % (nm, additive, onoff, noshow))
        # SET TEXTMERGE DELIMITERS TO — ORACLE-MEASURED round-42 I9:
        #   reset  47 60 be 07
        #   pair   47 60 be fc <left> [fd] 07 fc <right> [fd]
        # Unmeasured DELIMITERS tails (no 07, one operand, trailing bytes)
        # keep raising SET variant outside forced subset.
        if buf[1] == S.SET_TEXTMERGE_ID and end >= 3 \
                and buf[2] == S.SET_TEXTMERGE_DELIMITERS_MARK:
            # r52-setword: with no TO the mark stands alone; the TO form is
            # the mark plus the ARGJOIN the reset spends.
            if end == 3:
                return SetStmt("SET TEXTMERGE DELIMITERS")
            if end == 4 and buf[3] == S.ARGJOIN:
                return SetStmt("SET TEXTMERGE DELIMITERS TO")
            if buf[3] != S.FC:
                raise Unsupported("SET variant outside forced subset")
            les, k = _dec_expr(buf, 4, end, syms, stop_bytes=_IF_COND_STOP)
            if len(les) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k >= end or buf[k] != S.ARGJOIN:
                raise Unsupported("SET variant outside forced subset")
            k += 1
            if k >= end or buf[k] != S.FC:
                raise Unsupported("SET variant outside forced subset")
            res, k = _dec_expr(buf, k + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(res) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET TEXTMERGE DELIMITERS TO %s, %s"
                           % (_emit(les[0]), _emit(res[0])))
        # PRINTER: '47 2a 28 0e' <-> 'SET PRINTER TO DEFAULT';
        # '47 2a 28 4a fc <expr>' <-> 'SET PRINTER TO NAME (<expr>)'
        # (excelxml.vcx s10, 3/3 alignment; markers are PRINTER-slot keywords).
        if buf[1] == S.SET_PRINTER_ID and end == 4 \
                and buf[2] == S.TO_MARK and buf[3] == S.SET_PRINTER_DEFAULT_MARK:
            return SetStmt("SET PRINTER TO DEFAULT")
        if buf[1] == S.SET_PRINTER_ID and end >= 5 \
                and buf[2] == S.TO_MARK and buf[3] == S.SET_PRINTER_NAME_MARK:
            if buf[4] != S.FC:
                raise Unsupported("SET variant outside forced subset")
            es, k = _dec_expr(buf, 5, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET PRINTER TO NAME %s" % _emit(es[0]))
        # REPORTBEHAVIOR: '47 93 fc <expr>' <-> 'SET REPORTBEHAVIOR 80|90' —
        # NO TO marker, the value group follows the id directly (19 stmts).
        # r52-setword measured ENGINEBEHAVIOR on the same frame under id 90.
        if buf[1] in S.SET_NO_TO_VALUE_IDS and end >= 4 and buf[2] == S.FC:
            es, k = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET %s %s" % (S.SET_NO_TO_VALUE_IDS[buf[1]],
                                          _emit(es[0])))
        # r52-setword: DATE's word rides a bare fb string with NO TO mark —
        # 'SET DATE ANSI' is '47 0b fb 0400 ANSI'. A second source word leaves
        # no trace ('SET DATE ANSI LONG' is the same frame as 'SET DATE ANSI'),
        # which is why the emitted spelling is the first word alone.
        if buf[1] == S.SET_DATE_ID and end >= 5 and buf[2] == S.STR:
            n = S.u16(buf, 3)
            if 5 + n != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET DATE %s" % _payload_text(buf[5:5 + n]))
        # r52-setword: DEVICE takes a destination KEYWORD in its value slot,
        # and the FILE keyword carries the same name operand every file verb
        # spends. PRINTER may be followed by the PROMPT word.
        if buf[1] == S.SET_DEVICE_ID and end >= 4 and buf[2] == S.TO_MARK \
                and buf[3] in S.SET_DEVICE_WORDS:
            word = S.SET_DEVICE_WORDS[buf[3]]
            if word == "FILE":
                name, t = _r50_operand(buf, 4, end, syms, "SET DEVICE")
                if t != end:
                    raise Unsupported("SET trailing bytes")
                return SetStmt("SET DEVICE TO FILE %s" % name)
            if end == 4:
                return SetStmt("SET DEVICE TO %s" % word)
            if end == 5 and word == "PRINTER" \
                    and buf[4] == S.SET_DEVICE_PROMPT_MARK:
                return SetStmt("SET DEVICE TO PRINTER PROMPT")
            raise Unsupported("SET trailing bytes")
        # r52-setword: STATUS drops the TO mark entirely, and STATUS BAR keeps
        # the toggle behind the same 06 BAR mark DEFINE BAR spends.
        if buf[1] == S.SET_STATUS_ID:
            if end == 2:
                return SetStmt("SET STATUS TO")
            if end == 4 and buf[2] == S.SET_STATUS_BAR_MARK \
                    and buf[3] in (0x20, 0x1F):
                return SetStmt("SET STATUS BAR %s"
                               % ("ON" if buf[3] == 0x20 else "OFF"))
        # NOTIFY CURSOR sub-keyword: '47 5a bd 20|1f' <->
        # 'SET NOTIFY CURSOR ON|OFF' (fxmemberdatascript.vcx s22/s23);
        # plain NOTIFY keeps the generic ONOFF path above.
        if buf[1] == 0x5A and end == 4 and buf[2] == S.SET_NOTIFY_CURSOR_MARK \
                and buf[3] in (0x20, 0x1F):
            return SetStmt("SET NOTIFY CURSOR %s" % ("ON" if buf[3] == 0x20 else "OFF"))
        # ORDER with work-area clause: '47 28 16 <alias> 28 <value>' <->
        # 'SET ORDER TO <value> IN <alias>' (foxcharts s59 stmt46: alias slot is
        # a bare f7 sym; xfrxlib s48 stmt15: an fc-group). Value spelling first,
        # per the stored sources ('SET ORDER TO 0 IN FRX').
        if buf[1] == 0x28 and end >= 7 and buf[2] == S.SET_ORDER_IN_MARK:
            t = 3
            if buf[t] == S.SYM and t + 3 <= end:
                alias = _sym(syms, S.u16(buf, t + 1))
                t += 3
            elif buf[t] == S.FC:
                aes, ak = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(aes) != 1:
                    raise Unsupported("SET variant outside forced subset")
                t = ak
                if t < end and buf[t] == S.FD:
                    t += 1
                alias = _emit(aes[0])
            else:
                raise Unsupported("SET variant outside forced subset")
            if t + 1 >= end or buf[t] != S.TO_MARK:
                raise Unsupported("SET variant outside forced subset")
            # value: fc-group OR bare string literal ('SET ORDER TO 0 IN FRX')
            es, k, _ungrouped = dec_set_value(buf, t + 1, end, syms,
                                              sid=buf[1])
            direction, k = _dec_order_direction(buf, k, end)
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET ORDER TO %s IN %s%s"
                           % (_emit_set_order_tag(es), alias, direction))
        # SET's IN <alias> tail on the settings that spend their TO mark in
        # FRONT of the IN mark — ORACLE-MEASURED r52-setin:
        #   47 1a 28 16 <alias> [<value group>]   SET FILTER TO [<e>] IN <a>
        #   47 79 28 16 <alias> <value group>     SET KEY    TO  <e>  IN <a>
        # The work area comes FIRST on the wire and the setting's own value
        # follows it, which is the reverse of the source order; the alias is a
        # bare symbol, a bare numeric literal or its own group.
        if buf[1] in S.SET_IN_TAIL_TO_FIRST and end >= 5 \
                and buf[2] == S.TO_MARK and buf[3] == S.SET_ORDER_IN_MARK:
            name = S.SET_IN_TAIL_TO_FIRST[buf[1]]
            alias, t = _dec_in_alias(buf, 4, end, syms)
            if t == end:
                return SetStmt("SET %s TO IN %s" % (name, alias))
            if buf[t] != S.FC:
                raise Unsupported("SET trailing bytes")
            ves, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ves) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1          # closer reader-stripped when statement-final
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET %s TO %s IN %s"
                           % (name, _emit(ves[0]), alias))
        # SET REPROCESS — r71-small. TO AUTOMATIC is `28 bc`; a numeric TO
        # takes the grouped value, and SECONDS is a trailing d1 behind it.
        # AUTOMATIC SECONDS is the same frame as AUTOMATIC.
        if buf[1] == S.SET_REPROCESS_ID and end >= 4 and buf[2] == S.TO_MARK:
            if buf[3] == S.SET_REPROCESS_AUTOMATIC_MARK:
                if end != 4:
                    raise Unsupported("SET trailing bytes")
                return SetStmt("SET REPROCESS TO AUTOMATIC")
            es, k, _ungrouped = dec_set_value(buf, 3, end, syms, sid=buf[1])
            seconds = ""
            if k < end and buf[k] == S.SET_REPROCESS_SECONDS_MARK:
                seconds = " SECONDS"
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET REPROCESS TO %s%s" % (_emit(es), seconds))
        # Generic measured value form: '47 <id> 28 [fc <expr> [03] [fd]] |
        # fb <str>] [01]' — grouped spellings carry the PAREN postfix 03 inside
        # the group for '(m.x)' values, fd is reader-stripped when final, and
        # 01 = ADDITIVE on its measured ids only. Bare single string operands
        # are measured on ORDER/CLASSLIB/PROCEDURE/LIBRARY ('SET ORDER TO
        # Revert', 'SET CLASSLIB TO foxchartsBeta.vcx ADDITIVE').
        if buf[1] in S.SET_VALUE_TO_NAMES and buf[2] == S.TO_MARK and end > 3:
            name = S.SET_VALUE_TO_NAMES[buf[1]]
            es, k, ungrouped = dec_set_value(buf, 3, end, syms, sid=buf[1])
            # r71-classlib: extra libraries on 07, then ALIAS 02, then IN 16.
            # ADDITIVE stays last, as the generic tail below already reads it.
            # Source order is IN then ALIAS then ADDITIVE; the wire stores
            # ALIAS ahead of IN.
            libs = []
            alias = ""
            in_clause = ""
            if name == "CLASSLIB":
                libs.append(_emit_classlib_lib(es, ungrouped))
                while k < end and buf[k] == S.ARGJOIN:
                    k += 1
                    nxt, k, u2 = dec_set_value(buf, k, end, syms, sid=buf[1])
                    libs.append(_emit_classlib_lib(nxt, u2))
                if k < end and buf[k] == S.SET_CLASSLIB_ALIAS_MARK:
                    k += 1
                    asp, k = _dec_classlib_alias_operand(buf, k, end, syms)
                    alias = " ALIAS %s" % asp
                if k < end and buf[k] == S.SET_ORDER_IN_MARK:
                    k += 1
                    isp, k = _dec_classlib_in_operand(buf, k, end, syms)
                    in_clause = " IN %s" % isp
            additive = ""
            if k < end and buf[k] == S.SET_ADDITIVE_MARK:
                if buf[1] not in S.SET_ADDITIVE_IDS and name != "TEXTMERGE":
                    raise Unsupported("SET trailing bytes")
                additive = " ADDITIVE"
                k += 1
            if name == "TEXTMERGE" and k < end \
                    and buf[k] == S.SET_NOSHOW_MARK:
                additive += " NOSHOW"
                k += 1
            direction = ""
            if name == "ORDER":
                direction, k = _dec_order_direction(buf, k, end)
            if k != end:
                raise Unsupported("SET trailing bytes")
            if name == "CLASSLIB":
                return SetStmt("SET CLASSLIB TO %s%s%s%s"
                               % (", ".join(libs), in_clause, alias, additive))
            if name == "ORDER":
                return SetStmt("SET ORDER TO %s%s%s"
                               % (_emit_set_order_tag(es), additive, direction))
            # An UNGROUPED fb operand is the unquoted-name spelling for every
            # setting that has one — the same one-bit spelling r50-leadsweep
            # measured on REPORT FORM and EXTERNAL, and r52-setvalue measured
            # across the whole SET namespace. A quoted value is a GROUPED
            # `fc d9`, so quoting an fb payload would write a source the
            # compiler never produced. An EMPTY payload is the bare TO with an
            # operand slot the compiler spends anyway (PATH, TOPIC).
            if ungrouped and isinstance(es, Str):
                if not es.text:
                    return SetStmt("SET %s TO%s" % (name, additive))
                return SetStmt("SET %s TO %s%s" % (name, es.text, additive))
            return SetStmt("SET %s TO %s%s" % (name, _emit(es), additive))
        raise Unsupported("SET variant outside forced subset")
    if lead == S.REPLACE_LEAD:
        pairs = []
        all_scope = False
        in_spec = None
        # statement-final bare 03 is the compiled ALL clause, NOT a paren node —
        # forced 224/224 against stored sources across the whole dev population
        # (zero counter-cases); exclude it before parsing the final expression.
        #
        # Round-32 refinement: the strip is PROVISIONAL. When the reader's fd-fe
        # strip removed the FINAL expression group's closer, that trailing 03 can
        # be the VALUE BYTE of the final numeric literal instead — measured
        # matrix (4 blocked solos, census lane-r32-1):
        #   setpi2erp20151128.scx::frmGETDATA gen221 stmt483 and
        #   setpi2erp20151210.scx::frmGETDATA stmt483 'REPLACE 库存 WITH Y2,标示
        #   WITH 3' (stored L1239 / L1194), setpi2erp.scx::frmGETDATA stmt525
        #   (L1292) — wire `… f7<库存> d1 fc f7<Y2> fd 07 f7<标示> d1 fc f8 01 03`;
        #   serviceview.scx::cdYes stmt67 '…,TableID WITH 3' (L78), six pairs,
        #   same tail. The literal arms read their value bytes unbounded, so
        #   under the shortened bound the final expression either faults or
        #   overruns ONTO the true end; only an EXACT landing on orig_end
        #   retracts the strip (branch below). Every previously forced reading
        #   never reaches it and behaves byte-for-byte as before.
        strip_all = False
        orig_end = end
        final_paren = False
        if end >= 2 and buf[end - 1] == 0x03:
            strip_all = True
            end -= 1
            # r47-replaceall: ALL closes the WITH group first, so the scope
            # byte follows an fd (`… <expr> fd 03`). A parenthesised value with
            # no scope ends `… <expr> 03` — the group's own fd is the
            # statement's last byte and the reader strips it. Reading that 03
            # as ALL loses the parentheses AND writes an fd that is not there.
            final_paren = end >= 1 and buf[end - 1] != S.FD
        if end >= 2 and buf[1] == 0x16:
            # REPLACE ... IN <alias> | IN (<expr>): measured clause-first layout
            # (VFPxWorkbookXLSX 'REPLACE c_cells.celldeleted WITH True IN
            # c_cells'; fxmemberdatascript 'REPLACE Execute WITH "" IN
            # (THIS.scriptAlias)'). Wire: 3e 16 f7 <sym> <pairs> |
            # 3e 16 fc <expr> [03] fd <pairs>.
            t = 2
            if t + 3 <= end and buf[t] == S.SYM:
                in_spec = _sym(syms, S.u16(buf, t + 1))
                t += 3
            elif t < end and buf[t] == S.FC:
                depth, fd_pos = 1, t + 1
                while fd_pos < end and depth:
                    if buf[fd_pos] == S.FC:
                        depth += 1
                    elif buf[fd_pos] == S.FD:
                        depth -= 1
                        if depth == 0:
                            break
                    fd_pos += 1
                if depth or fd_pos >= end:
                    raise Unsupported("REPLACE IN clause unresolved")
                expr_end = fd_pos
                if expr_end > t + 1 and buf[expr_end - 1] == 0x03:
                    expr_end -= 1     # contextual-reuse 03 separator before fd
                es2, k2 = _dec_expr(buf, t + 1, expr_end, syms)
                if len(es2) != 1 or k2 != expr_end:
                    raise Unsupported("REPLACE IN expression unresolved")
                t = fd_pos + 1
                in_spec = ("(", es2[0], ")")
            else:
                raise Unsupported("REPLACE IN clause unresolved")
            j = t
        else:
            j = 1
        while True:
            lv, j = _dec_lvalue(buf, j, end, syms)
            if buf[j] != S.REPLACE_WITH or buf[j + 1] != S.FC:
                raise Unsupported("REPLACE WITH unwrapped")
            es, k = _dec_expr(buf, j + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("REPLACE expression unresolved")
            if strip_all and k == orig_end:
                # Round-32 retract: the final expression overran the shortened
                # bound by exactly the stripped byte and completed on the true
                # end — that byte was this expression's own value byte (the
                # measured carriers are final f8-width literals), not an ALL
                # clause. Mid-statement pairs cannot get here: their fd stops
                # the scan first.
                pairs.append((lv, es[0]))
                return ReplaceStmt(
                    pairs, all_scope=all_scope, in_spec=in_spec,
                    all_first=_replace_all_first(syms, all_scope, in_spec,
                                                 None))
            # the FINAL pair's fd is consumed by the reader's fd-fe strip, so a clean
            # run-to-end is legal; mid-statement pairs keep their fd before 07/ALL
            if k < end and buf[k] == S.FD:
                k += 1
            elif k != end:
                raise Unsupported("REPLACE expression unresolved")
            if final_paren and k == end:
                es[0] = Paren(es[0])
            pairs.append((lv, es[0]))
            if k == end:
                scope = all_scope or (strip_all and not final_paren)
                return ReplaceStmt(
                    pairs, all_scope=scope, in_spec=in_spec,
                    all_first=_replace_all_first(syms, scope, in_spec, None))
            if buf[k] == 0x03:
                # ALL scope: forced 9/9 against stored 'REPLACE ... ALL' sources;
                # round-28 W4: the byte may also PRECEDE a trailing FOR clause
                # ('REPLACE .. WITH .. ALL FOR id<>1', setpurtd.lhbbak
                # OpChgClass s0 stmts4/8)
                all_scope = True
                k += 1
                if k == end:
                    return ReplaceStmt(
                        pairs, all_scope=True, in_spec=in_spec,
                        all_first=_replace_all_first(syms, True, in_spec,
                                                     None))
            if buf[k] == S.ARGJOIN:
                j = k + 1
                continue
            if buf[k] == 0x13 and k + 1 < end and buf[k + 1] == S.FC:
                # trailing FOR clause: 13 fc <cond> [fd] (mainmenu Command5 aligned)
                fes, fk = _dec_expr(buf, k + 2, end, syms, stop_bytes=_IF_COND_STOP)
                if len(fes) != 1:
                    raise Unsupported("REPLACE FOR clause unresolved")
                if fk < end and buf[fk] == S.FD:
                    fk += 1
                if fk != end:
                    raise Unsupported("REPLACE trailing bytes")
                if strip_all and final_paren:
                    # r48-scopeword: the ALL byte always sits immediately after
                    # the WITH group's fd — `REPLACE f WITH 1 ALL FOR c` and
                    # `… FOR c ALL` are the same frame, `fd 03 13 <cond>`. A
                    # trailing 03 BEHIND the condition is that condition's own
                    # parenthesis, which is exactly what r47-replaceall's
                    # fd-precedes test says: here the byte before it is the
                    # condition's last operator, not an fd.
                    return ReplaceStmt(pairs, all_scope=all_scope,
                                       for_cond=Paren(fes[0]), in_spec=in_spec)
                return ReplaceStmt(pairs, all_scope=all_scope or strip_all,
                                   for_cond=fes[0], in_spec=in_spec)
            raise Unsupported("REPLACE trailing bytes")
    if lead in (S.SUM_LEAD, S.COUNT_LEAD):
        # <lead> [13 fc <cond> fd] 28 <targets joined by 07> (<fc expr fd> joined
        # by 07)* — the compiled targets-first layout (iter. 38), extended by the
        # leading FOR scope clause measured ahead of the TO section:
        #   SUM cash*profit/100,cash TO a1,a2 FOR !EMPTY(profit) AND !ISNULL(profit)
        #       (preorder1.scx::CdQuery stmt 113)
        #   SUM TA015*OLDID/3600 TO Y9 FOR ALLTRIM(TA010)<=X AND MD002=Y
        #       (picost.scx::Command5 stmt 84)
        #   COUNT TO X1 FOR ALLTRIM(TA010)<=X AND MD002=Y — lead 12, targets only
        #       (picost.scx::Command5 stmt 82; base `12 28 f7 <sym>` is the
        #       TOKEN_REFERENCE "COUNT TO var" row)
        # The 13 fc … fd token is the same clause REPLACE carries trailing (iter. 33).
        # Round-32 measured extensions (COUNT only — SUM keeps its closed shape):
        #   03            explicitly spelled ALL scope word before the clause
        #                 ('COUNT ALL FOR INLIST(ObjType,… ) AND Double AND Resoid
        #                 # 1 TO m.liTally', _reportlistener.vcx::xmllistener s50
        #                 stmt19 -> 12 03 13 fc .. fd 28 f5 0d f7 <sym>)
        #   2b fc .. fd   WHILE clause ('COUNT TO lii WHILE XX000==liPage',
        #                 xfrxlib.vcx::xfrxie s0 stmt26). ALL+WHILE and FOR+WHILE
        #                 are UNMEASURED combinations and stay Unsupported.
        if lead == S.COUNT_LEAD:
            is_count = True
            shape = "COUNT shape"
        else:
            is_count = False
            shape = "SUM shape"
        t = 1
        for_cond = None
        while_cond = None
        count_all = False
        scope = None
        has_clause = False
        clause_tap = _sym_tap()
        # r59-sumscope and r59-countscope: BOTH verbs spell the clause head the
        # way CALCULATE does and in the same place — NOOPTIMIZE, the scope word,
        # FOR, WHILE — every one ahead of the 28 TO mark, and a pair is those
        # same tokens concatenated in that frame order. Round 32 measured ALL
        # and WHILE on a single COUNT carrier each and hardened on exactly what
        # that one carrier showed: `12 03` only WITH a following FOR, and
        # ALL+WHILE / FOR+WHILE refused as unmeasured. Both matrices authored
        # the bank whole instead, so the hardening is measured away rather than
        # widened by guess.
        verb = "COUNT" if is_count else "SUM"
        if t < end and buf[t] == S.CALC_NOOPTIMIZE:
            raise Unsupported("%s NOOPTIMIZE clause unmeasured" % verb)
        if t < end and buf[t] in S.CALC_SCOPE_WORDS:
            scope = (S.CALC_SCOPE_WORDS[buf[t]], None)
            count_all = buf[t] == 0x03
            t += 1
        elif t < end and buf[t] in S.CALC_SCOPE_COUNTED:
            word = S.CALC_SCOPE_COUNTED[buf[t]]
            if t + 1 >= end or buf[t + 1] != S.FC:
                raise Unsupported("%s scope count unwrapped" % verb)
            with clause_tap:
                ses, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(ses) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("%s scope count unresolved" % verb)
            scope = (word, ses[0])
            t = k + 1
        if t + 1 < end and buf[t] == S.CALC_FOR_MARK and buf[t + 1] == S.FC:
            with clause_tap:
                fes, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(fes) != 1:
                raise Unsupported("%s FOR clause unresolved" % verb)
            # A clause that is the LAST thing in the statement carries no
            # closing fd — its RPN runs to the stream end, exactly as LOCATE's
            # does (r59-countscope `ct_no_to`: `12 03 13 fc <rpn>` with no TO).
            k = _agg_clause_end(buf, k, end, verb, "FOR")
            for_cond = fes[0]
            t = k
        if t < end and buf[t] == S.CALC_WHILE_MARK:
            if t + 1 >= end or buf[t + 1] != S.FC:
                raise Unsupported("%s WHILE clause unwrapped" % verb)
            with clause_tap:
                wes, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(wes) != 1:
                raise Unsupported("%s WHILE clause unresolved" % verb)
            k = _agg_clause_end(buf, k, end, verb, "WHILE")
            while_cond = wes[0]
            t = k
        has_clause = (scope is not None or for_cond is not None
                      or while_cond is not None)
        targets = []
        to_array = False
        to_tap = _sym_tap()
        if t < end and buf[t] == S.TO_MARK:
            t += 1
            if not is_count and t < end and buf[t] == S.CALC_TO_ARRAY_MARK:
                # `28 04 <lvalue>`: TO ARRAY, the same mark CALCULATE spends
                to_array = True
                t += 1
            with to_tap:
                while True:
                    tv, t = _dec_lvalue(buf, t, end, syms)
                    targets.append(tv)
                    # a COUNT stream ends directly after its target memvar
                    if t < end and buf[t] == S.ARGJOIN:
                        t += 1
                        continue
                    break
        elif not (is_count and (for_cond is not None or while_cond is not None)):
            # a COUNT whose FOR/WHILE clause carries no TO section is measured
            # (r59-countscope `ct_no_to`, `COUNT ALL FOR c`); a bare scope word
            # with neither a clause nor a TO section is not.
            raise Unsupported(shape)
        values = []
        expr_tap = _sym_tap()
        while t < end and not is_count:
            # COUNT never carries an expression list; anything left over under
            # that lead is a shape this arm has not measured, and the check
            # below names it rather than reading it as a summed expression.
            if buf[t] != S.FC:
                raise Unsupported("SUM expr unwrapped")
            with expr_tap:
                es, k = _dec_expr(buf, t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SUM expression unresolved")
            k += 1 if k < end and buf[k] == S.FD else 0
            values.append(es[0])
            if k < end and buf[k] == S.ARGJOIN:
                t = k + 1
                continue
            t = k
            break
        # r49-clauseorder: the frame stores the FOR/WHILE clause ahead of the TO
        # section whatever order the source wrote, and the symbol table keeps
        # the source's. The ALL spelling is unmeasured in the TO-first order, so
        # it keeps the canonical emission.
        clause_first = has_clause and _written_first(to_tap, clause_tap)
        if is_count:
            # measured COUNT carries at most one target memvar and never an
            # expression list; the TO section itself is optional behind a clause.
            if values or t != end or len(targets) > 1:
                raise Unsupported(shape)
            return CountStmt(targets[0] if targets else None,
                             for_cond=for_cond, while_cond=while_cond,
                             count_all=count_all, scope=scope,
                             to_first=clause_first)
        if len(values) != len(targets) or t != end:
            raise Unsupported(shape)
        # SUM emits TO before FOR, so the recovered order is the mirror one.
        # SUM also has a part whose source position is FIXED — the summed
        # expressions are written before either clause in every spelling — so
        # any name they introduce must be numbered below both clauses'. A table
        # that says otherwise is one no source produces, and the reader declines
        # rather than reading an order into it.
        expr_lo = expr_tap.first_new()
        cf = clause_tap.first_new()
        tf = to_tap.first_new()
        consistent = expr_lo is None or all(
            expr_lo < i for i in (cf, tf) if i is not None)
        if has_clause and consistent and cf is not None and tf is not None:
            for_first = cf < tf
        else:
            # The table cannot tell. Round 49's canonical for the bare clause is
            # TO first, and `SUM e TO v FOR c` is measured (r59-sumscope
            # st_to_first_for). A SCOPE word is different: every spelling the
            # sweep compiled writes it BEFORE the TO section, so it leads when
            # one is present rather than emitting an order never measured.
            for_first = scope is not None
        return SumStmt(targets, values, for_cond=for_cond,
                       while_cond=while_cond, scope=scope, to_array=to_array,
                       for_first=for_first)
    if lead == S.GO_TOP[0]:
        # Measured GO/GOTO family (see GoTop docstring). Canonical spelling 'GO':
        #   23 29                                        GO TOP      (FORCED 27/27)
        #   23 36                                        GO BOTTOM   (TOKEN_REFERENCE:73)
        #   23 fc <expr>                                 GO <expr>
        #   23 16 <target> [<rec-expr>] [29|36]          GO [TOP|BOTTOM|<expr>] IN <target>
        # Anything unobserved (unknown second byte, trailing bytes, truncated
        # operands) stays Unsupported — no generalization.
        t = 1
        in_target = None
        if buf[t] == S.GO_IN_CLAUSE:
            t += 1
            if t >= end:
                raise Unsupported("GO IN target missing")
            if buf[t] == S.SYM:
                if t + 3 > end:
                    raise Unsupported("GO IN target truncated")
                in_target = Sym(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            elif buf[t] == S.FC:
                es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(es) != 1 or k >= end or buf[k] != S.FD:
                    raise Unsupported("GO IN target unresolved")
                in_target = es[0]
                t = k + 1
            else:
                raise Unsupported("GO IN target form")
        elif end == 2:
            if buf[t] == S.GO_TOP[1]:
                return GoTop()
            if buf[t] == S.GO_BOTTOM_MARK:
                return GoTop(selector="BOTTOM")
            raise Unsupported("GO TOP shape")
        elif buf[t] != S.FC:
            raise Unsupported("GO shape")
        selector = None
        if t < end and buf[t] == S.FC:
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("GO expression unresolved")
            selector = es[0]
            t = k + 1 if k < end and buf[k] == S.FD else k
        if t < end:
            if end - t != 1 or buf[t] not in (S.GO_TOP[1], S.GO_BOTTOM_MARK):
                raise Unsupported("GO shape")
            selector = None if buf[t] == S.GO_TOP[1] else "BOTTOM"
        return GoTop(selector=selector, in_target=in_target)
    if lead == S.SELECT_WA:
        if end == 4 and buf[1] == S.SYM:
            return SelectStmt(_sym(syms, S.u16(buf, 2)))
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x01:
            # SELECT <numeric area>: I16 subop-1 literal (iter. 41)
            return SelectStmt(str(S.u16(buf, 3)))
        if buf[1] == S.FC:
            # SELECT (<expr>): memvar/path workarea (_reportlistener, iter. 43)
            es, k = _dec_expr(buf, 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SELECT workarea expression unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SELECT workarea trailing bytes")
            return SelectStmt(_emit(es[0]))
        raise Unsupported("SELECT workarea shape")
    if lead == S.ENDIF_LEAD:
        if end != 1:
            raise Unsupported("ENDIF trailing bytes")
        return ("ENDIF",)
    if lead == S.ELSE_LEAD:
        # 1b f9 05 <u16> — target verified at frame-walk time against code base;
        # e9 00 <u32> is the long-jump width of the same ENDIF anchor
        if end == 5 and buf[1] == S.INT16 and buf[2] == 0x05:
            return ("ELSE", S.u16(buf, 3))
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            return ("ELSE", int.from_bytes(buf[3:7], "little"))
        raise Unsupported("ELSE frame shape")
    if lead in (S.EXPRSTMT, S.EXPRSTMT_BARE):
        bare = lead == S.EXPRSTMT_BARE
        if buf[j] != S.FC:
            if not bare:
                raise Unsupported("expression-statement unwrap")
            # 99 <e2-path>: WITH-scoped method invocation without parens
            if buf[j] == S.WITHREF:
                try:
                    node, k = _dec_withref(buf, j, end, syms)
                except Unsupported:
                    # r42-formrel: 99 e2 e5 <M> fc <sub> fd 03 f7 <term>
                    # (.FORMS(I).RELEASE). Stock path — the AATest carrier
                    # is a bare statement, not the retry-only P8 f6-callee.
                    node_prop = _dec_with_index_prop(buf, j, end, syms)
                    if node_prop is not None:
                        return ExprStmt(node_prop, bare=True)
                    # Round37 P8 (C09/G2, retry pass only): the measured
                    # WITH-scoped indexed-mid-call statement shape hooks here;
                    # any non-carrier re-raises its historical message.
                    if not _EXPR_RETRY_ACTIVE:
                        raise
                    node2 = _dec_with_chain_call(buf, j, end, syms)
                    if node2 is not None:
                        return ExprStmt(node2, bare=True)
                    raise
                if k != end:
                    raise Unsupported("bare withref-statement shape")
                return ExprStmt(node, bare=True)
            # 99 df e3 <cls> f7 <mbr> f7 <dup>: CLASS::MEMBER scope-resolved
            # invocation, statement-final (round 33 lane R33-1). Anything that is
            # not this exact spelling falls through to the stock reader below,
            # so every other 99 tail keeps its historical rejection.
            if buf[j] == S.SCOPE_OP:
                node = _dec_scope_call_tail(buf, j, end, syms)
                if node is not None:
                    return ExprStmt(node, bare=True)
            # 99 f5 0d <f4 hop>+ f7 <term>: m.<var>.<path> bare invocation,
            # statement-final (round 33 lane R33-1); non-final or missing
            # terminal f7 stays with the stock reader unchanged.
            if buf[j] == S.WORKAREA_REF and j + 2 < end \
                    and buf[j + 1] == 0x0D and buf[j + 2] == S.MEMBER:
                node = _dec_memvar_path_tail(buf, j, end, syms)
                if node is not None:
                    return ExprStmt(node, bare=True)
                # 99 f5 0d <f4 hop>+ e5 <M> <args> 03 [hops] f7 <term>: the
                # same bare invocation with a CALL link in the chain (round 40
                # lane C, _dec_memvar_chain_tail). Declines to None on every
                # byte that is not this measured shape.
                node = _dec_memvar_chain_tail(buf, j, end, syms)
                if node is not None:
                    return ExprStmt(node, bare=True)
            # 99 [f5 0d] e5 <arr> <subs> 16 [f4 <hop>]* f6 <M> <args> 03: the
            # same bare invocation with an array ELEMENT as its receiver
            # (r50-sysapp). Declines to None on every other shape.
            node = _dec_array_elem_call(buf, j, end, syms)
            if node is not None:
                return ExprStmt(node, bare=True)
            # 99 <f4/f7 path>: member invocation without parens; extended by the
            # population lane PATHS to measured call chains that run to the
            # statement end ('Character(AgentID).Play(MyKey(s1))',
            # mainmenu3.scx::Timer1; 'this.cntxfrxmultipage1.removePage(tnPage)',
            # xfrxlib.vcx::frmmppreviewer)
            try:
                node, k = _dec_path(buf, j, end, syms)
                if k == end and isinstance(node, MemberPath):
                    return ExprStmt(node, bare=True)
            except Unsupported as e:
                if "member path without terminal property" not in str(e):
                    raise
            node, k = _dec_object_chain(buf, j, end, syms)
            if k != end:
                raise Unsupported("bare member-statement shape")
            return ExprStmt(node, bare=True)
        # Measured corpus shape: the expression runs to the END of the stream — the
        # trailing fd of `fc expr fd` was consumed by the reader's fd-fe strip. The old
        # handler demanded a surviving fd, which no corpus statement satisfies.
        try:
            es, k = _dec_expr(buf, j + 1, end, syms)
        except Unsupported as stock_err:
            # Round37-wave2 P16 (carriers 3f133997f6b20709:28 /
            # 78429a71ad111792:28): the measured comma-list continuation of a
            # lead-86 statement — `fc <expr>` units joined by fd 07 (FD+ARGJOIN),
            # N>=2, statement ends after the last unit. Retry-only engagement:
            # every stock success and every non-matching failure keeps its exact
            # historical behavior/message; bare 99 statements are not measured
            # with this tail and stay on the stock path.
            if bare:
                raise
            units = _dec_exprstmt_comma_list(buf, j + 1, end, syms)
            if units is None:
                raise
            return ExprStmt(ExprList(units), bare=bare)
        if len(es) != 1 or k != end:
            raise Unsupported("expression-statement shape")
        return ExprStmt(es[0], bare=bare)
    if lead == 0x38:
        # QUIT (Guineu CommandTokens.QUIT=0x38); bare form only
        if end != 1:
            raise Unsupported("QUIT trailing bytes")
        return ("QUIT",)
    if lead == 0x0E:
        if end == 1:
            return ("CLEAR",)
        if end == 2 and buf[1] in S.CLEAR_KEYWORDS:
            # r54-clearbank: the operand is ONE keyword byte, the bank swept
            # whole on the oracle. WINDOW/WINDOWS/WINDOW w1 all collapse to
            # 0e2c (r42-clear): neither the name nor the plural is on the wire.
            return ClearStmt(S.CLEAR_KEYWORDS[buf[1]])
        if end == 3 and buf[1] == S.CLEAR_READ and buf[2] == S.CLEAR_ALL:
            # CLEAR READ ALL is READ's byte followed by ALL's OWN byte
            return ClearStmt("READ ALL")
        if end >= 3 and buf[1] in (S.CLEAR_CLASSLIB, 0x4F):
            # r54-clearbank: CLASS and CLASSLIB take one operand and the wire
            # records the SOURCE'S spelling of it — a bare name rides as its
            # own token (an fb literal for CLASSLIB, a symbol for CLASS) and a
            # quoted or parenthesised one rides an fc group whose closer is
            # reader-stripped at statement end, exactly as DECLARE's library is
            word = "CLASSLIB" if buf[1] == S.CLEAR_CLASSLIB else "CLASS"
            if buf[2] == S.FC:
                try:
                    node, t = _fc_group(buf, 2, end, syms)
                except Unsupported:
                    raise Unsupported("CLEAR trailing bytes")
                if t != end:
                    raise Unsupported("CLEAR trailing bytes")
                return ClearStmt(word, expr=node)
            if word == "CLASS":
                if end != 5 or buf[2] != S.SYM:
                    raise Unsupported("CLEAR trailing bytes")
                return ClearStmt("CLASS", [_sym(syms, S.u16(buf, 3))])
            name, t = _dec_str_arg(buf, 2, end)
            if t != end:
                raise Unsupported("CLEAR trailing bytes")
            return ClearStmt("CLASSLIB", [name])
        if end >= 3 and buf[1:3] == bytes([0x56, 0x02]):
            names = []
            ops = []
            t = 3
            while t < end:
                # r49-dllname: the opcode IS the source's quoting. A double
                # quoted name is a string literal (d9) whose payload keeps the
                # author's case; a bare name is an identifier (fb) the compiler
                # upper-cases, so `WinAPI_Foo` and `winapi_foo` are one frame.
                # Single quotes and brackets ride fb with the case intact
                # (round-42 strdelim), which is why a mixed-case fb payload
                # cannot have been written bare.
                ops.append(buf[t])
                name, t = _dec_str_arg(buf, t, end)
                names.append(name)
                if t == end:
                    break
                if buf[t] != S.ARGJOIN:
                    raise Unsupported("CLEAR DLLS name-list tail")
                t += 1
            if not names:
                raise Unsupported("CLEAR DLLS name missing")
            return ClearStmt("DLLS", names, ops)
        # round-28 W4: RESOURCES, bare or with one grouped operand
        if buf[1] == 0xCC:
            operand = None
            t = 2
            if t < end and buf[t] == S.FC:
                try:
                    operand, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("CLEAR trailing bytes")
            if t != end:
                raise Unsupported("CLEAR trailing bytes")
            return ClearStmt("RESOURCES", expr=operand)
        raise Unsupported("CLEAR trailing bytes")
    if lead == 0x14:
        # DELETE (CommandTokens.DELETE=0x14). Measured forms: bare (`14`, CMD_SWEEP
        # DELETE row) and the FOR clause `14 13 fc <cond> [fd]` — byte 13 = FOR is
        # pinned by the sweep cross-family rows (LOCATE `2d 13`, JOIN WITH..FOR
        # `29 .. 13 fc fd`, COPY "FOR clause on COPY = 13 fc..fd"); like LOCATE FOR,
        # the condition runs to stream end (trailing fd reader-stripped). Scope
        # clauses other than FOR stay unforced.
        # Round-28 additions, each carrier-aligned: leading scope byte 03 = ALL
        # ('DELETE ALL' org_chart s1 stmts16/49; 'DELETE ALL FOR <cond>'
        # gfxnorender s1 stmt61 — same compiled ALL byte REPLACE carries);
        # 12 = FILE clause with literal or grouped-expression operand;
        # c4 = VIEW clause with a name literal; 1e = NEXT clause whose count is
        # an fc-group. Anything else keeps the unchanged trailing-bytes label.
        # r54-inalias (41 programs) measured the whole record-scope bank and it
        # is read here as ONE ordered walk in the compiler's own wire order:
        #   14 [16 <alias>] [30] [<scope>] [13 fc <for>] [2b fc <while>]
        # against the source order
        #   DELETE [<scope>] [FOR <c>] [WHILE <c>] [IN <alias>] [NOOPTIMIZE]
        # so a combination the walk does not reach — a scope word in front of
        # the IN mark, a second clause after the condition — still refuses.
        if end == 1:
            return ("DELETE",)
        t = 1
        if t < end and buf[t] == S.COPY_FILE_MARK:
            t += 1
            if t < end and buf[t] in (S.STR, S.STR2):
                name, t2 = _dec_str_arg(buf, t, end)
                if t2 != end:
                    raise Unsupported("DELETE trailing bytes")
                # stored sources spell these names UNQUOTED ('DELETE FILE
                # P_ASS', 'DELETE FILE *.pngg')
                return DeleteScopeStmt("FILE", name)
            try:
                operand, t2 = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("DELETE file expression unresolved")
            if t2 != end:
                raise Unsupported("DELETE trailing bytes")
            return DeleteScopeStmt("FILE", operand)
        if t < end and buf[t] == 0xC4:
            t += 1
            if t < end and buf[t] in (S.STR, S.STR2):
                name, t2 = _dec_str_arg(buf, t, end)
                if t2 != end:
                    raise Unsupported("DELETE trailing bytes")
                return DeleteScopeStmt("VIEW", name)
            raise Unsupported("DELETE trailing bytes")
        # Round-31: `16 f7 <sym>` = the compiled IN-work-area clause — the same
        # clause-first wire byte REPLACE carries under its own lead ('REPLACE ..
        # WITH True .. IN c_cells' -> `3e 16 f7 ..`, reader above). Every carrier
        # lives in VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx and is aligned to its
        # own stored METHODS line (alignment table /tmp/foxlift-r31-delete-scope/
        # samples/ALIGNMENT.md): bare 'DELETE IN c_sheets' -> `14 16 f7 <alias>`,
        # and 'DELETE FOR workbook = tnWB IN c_cells' ->
        # `14 16 f7 <alias> 13 fc <cond>` — the compiler wires the IN clause
        # FIRST regardless of the authored FOR..IN order, then the condition runs
        # to stream end like the bare-FOR arm above. r54-inalias widened the
        # alias to the three spellings the shared `16` mark carries and put the
        # scope words, NOOPTIMIZE and WHILE behind it in one walk.
        alias = None
        if t < end and buf[t] == S.GO_IN_CLAUSE:
            alias, t = _dec_in_alias(buf, t + 1, end, syms,
                                     refusal="DELETE trailing bytes")
        nooptimize = False
        if t < end and buf[t] == S.DELETE_NOOPTIMIZE:
            nooptimize = True
            t += 1
        scope, count = None, None
        if t < end and buf[t] in S.DELETE_SCOPE_WORDS:
            scope = S.DELETE_SCOPE_WORDS[buf[t]]
            t += 1
            if scope in S.DELETE_SCOPE_COUNTED:
                try:
                    count, t = _fc_group(buf, t, end, syms)
                except Unsupported:
                    raise Unsupported("DELETE %s count unresolved" % scope)
        cond = while_cond = None
        if t + 2 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
            try:
                cond, t = _fc_group(buf, t + 1, end, syms)
            except Unsupported:
                raise Unsupported("DELETE FOR condition unresolved")
        if t + 2 < end and buf[t] == S.DELETE_WHILE_MARK \
                and buf[t + 1] == S.FC:
            try:
                while_cond, t = _fc_group(buf, t + 1, end, syms)
            except Unsupported:
                raise Unsupported("DELETE WHILE condition unresolved")
        if t != end:
            raise Unsupported("DELETE trailing bytes")
        # The two shapes rounds 28 and 31 measured keep the nodes they were
        # measured into, so nothing downstream of them moves.
        if alias is None and not nooptimize and while_cond is None \
                and count is None and scope in (None, "ALL"):
            if cond is not None:
                return DeleteFor(cond, all_scope=scope == "ALL")
            if scope == "ALL":
                return ("DELETE ALL",)
        if scope is None and count is None and cond is None \
                and while_cond is None and not nooptimize and alias is None:
            raise Unsupported("DELETE trailing bytes")
        return DeleteScopeStmt(scope or "", count, cond=cond, alias=alias,
                               while_cond=while_cond, nooptimize=nooptimize)
    if lead == S.ERASE_LEAD:
        # ERASE — two measured operand spellings, then an optional clause tail.
        #
        # 1. Literal name: lead 20 + fb string, then end of statement. Bound by the
        #    command sweep's authored 'ERASE ers1.txt' -> `20 fb 08 'ers1.txt'`
        #    (CMD_SWEEP.md bound-commands table). Trailing bytes stay unsupported.
        if end >= 4 and buf[j] == S.STR:
            n = S.u16(buf, j + 1)
            if j + 3 + n != end:
                raise Unsupported("ERASE trailing bytes")
            return EraseStmt(_payload_text(buf[j + 3:j + 3 + n]))
        # 2. File EXPRESSION: `20 fc <rpn> [fd c4]`, corpus-forced across 31 dev
        #    methods / 51 statements with every distinct stream shape aligned to its
        #    own stored METHODS source (pop-erase lane audit):
        #      f7 sym .. 03            = ERASE (lcFileName)     _internet.vcx::_urlcombobox
        #      f5 0d f7 .. d9 .. 06 03 = ERASE (m.lcDir + "mem.txt")
        #                                foxcharts.vcx::foxcharts s59 x4
        #      f4 hop f7 .. 03         = ERASE (THIS.SaveTargetFileName) NORECYCLE
        #                                _reportlistener.vcx::xmllistener x4
        #      f7 .. d9 .. 06          = ERASE OldPath+"\TMPLH2W11.*"  buyfine.scx
        #                                (NO paren marker, NO clause bytes)
        #      d9 ..                   = ERASE "transtmp.xml"  translate_en.scx
        #      43 43 .. 9b fb .. 06    = ERASE ALLTRIM(STR(zzkeyid ))+'下发.pdf'
        #      .. 03 fd c4             = ERASE (THIS.TargetFileName) RECYCLE
        #                                utilityreportlistener EraseReport x3
        #    The trailing 03 is the runtime-paren marker already consumed INSIDE
        #    _dec_expr (same byte as SET DECIMALS TO's), so Paren nodes make both the
        #    parenthesized and paren-less sources round-trip without extra emission.
        #    `fd c4` = RECYCLE: spelling forced by utilityreportlistener's own stored
        #    source (three `ERASE ... RECYCLE` lines against three `03 fd c4` tails,
        #    while that record's NORECYCLE lines carry no tail). NORECYCLE itself
        #    leaves NO bytecode trace — of the 35 bare-`03` carriers, 26 read plain
        #    `(x)` and 9 read `(x) NORECYCLE` in their own sources — so it is never
        #    emitted (same accepted class as SET DATE's traceless trailing LONG).
        #    The evidence queue's "[06 03] NORECYCLE?" guess is refuted by those
        #    same carriers: 06 is the '+' concatenation operator INSIDE the operand
        #    expression.
        #    Only fc-wrapped operands bind; anything else stays a loud gap. The
        #    group closer fd follows the family convention (_fc_group): present in
        #    the RECYCLE carriers where the statement continues, reader-stripped
        #    when statement-final everywhere else.
        if buf[1:2] != b"\xfc":
            raise Unsupported("ERASE file form")
        try:
            operand, k = _fc_group(buf, 1, end, syms)
        except Unsupported:
            raise Unsupported("ERASE file expression unresolved")
        recycle = False
        # RECYCLE is bound ONLY as its measured sequence: group closer fd followed
        # by c4. A c4 arriving WITHOUT the closer (buf[k-1] != fd) is an unmeasured
        # arrangement and stays a loud gap, like any other leftover byte.
        if end - k == 1 and buf[k] == 0xC4 and buf[k - 1] == S.FD:
            recycle = True
        elif k != end:
            raise Unsupported("ERASE trailing bytes")
        return EraseStmt(operand, recycle)
    if lead == 0x3D:
        # RENAME <old-file> TO <new-name> — lane r34-B (census
        # /tmp/foxlift-r34-census, family "statement lead 0x3d"). Two measured
        # shapes, each pinned by its carrier's own stored METHODS source:
        #
        # 1. Literal new name: 3d fb<len><old> 28 fb<len><new>
        #    purtcmanage.scx::CdSend stmts100/101 <-> L122/L123
        #      'RENAME 报表打印.frx TO reporttest.frx' / '.frt'
        #    The new-name literal runs EXACTLY to end-of-statement (both wire
        #    carriers do); a short read or any tail byte rejects.
        #
        # 2. Expression new name: 3d fb<len><old> 28 fc <expr>
        #    pidocchk.scx::CdSend stmts131/132 <-> L174/L175
        #      'RENAME 报表打印.frx TO ALLTRIM(keytxt)+m供应商+''.frx'''
        #      wire expr = fc 43 f7<KEYTXT> 9b f7<供应商> 06 fb '.frx' 06
        #    ONE value consuming the whole remainder, else reject.
        #
        # The old name is a string literal on every measured carrier (fb on
        # both; d9 shares the literal envelope like SQL FROM/CURSOR names).
        # Context stays local: 28 binds as TO only immediately after the old
        # name under lead 3d, never globally. Truncated length fields, a
        # missing TO, trailing bytes and symbol/bare-operand spellings stay
        # loudly Unsupported — the simulation envelope
        # (/tmp/foxlift-r34-census scripts/lane_sims34.py sim_B_rename) is the
        # whole acceptance boundary, and the whole-population diff proved it
        # touches exactly the two gain keys.
        if j + 3 > end or buf[j] not in (S.STR, S.STR2):
            raise Unsupported("RENAME old-name literal missing")
        n_old = S.u16(buf, j + 1)
        if j + 3 + n_old > end:
            raise Unsupported("RENAME old-name string truncated")
        old = _payload_text(buf[j + 3:j + 3 + n_old])
        t = j + 3 + n_old
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("statement lead 0x3d missing TO")
        t += 1
        if t < end and buf[t] in (S.STR, S.STR2):
            if t + 3 > end:
                raise Unsupported("RENAME new-name string truncated")
            n_new = S.u16(buf, t + 1)
            if t + 3 + n_new != end:
                raise Unsupported("statement lead 0x3d trailing bytes")
            return RenameStmt(old,
                              _payload_text(buf[t + 3:t + 3 + n_new]))
        if t < end and buf[t] == S.FC:
            es, k = _dec_expr(buf, t + 1, end, syms)
            if len(es) != 1 or k != end:
                raise Unsupported("RENAME new-name expression unresolved")
            return RenameStmt(old, es[0])
        raise Unsupported("statement lead 0x3d new-name form unmeasured")
    if lead == 0xBD:
        # round-28 W4 / r46-throw: bd as statement lead is THROW (n11;
        # context-local vs ON ESCAPE under lead 31). Bare THROW is the
        # 1-byte statement `bd` (oracle r46-throw; HARVEST.md). THROW
        # <expr> is `bd fc <expr>` with no closer:
        # 'bd fc f8020b' = THROW 11; 'bd fc f50df700..' = THROW (m.x).
        if end == 1:
            return ThrowStmt(None)
        if end < 3 or buf[1] != S.FC:
            raise Unsupported("THROW expression unwrapped")
        es, k = _dec_expr(buf, 2, end, syms)
        if len(es) != 1 or k != end:
            raise Unsupported("THROW expression unresolved")
        return ThrowStmt(es[0])
    if lead == 0x31:
        # ON family — round-20 FORCED grammar: 31 <selector> [operands..]
        # fb<u16-len><command-bytes>. Selector map lives ONLY here, beneath this
        # lead: bd as statement lead is THROW (n11) while bd under 31 is ON ESCAPE
        # (n03) — context-local reuse, never a global byte->token entry. Bare ON
        # ERROR emits 7b 10 fb 0000 and does NOT route through here; ON PAGEDOWN/
        # PAGEUP do not exist in VFP9 (round-20 forced negatives). Every shape
        # outside the measured selector map stays Unsupported.
        if end < 2:
            raise Unsupported("ON selector missing")
        sel = buf[1]
        t = 2
        head = {S.ON_SELECTOR_ERROR: "ERROR",
                S.ON_SELECTOR_ESCAPE: "ESCAPE",
                S.ON_SELECTOR_SHUTDOWN: "SHUTDOWN"}.get(sel)
        if head is not None:
            handler, t = _on_handler_text(buf, t, end)
            return OnStmt(head, handler)
        if sel == S.ON_SELECTOR_KEY_LABEL:
            # 31 17 32 fb<label> fb<handler>
            if t >= end or buf[t] != S.ON_KEY_LABEL_MARK:
                raise Unsupported("ON KEY LABEL form")
            t += 1
            if t + 3 > end or buf[t] != S.STR:
                raise Unsupported("ON KEY LABEL label missing")
            ln = S.u16(buf, t + 1)
            label = _payload_text(buf[t + 3:t + 3 + ln])
            t += 3 + ln
            handler, t = _on_handler_text(buf, t, end)
            return OnStmt("KEY LABEL", handler, label=label)
        if sel == S.ON_SELECTION_PREFIX:
            if t >= end:
                raise Unsupported("ON SELECTION kind missing")
            kind = buf[t]
            t += 1
            if kind in (S.ON_SELECTION_POPUP, S.ON_SELECTION_MENU):
                # d0 c6|1c f7 <popup> fb<handler>
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("ON SELECTION name missing")
                popup = _sym(syms, S.u16(buf, t + 1))
                t += 3
                kw = "SELECTION POPUP" if kind == S.ON_SELECTION_POPUP \
                    else "SELECTION MENU"
                handler, t = _on_handler_text(buf, t, end)
                return OnStmt(kw, handler, popup=popup)
            if kind == S.ON_SELECTION_BAR:
                # d0 06 fc <expr> fd c3 f7 <popup> fb<handler>
                if t >= end or buf[t] != S.FC:
                    raise Unsupported("ON SELECTION BAR number unwrapped")
                es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(es) != 1 or k >= end or buf[k] != S.FD:
                    raise Unsupported("ON SELECTION BAR number unresolved")
                t = k + 1
                if t >= end or buf[t] != S.ON_SELECTION_OF:
                    raise Unsupported("ON SELECTION BAR OF clause missing")
                t += 1
                popup, t = _menu_popup_operand(buf, t, end, syms)
                if popup is None:
                    raise Unsupported("ON SELECTION BAR popup missing")
                handler, t = _on_handler_text(buf, t, end)
                return OnStmt("SELECTION BAR", handler, popup=popup, bar=es[0])
            raise Unsupported(f"ON SELECTION kind 0x{kind:02x} unmeasured")
        if sel == S.ON_SELECTION_BAR:
            # 06 without the d0 prefix = plain ON BAR (round-37 G1: selector 06
            # is the BAR KIND byte, not an action marker — a01 keeps it with a
            # WAIT WINDOW action). Same operand frame as the SELECTION variant,
            # then either a structured ACTIVATE POPUP target (bc c6 f7<sym>,
            # b11) or an ordinary fb command payload (a01).
            bar, t = _fc_group(buf, t, end, syms)
            if t >= end or buf[t] != S.ON_SELECTION_OF:
                raise Unsupported("ON BAR OF clause missing")
            t += 1
            popup, t = _menu_popup_operand(buf, t, end, syms)
            if popup is None:
                raise Unsupported("ON BAR popup missing")
            if t < end and buf[t] == S.ON_ACTIVATE_MARK:
                if t + 5 != end or buf[t + 1] != S.DEFINE_POPUP_KW \
                        or buf[t + 2] != S.SYM:
                    raise Unsupported("ON BAR ACTIVATE target form")
                handler = "ACTIVATE POPUP " + _sym(syms, S.u16(buf, t + 3))
                return OnStmt("BAR", handler, popup=popup, bar=bar)
            handler, t = _on_handler_text(buf, t, end)
            return OnStmt("BAR", handler, popup=popup, bar=bar)
        if sel == S.DEFINE_PAD_KW:
            # r43-onpad: 31 bc f7 <pad> c3 ec 02 bc c6 f7 <popup>
            # ON PAD x OF _MSYSMENU ACTIVATE POPUP p. Byte bc is the PAD
            # selector here and the ACTIVATE mark after OF — position decides.
            # DO <cmd> is an fb payload after OF (same as ON BAR).
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("ON PAD name missing")
            pad = _sym(syms, S.u16(buf, t + 1))
            t += 3
            if t >= end or buf[t] != S.ON_SELECTION_OF:
                raise Unsupported("ON PAD OF clause missing")
            t += 1
            if t + 2 > end or buf[t] != S.MENU_BAR_ID_MARK:
                raise Unsupported("ON PAD OF form")
            of_menu = S.PUSH_POP_MENU_IDS.get(buf[t + 1])
            if of_menu is None:
                raise Unsupported("ON PAD menu id 0x%02x unmeasured" % buf[t + 1])
            t += 2
            if t < end and buf[t] == S.ON_ACTIVATE_MARK:
                if t + 5 != end or buf[t + 1] != S.DEFINE_POPUP_KW \
                        or buf[t + 2] != S.SYM:
                    raise Unsupported("ON PAD ACTIVATE target form")
                handler = "ACTIVATE POPUP " + _sym(syms, S.u16(buf, t + 3))
                return OnStmt("PAD", handler, popup=pad, of_menu=of_menu)
            handler, t = _on_handler_text(buf, t, end)
            return OnStmt("PAD", handler, popup=pad, of_menu=of_menu)
        raise Unsupported(f"ON selector 0x{sel:02x} unmeasured")
    if lead == 0x7C:
        # DECLARE <ret> <func> IN <lib> [AS <alias>] [type (07 type)*] — the one
        # shape every lead-0x7c statement in the frozen benchmark carries (301/301).
        # Type keywords, the AS marker and the @ byref suffix are pinned by the
        # carriers' own stored sources; param names are dropped before the bytecode
        # and re-emit nameless. Anything outside the measured token set stays
        # Unsupported — never guessed.
        t = 1
        ret = None
        if t < end and buf[t] != S.STR and buf[t] != S.FC:
            ret = _DECLARE_TYPES.get(buf[t])
            if ret is None:
                raise Unsupported(
                    f"DECLARE return type 0x{buf[t]:02x} unmeasured")
            t += 1
        if t + 3 > end or buf[t] != S.STR:
            raise Unsupported("DECLARE function name missing")
        n = S.u16(buf, t + 1)
        fname = _payload_text(buf[t + 3:t + 3 + n])
        t += 3 + n
        if t >= end or buf[t] != S.DECLARE_IN_MARK:
            raise Unsupported("DECLARE IN clause missing")
        t += 1
        if t < end and buf[t] == S.STR:
            n = S.u16(buf, t + 1)
            if t + 3 + n > end:
                raise Unsupported("DECLARE library truncated")
            lib = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        elif t < end and buf[t] == S.FC:
            # An fc-wrapped library is an EXPRESSION the author wrote as such, and the
            # wrapper is what distinguishes it from the bare-name form above: 'IN gdi32'
            # stores 16 fb<gdi32>, 'IN "user32"' stores 16 fc d9<user32> fd. Inside the
            # group the literal token even records the quote character (schemas.STR2:
            # d9 double, fb single), so the quotes render from the node like any other
            # expression — stripping them back to a bare name loses what the wire kept.
            # r54-declarelib: the group is the statement's LAST clause whenever
            # no AS alias and no parameter list follows, and then its closer is
            # reader-stripped exactly as every statement-final group's is.
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            k2 = _clause_group_close(buf, k, end)
            if len(es) != 1 or k2 is None:
                raise Unsupported("DECLARE library unresolved")
            lib = _emit(es[0])
            t = k2
        else:
            raise Unsupported("DECLARE library form")
        alias = None
        if t < end and buf[t] == S.DECLARE_AS_MARK:
            t += 1
            if t + 3 > end or buf[t] != S.STR:
                raise Unsupported("DECLARE alias missing")
            n = S.u16(buf, t + 1)
            alias = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        params = []
        trailing_comma = False
        while t < end:
            ty = _DECLARE_TYPES.get(buf[t])
            if ty is None:
                raise Unsupported(
                    f"DECLARE type token 0x{buf[t]:02x} unmeasured")
            t += 1
            piece = ty
            if t < end and buf[t] == S.DECLARE_PARAM_BYREF:
                piece += " @"
                t += 1
            params.append(piece)
            if t >= end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("DECLARE parameter list tail")
            t += 1
            if t >= end:
                # r44-decl7c: trailing ARGJOIN compiles from a trailing comma.
                trailing_comma = True
                break
        return DeclareDllStmt(fname, lib, ret=ret, alias=alias, params=params,
                              trailing_comma=trailing_comma)
    # ---- round-29 structured statement leads (append-only; see class docs) ----
    if lead == 0x26:
        # INDEX ON <expr> TAG <tag>: oracle-bound by CMD_SWEEP.md row INDEX
        # ('2620fcf70000fdcaf70100'); corpus census: dominant shape x54 plus
        # the tail flags below. Everything else stays blocked.
        if end < 3 or buf[1] != 0x20 or buf[2] != S.FC:
            raise Unsupported("statement lead 0x26")
        es, k = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("INDEX ON expression unresolved")
        if k >= end or buf[k] != S.FD:
            raise Unsupported("statement lead 0x26")
        t = k + 1
        if t + 4 > end or buf[t] != 0xCA:
            # 0xCA=TAG (CMD_SWEEP cross-family row)
            raise Unsupported("statement lead 0x26")
        if buf[t + 1] == S.SYM:
            tag = _sym(syms, S.u16(buf, t + 2))
            t += 4
        elif buf[t + 1] in (S.STR, S.STR2):
            # round-40 lane F: the TAG operand also arrives as a QUOTED literal,
            # 'ca <fb|d9> <u16 len> <bytes>'. Carrier xfrxlib.vcx::xfcont s66
            # stmt18 <-> stored 'INDEX ON XX000 TAG "I01" ADDI'; the quote style
            # rides the string opcode exactly as it does everywhere else, so the
            # emitted tag keeps the source's own quotes and re-compiles.
            dq = buf[t + 1] == S.STR2
            txt, t = _dec_str_arg(buf, t + 1, end)
            tag = _emit(Str(txt, dq=dq))
        else:
            raise Unsupported("statement lead 0x26")
        # Tail flags, each at most once, any measured order (round-33 index
        # lane): 3c DESCENDING (CMD_SWEEP round-10 clause pass; census
        # foxcharts s83), 01 ADDITIVE (clause table; census c79070eeff459e07
        # s67 stmt14), bd ASCENDING + d4 CANDIDATE (_webbrowser3 s15 stmt74
        # 'INDEX ON IndexValue TAG IndexValue ASCENDING ADDITIVE' <->
        # ...caf70a00bd01; VFPxWorkbookXLSX s13 stmt13 CANDIDATE <->
        # ...caf72a00d4). A repeat or an unknown byte falls to the loud
        # unmeasured raise below.
        descending = additive = ascending = candidate = False
        for_cond = None
        while t < end:
            if buf[t] == 0x3C and not descending:
                descending = True
            elif buf[t] == 0x01 and not additive:
                additive = True
            elif buf[t] == 0xBD and not ascending:
                ascending = True
            elif buf[t] == 0xD4 and not candidate:
                candidate = True
            elif buf[t] == 0x13 and for_cond is None \
                    and t + 1 < end and buf[t + 1] == S.FC:
                # FOR clause, same 13 token LOCATE/REPLACE carry
                # (census c79070eeff459e07 s16 stmt58 'INDEX .. FOR NOT DELETED()')
                fes, fk = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
                if len(fes) != 1:
                    raise Unsupported("INDEX ON FOR clause unresolved")
                for_cond = fes[0]
                t = fk + 1 if fk < end and buf[fk] == S.FD else fk
                break
            else:
                raise Unsupported("INDEX clause 0x%02x unmeasured" % buf[t])
            t += 1
        if t != end:
            raise Unsupported("statement lead 0x26")
        return IndexOnStmt(es[0], tag, descending, additive, for_cond,
                           ascending, candidate)
    if lead == 0xA9:
        # ASSERT <expr> [MESSAGE <"str">]: CMD_SWEEP.md bound row ('ASSERT
        # llAsr' -> a9fcf70000) plus the corpus MESSAGE clause (marker 1d then
        # an fc-wrapped double-quoted literal; foxcharts s18 family x89).
        if end < 2 or buf[1] != S.FC:
            raise Unsupported("statement lead 0xa9")
        es, k = _dec_expr(buf, 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("ASSERT expression unresolved")
        msg = None
        if k < end and buf[k] == S.FD:
            k += 1
            if k < end and buf[k] == 0x1D:
                if k + 2 >= end or buf[k + 1] != S.FC:
                    raise Unsupported("ASSERT MESSAGE clause unresolved")
                mes, mk = _dec_expr(buf, k + 2, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                # census sightings: double-quoted literals AND concatenated
                # string expressions ('...' + This.SourceAlias + '!'). Only
                # the lone SINGLE-quoted literal spelling is unmeasured.
                if len(mes) != 1 or mk != end or \
                        (isinstance(mes[0], Str) and not mes[0].dq):
                    raise Unsupported("ASSERT MESSAGE clause unresolved")
                msg = mes[0]
                return AssertStmt(es[0], msg)
        if k != end:
            raise Unsupported("statement lead 0xa9")
        return AssertStmt(es[0], None)
    if lead == 0x08:
        # AVERAGE: CMD_SWEEP.md bound row ('AVERAGE f1 TO avg1' ->
        # 0828f70100fcf70000); same targets-first wire layout as SUM/COUNT
        # (iter. 38). Census: single-pair x9 / three-pair x7 / leading FOR x2.
        if end < 2:
            raise Unsupported("statement lead 0x08")
        t = 1
        for_cond = None
        if t + 1 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
            fes, fk = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(fes) != 1 or fk >= end or buf[fk] != S.FD:
                raise Unsupported("AVERAGE FOR clause unresolved")
            for_cond = fes[0]
            t = fk + 1
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("AVERAGE shape")
        targets, t = [], t + 1
        while True:
            tv, t = _dec_lvalue(buf, t, end, syms)
            targets.append(tv)
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        values = []
        while t < end:
            if buf[t] != S.FC:
                raise Unsupported("AVERAGE shape")
            ves, vk = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ves) != 1:
                raise Unsupported("AVERAGE expression unresolved")
            vk += 1 if vk < end and buf[vk] == S.FD else 0
            values.append(ves[0])
            if vk < end and buf[vk] == S.ARGJOIN:
                t = vk + 1
                continue
            t = vk
            break
        if not values or len(values) != len(targets) or t != end:
            raise Unsupported("AVERAGE shape")
        return AverageStmt(targets, values, for_cond=for_cond)
    if lead == 0x69:
        # ALTER TABLE <t> ADD|ALTER COLUMN <col> <Type>[(w[,d])] [NULL]:
        # CMD_SWEEP.md bound row (c0=ADD) + census gold pairs (bc=ALTER,
        # quote.scx/pilistdetail2; d6=NULL tail, _internet.vcx carriers).
        if end < 2 or buf[1] != 0x31:
            raise Unsupported("statement lead 0x69")
        t = 2
        if t < end and buf[t] in (S.STR, S.STR2):
            n = S.u16(buf, t + 1)
            if t + 3 + n > end:
                raise Unsupported("statement lead 0x69")
            table = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        elif t < end and buf[t] == S.FC:
            tes, tk = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(tes) != 1 or tk >= end or buf[tk] != S.FD:
                raise Unsupported("ALTER TABLE name unresolved")
            table = tes[0]
            t = tk + 1
        else:
            raise Unsupported("statement lead 0x69")
        kw = None
        if t < end:
            kw = {0xC0: "ADD", 0xBC: "ALTER"}.get(buf[t])
        if kw is None:
            raise Unsupported("ALTER TABLE keyword 0x%02x unmeasured"
                              % buf[t] if t < end else "ALTER TABLE truncated")
        t += 1
        if t >= end or buf[t] != 0xD5:
            raise Unsupported("ALTER TABLE COLUMN clause missing")
        t += 1
        if t + 3 <= end and buf[t] == S.SYM:
            col = _sym(syms, S.u16(buf, t + 1))
            t += 3
        elif t < end and buf[t] == S.FC:
            # r49-valsweep: the column name is a name EXPRESSION as readily as
            # a name — `ALTER TABLE (m.a) ADD COLUMN (m.b) M` groups both
            ces, ck = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                raise Unsupported("ALTER TABLE column missing")
            col = _emit(ces[0])
            t = ck + 1
        else:
            raise Unsupported("ALTER TABLE column missing")
        if t < end and buf[t] in (S.STR, S.STR2):
            n = S.u16(buf, t + 1)
            if t + 3 + n > end:
                raise Unsupported("ALTER TABLE type truncated")
            typ = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        else:
            raise Unsupported("ALTER TABLE type missing")
        widths = []
        if t < end and buf[t] == 0x02:
            # width/decimal group, the CREATE CURSOR field-argument grammar
            t += 1
            while True:
                if t >= end or buf[t] != S.FC:
                    raise Unsupported("ALTER TABLE width group unresolved")
                wes, wk = _dec_expr(buf, t + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(wes) != 1:
                    raise Unsupported("ALTER TABLE width group unresolved")
                wk += 1 if wk < end and buf[wk] == S.FD else 0
                widths.append(wes[0])
                if wk < end and buf[wk] == S.ARGJOIN:
                    t = wk + 1
                    continue
                t = wk
                break
            if t >= end or buf[t] != 0x03:
                raise Unsupported("ALTER TABLE width group unterminated")
            t += 1
        null = False
        if t < end and buf[t] == 0xD6:
            null = True
            t += 1
        if t != end:
            raise Unsupported("ALTER TABLE trailing bytes")
        return AlterTableStmt(table, kw, col, typ, widths, null)
    if lead == 0x2F:
        # MODIFY: COMMAND bc (CMD_SWEEP.md row), FILE 12 and MEMO 1b (census
        # gold pairs _webview/_webbrowser3/translate_en); NOEDIT c5 and RANGE
        # c7 are FILE-only witnesses, NOWAIT 3a per CMD_SWEEP.
        if end < 2:
            raise Unsupported("statement lead 0x2f")
        kind_byte = buf[1]
        t = 2
        target = None
        range_args = None
        noedit = False

        def _r29_name_or_group():
            nonlocal t
            if t < end and buf[t] in (S.STR, S.STR2):
                n = S.u16(buf, t + 1)
                if t + 3 + n > end:
                    raise Unsupported("MODIFY name truncated")
                txt = _payload_text(buf[t + 3:t + 3 + n])
                t += 3 + n
                return txt
            if t < end and buf[t] == S.FC:
                nes, nk = _dec_expr(buf, t + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(nes) != 1 or nk >= end or buf[nk] != S.FD:
                    raise Unsupported("MODIFY target unresolved")
                t = nk + 1
                return nes[0]
            raise Unsupported("MODIFY target missing")

        if kind_byte == 0xBC:
            kind = "COMMAND"
            target = _r29_name_or_group()
        elif kind_byte == 0x12:
            # FILE clause byte; only fc-group names witnessed
            kind = "FILE"
            if t < end and buf[t] == S.FC:
                nes, nk = _dec_expr(buf, t + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(nes) != 1:
                    raise Unsupported("MODIFY target unresolved")
                nk += 1 if nk < end and buf[nk] == S.FD else 0
                target = nes[0]
                t = nk
            else:
                raise Unsupported("MODIFY target missing")
        elif kind_byte == 0x1B:
            # MEMO keyword; dotted member path (translate_en.scx gold pair)
            kind = "MEMO"
            parts = []
            while t + 3 <= end and buf[t] == S.MEMBER:
                parts.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            if t + 3 <= end and buf[t] == S.SYM:
                parts.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
            if not parts:
                raise Unsupported("MODIFY MEMO path missing")
            target = ".".join(parts)
        else:
            raise Unsupported("statement lead 0x2f")
        nowait = False
        # r48-valsweep: MODIFY's clauses are shared by every kind and stored in
        # one canonical order — `[c5 NOEDIT] [3a NOWAIT] [c7 RANGE] [51 AS]
        # [2c WINDOW] [25 SAVE] [16 IN] [cf SAME] [ca NOMENU]` — whatever order
        # the source wrote them in. NOEDIT and RANGE keep their FILE-only
        # witnesses under COMMAND/FILE, which is where the earlier rounds
        # measured them.
        window = in_window = codepage = None
        same = nomenu = save = False
        while t < end:
            b = buf[t]
            if b == 0xC5 and not noedit and kind in ("COMMAND", "FILE"):
                noedit = True
                t += 1
                continue
            if b == 0xC7 and range_args is None and kind in ("COMMAND", "FILE"):
                range_args = []
                t += 1
                for _side in (0, 1):
                    if t >= end or buf[t] != S.FC:
                        raise Unsupported("MODIFY RANGE argument missing")
                    res_, rk = _dec_expr(buf, t + 1, end, syms,
                                         stop_bytes=_IF_COND_STOP)
                    if len(res_) != 1:
                        raise Unsupported("MODIFY RANGE argument unresolved")
                    if _side == 0:
                        if rk >= end or buf[rk] != S.FD:
                            raise Unsupported(
                                "MODIFY RANGE argument unresolved")
                        range_args.append(res_[0])
                        t = rk + 1
                        if t >= end or buf[t] != S.ARGJOIN:
                            raise Unsupported("MODIFY RANGE tail")
                        t += 1
                    else:
                        # trailing group's fd is the reader-stripped tail
                        rk += 1 if rk < end and buf[rk] == S.FD else 0
                        range_args.append(res_[0])
                        t = rk
                continue
            if b == 0x3A and not nowait and kind in ("COMMAND", "FILE"):
                nowait = True
                t += 1
                continue
            if b == 0x2C and window is None:
                window, t = _dec_window_name(buf, t + 1, end, syms,
                                             verb="MODIFY")
                continue
            if b == 0x16 and in_window is None:
                in_window, t = _dec_window_name(buf, t + 1, end, syms,
                                                verb="MODIFY")
                continue
            if b == 0x51 and codepage is None:
                codepage, t = _fc_group(buf, t + 1, end, syms)
                continue
            if b == 0xCF and not same:
                same, t = True, t + 1
                continue
            if b == 0xCA and not nomenu:
                nomenu, t = True, t + 1
                continue
            if b == 0x25 and not save:
                save, t = True, t + 1
                continue
            raise Unsupported("MODIFY trailing bytes")
        return ModifyStmt(kind, target, noedit, range_args, nowait,
                          window=window, in_window=in_window, same=same,
                          nomenu=nomenu, save=save, codepage=codepage)
    if lead == S.CALC_LEAD:
        # CALCULATE <fn>(e)[, <fn>(e)..] TO v[, v..]: the item list and the TO
        # targets are both joined by ARGJOIN 07, and the selector table is the
        # eight aggregate functions bc..c3 (round59_calcitems oracle sweep; the
        # shipped arm knew only c2=SUM and be=MAX and read one item with no
        # joiner, which is why a two-item CALCULATE tripped the `07` between
        # items). Each item's group carries zero (CNT) or more argjoin-07
        # argument expressions (NPV carries two). Gold pair unchanged:
        # 'CALCULATE SUM(f1) TO clc1' (CMD_SWEEP), 'CALCULATE MAX(KEYID) TO X'.
        if end < 2:
            raise Unsupported("statement lead 0x7d")
        t = 1
        # The clause head, in the fixed frame order round59_calcclause measured:
        # IN, NOOPTIMIZE, scope word, FOR, WHILE — then the TO section. IN and
        # NOOPTIMIZE are measured but not read here; they keep a named refusal.
        scope = None
        for_cond = None
        while_cond = None
        clause_tap = _sym_tap()
        if t < end and buf[t] == S.CALC_IN_MARK:
            raise Unsupported("CALCULATE IN clause unmeasured")
        if t < end and buf[t] == S.CALC_NOOPTIMIZE:
            raise Unsupported("CALCULATE NOOPTIMIZE clause unmeasured")
        if t < end and buf[t] in S.CALC_SCOPE_WORDS:
            scope = (S.CALC_SCOPE_WORDS[buf[t]], None)
            t += 1
        elif t < end and buf[t] in S.CALC_SCOPE_COUNTED:
            word = S.CALC_SCOPE_COUNTED[buf[t]]
            if t + 1 >= end or buf[t + 1] != S.FC:
                raise Unsupported("CALCULATE scope count unwrapped")
            with clause_tap:
                ses, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(ses) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("CALCULATE scope count unresolved")
            scope = (word, ses[0])
            t = k + 1
        if t + 1 < end and buf[t] == S.CALC_FOR_MARK and buf[t + 1] == S.FC:
            with clause_tap:
                fes, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(fes) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("CALCULATE FOR clause unresolved")
            for_cond = fes[0]
            t = k + 1
        if t + 1 < end and buf[t] == S.CALC_WHILE_MARK and buf[t + 1] == S.FC:
            with clause_tap:
                wes, k = _dec_expr(buf, t + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
            if len(wes) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("CALCULATE WHILE clause unresolved")
            while_cond = wes[0]
            t = k + 1
        targets = []
        to_array = False
        to_tap = _sym_tap()
        if t < end and buf[t] == S.TO_MARK:
            t += 1
            if t < end and buf[t] == S.CALC_TO_ARRAY_MARK:
                to_array = True
                t += 1
            with to_tap:
                while True:
                    tv, t = _dec_lvalue(buf, t, end, syms)
                    targets.append(tv)
                    if t < end and buf[t] == S.ARGJOIN:
                        t += 1
                        continue
                    break
        elif scope is None and for_cond is None and while_cond is None:
            # no clause head and no TO section: only the bare item-list form
            # (round59_calcclause `nc_bare_no_to`) reaches here.
            pass
        items = []
        while t < end:
            fn = S.CALC_ITEM_FN.get(buf[t])
            if fn is None:
                raise Unsupported(
                    "CALCULATE item selector 0x%02x unmeasured" % buf[t])
            t += 1
            if t >= end or buf[t] != S.CALC_ITEM_GROUP_OPEN:
                raise Unsupported("CALCULATE item group missing")
            t += 1
            args = []
            while t < end and buf[t] == S.FC:
                aes, ak = _dec_expr(buf, t + 1, end, syms,
                                    stop_bytes=_IF_COND_STOP)
                if len(aes) != 1:
                    raise Unsupported("CALCULATE item expression unresolved")
                ak += 1 if ak < end and buf[ak] == S.FD else 0
                args.append(aes[0])
                t = ak
                if t + 1 < end and buf[t] == S.ARGJOIN and buf[t + 1] == S.FC:
                    t += 1
                    continue
                break
            if t >= end or buf[t] != S.CALC_ITEM_GROUP_CLOSE:
                raise Unsupported("CALCULATE item group unterminated")
            items.append((fn, args))
            t += 1
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        if t != end:
            raise Unsupported("CALCULATE trailing bytes")
        if not items:
            raise Unsupported("CALCULATE shape")
        if to_array:
            # TO ARRAY names ONE array that receives every item's result
            # (round59_calcclause `ca_array_multi`: two items, one array).
            if len(targets) != 1:
                raise Unsupported("CALCULATE shape")
        elif targets and len(items) != len(targets):
            raise Unsupported("CALCULATE shape")
        # r49-clauseorder under a third lead: the frame stores the clauses ahead
        # of the TO section whatever order the source wrote, and the symbol
        # table keeps the source's. When neither side introduces a name the
        # table cannot tell, and the documented order (clauses, then TO) is the
        # canonical emission — a tie interns the same table either way.
        cf = clause_tap.first_new()
        tf = to_tap.first_new()
        clause_first = True if (cf is None or tf is None) else cf < tf
        return CalculateStmt(targets, items, scope=scope, for_cond=for_cond,
                             while_cond=while_cond, to_array=to_array,
                             clause_first=clause_first)
    if lead == 0x3F:
        # REPORT FORM <form> [clauses…]: CMD_SWEEP.md bound row
        # ('REPORT FORM rpt1'); the clause bank is r69-bank, read in wire
        # order. PREVIEW c1 / TO 28 / OBJECT 2e / NOCONSOLE 39 were bound
        # earlier; the rest of the marks are the r69-bank table.
        if end < 2 or buf[1] != 0x14:
            raise Unsupported("statement lead 0x3f")
        t = 2
        if t < end and buf[t] in (S.STR, S.STR2):
            n = S.u16(buf, t + 1)
            if t + 3 + n > end:
                raise Unsupported("statement lead 0x3f")
            form = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        elif t < end and buf[t] == S.FC:
            try:
                form, t = _fc_group(buf, t, end, syms)
            except Unsupported:
                raise Unsupported("REPORT FORM name unresolved")
        else:
            raise Unsupported("statement lead 0x3f")
        clauses = _dec_report_clauses(buf, t, end, syms)
        return ReportFormStmt(form, clauses)
    if lead == 0x97:
        # REMOVE TABLE <name>: CMD_SWEEP.md bound row ('REMOVE TABLE rmt1');
        # cd=DELETE bound by chartbillprint.scx::cdPrint 'REMOVE TABLE Foo11
        # DELETE'. Other tails stay blocked.
        if end < 2 or buf[1] != 0x31:
            raise Unsupported("statement lead 0x97")
        t = 2
        if t < end and buf[t] in (S.STR, S.STR2):
            n = S.u16(buf, t + 1)
            if t + 3 + n > end:
                raise Unsupported("statement lead 0x97")
            name = _payload_text(buf[t + 3:t + 3 + n])
            t += 3 + n
        else:
            raise Unsupported("statement lead 0x97")
        delete = False
        if t < end and buf[t] == 0xCD:
            delete = True
            t += 1
        if t != end:
            raise Unsupported("REMOVE TABLE trailing bytes")
        return RemoveTableStmt(name, delete)
    if lead in (S.CLASS_INIT_METHOD, S.CLASS_INIT_PROTECTED, S.CLASS_INIT_HIDDEN):
        # r43-class / r43-a3: class-init method index, same INT32 envelope.
        # a2 = public, a3 = PROTECTED, 9e = HIDDEN. Index 0 unmeasured.
        if end == 7 and buf[1] == S.INT32 and buf[2] == 0x00:
            idx = int.from_bytes(buf[3:7], "little")
            if idx >= 1:
                return ClassMethodIndex(idx)
        raise Unsupported("statement lead 0x%02x" % lead)
    if lead in (S.PROTECTED_LEAD, S.HIDDEN_LEAD):
        # r43-class: PROTECTED n -> a1 f7 <sym>; development compiled programs
        # carry only that 4-byte shape (12 statements). r50-leadsweep compiled
        # HIDDEN beside it — 9f, the SAME frame — and both words with a
        # 07-joined list, which is the shared declaration-list grammar every
        # other declaration verb uses.
        word = "PROTECTED" if lead == S.PROTECTED_LEAD else "HIDDEN"
        names, t = [], 1
        while True:
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("statement lead 0x%02x" % lead)
            names.append(_sym(syms, S.u16(buf, t + 1)))
            t += 3
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("statement lead 0x%02x" % lead)
            t += 1
        return ProtectedProp(names[0], more=names[1:], word=word)
    if lead == 0x96:
        # r43-class: ADD OBJECT x AS cls [WITH ...]. 96 31 is ADD TABLE and
        # stays unmeasured. WITH pairs are d1 then f7 prop 10 fc expr, 07-joined;
        # the last group's fd may be reader-stripped.
        if end < 2 or buf[1] != 0x2E:
            raise Unsupported("statement lead 0x96")
        t = 2
        if t + 3 > end or buf[t] != S.SYM:
            raise Unsupported("ADD OBJECT name missing")
        obj = _sym(syms, S.u16(buf, t + 1))
        t += 3
        if t >= end or buf[t] != S.AS_CLAUSE_MARK:
            raise Unsupported("ADD OBJECT AS missing")
        t += 1
        if t + 3 > end or buf[t] != S.SYM:
            raise Unsupported("ADD OBJECT class missing")
        cls = _sym(syms, S.u16(buf, t + 1))
        t += 3
        pairs = []
        if t < end and buf[t] == S.REPLACE_WITH:
            t += 1
            while t < end:
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("ADD OBJECT WITH name missing")
                prop = _sym(syms, S.u16(buf, t + 1))
                t += 3
                if t >= end or buf[t] != S.EQ:
                    raise Unsupported("ADD OBJECT WITH assignment missing")
                t += 1
                if t >= end or buf[t] != S.FC:
                    raise Unsupported("ADD OBJECT WITH value missing")
                es, t = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
                if len(es) != 1:
                    raise Unsupported("ADD OBJECT WITH value unresolved")
                if t < end and buf[t] == S.FD:
                    t += 1
                pairs.append((prop, es[0]))
                if t == end:
                    break
                if buf[t] != S.ARGJOIN:
                    raise Unsupported("ADD OBJECT WITH tail")
                t += 1
        if t != end:
            raise Unsupported("ADD OBJECT trailing bytes")
        return AddObjectStmt(obj, cls, pairs)
    if lead == S.EXPORT_LEAD:
        # r50-leadsweep: `EXPORT TO <file> [FIELDS <list>] TYPE <word>` is
        # `56 28 <file> [11 f7 <field> (07 f7 <field>)*] d4 <word>` — the
        # universal 28 TO, the same 11 FIELDS COPY TO and SCATTER carry and the
        # same d4 TYPE plus one-byte file-type bank APPEND FROM shares. SDF is
        # a COPY TO type, not an EXPORT one: VFP9 refuses `EXPORT … TYPE SDF`
        # outright, so only the words the matrix compiled are admitted.
        if end > 1 and buf[1] == S.TO_MARK:
            name, t = _r50_operand(buf, 2, end, syms, "EXPORT")
            fields = []
            if t < end and buf[t] == S.FIELDS_MARK:
                t += 1
                while t + 3 <= end and buf[t] == S.SYM:
                    fields.append(_sym(syms, S.u16(buf, t + 1)))
                    t += 3
                    if t < end and buf[t] == S.ARGJOIN:
                        t += 1
                        continue
                    break
            if t + 2 == end and buf[t] == S.TYPE_WORD_MARK \
                    and buf[t + 1] in S.EXPORT_TYPE_WORDS:
                line = "EXPORT TO " + name
                if fields:
                    line += " FIELDS " + ", ".join(fields)
                return CommandLine(line + " TYPE "
                                   + S.EXPORT_TYPE_WORDS[buf[t + 1]])
        raise Unsupported("statement lead 0x56")
    if lead == S.DOCK_LEAD:
        # r50-leadsweep: `DOCK WINDOW <w> POSITION <n>` is
        # `bf 2c f7 <w> 64 fc <n>`. The POSITION word is required — VFP9
        # refuses both the bare-number `DOCK WINDOW w 0` and the documented
        # `AT <row>, <col>` pair on this compiler — so it is the only form.
        if end > 5 and buf[1] == S.DEFINE_WINDOW_KW and buf[2] == S.SYM \
                and buf[5] == S.DOCK_POSITION_KW and buf[6:7] == bytes([S.FC]):
            win = _sym(syms, S.u16(buf, 3))
            es, t = _dec_expr(buf, 7, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) == 1 and (t == end
                                 or (t + 1 == end and buf[t] == S.FD)):
                return CommandLine("DOCK WINDOW %s POSITION %s"
                                   % (win, _emit(es[0])))
        raise Unsupported("statement lead 0xbf")
    if lead in (S.ACCEPT_LEAD, S.INPUT_LEAD):
        # r50-leadsweep: `ACCEPT ["prompt"] TO <var>` is
        # `05 [fc <prompt> fd] 28 <var>`; INPUT is the same frame under 27.
        word = "ACCEPT" if lead == S.ACCEPT_LEAD else "INPUT"
        t, prompt = 1, ""
        if t < end and buf[t] == S.FC:
            txt, t = _r50_operand(buf, t, end, syms, word)
            prompt = " " + txt
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("%s TO clause missing" % word)
        target, t = _r50_operand(buf, t + 1, end, syms, word + " TO")
        if t != end:
            raise Unsupported("%s trailing bytes" % word)
        return CommandLine("%s%s TO %s" % (word, prompt, target))
    if lead == S.FIND_LEAD:
        # r50-leadsweep: FIND's operand is literal source text, not a name
        # expression, so it is always the bare string envelope.
        if end > 3 and buf[1] == S.STR:
            txt, t = _dec_str_arg(buf, 1, end)
            if t == end:
                return CommandLine("FIND " + txt)
        raise Unsupported("statement lead 0x22")
    if lead == S.LABEL_LEAD:
        # r50-leadsweep: `LABEL FORM <name>` — the same 14 FORM mark REPORT
        # FORM and DO FORM carry.
        if end > 1 and buf[1] == S.FORM_MARK:
            name, t = _r50_operand(buf, 2, end, syms, "LABEL FORM")
            if t == end:
                return CommandLine("LABEL FORM " + name)
        raise Unsupported("statement lead 0x2a")
    if lead == S.IMPORT_LEAD:
        # r50-leadsweep: `IMPORT FROM <file> TYPE <word>` — the universal 15
        # FROM, then the same d4 TYPE mark and one-byte file-type bank
        # APPEND FROM and COPY TO already share (r47-typeword).
        if end > 1 and buf[1] == S.FROM_MARK:
            name, t = _r50_operand(buf, 2, end, syms, "IMPORT")
            if t + 1 < end and buf[t] == S.TYPE_WORD_MARK \
                    and buf[t + 1] in S.FILE_TYPE_WORDS and t + 2 == end:
                return CommandLine("IMPORT FROM %s TYPE %s"
                                   % (name, S.FILE_TYPE_WORDS[buf[t + 1]]))
        raise Unsupported("statement lead 0x57")
    if lead == S.JOIN_LEAD:
        # r50-leadsweep: `JOIN WITH <alias> TO <file> FOR <cond>` — WITH is the
        # same d1 REPLACE and DO carry, TO the universal 28 and FOR the 13
        # LOCATE and SCAN spend.
        t = 1
        if t + 3 > end or buf[t] != S.REPLACE_WITH:
            raise Unsupported("JOIN WITH clause missing")
        alias, t = _r50_operand(buf, t + 1, end, syms, "JOIN WITH")
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("JOIN TO clause missing")
        target, t = _r50_operand(buf, t + 1, end, syms, "JOIN TO")
        if t + 1 >= end or buf[t] != S.FOR_MARK or buf[t + 1] != S.FC:
            raise Unsupported("JOIN FOR clause missing")
        es, t = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1 or t != end:
            raise Unsupported("JOIN FOR unresolved")
        return CommandLine("JOIN WITH %s TO %s FOR %s"
                           % (alias, target, _emit(es[0])))
    if lead == S.SORT_LEAD:
        # r50-leadsweep: `SORT ON <field>[ /D] TO <file> [FIELDS <list>]` is
        # `49 [11 <fields>] 20 <field> [fb '/D'] 28 <file>` — the compiler puts
        # the FIELDS list in front and the emission writes the source order,
        # which recompiles to the one frame. The order flag is stored as the
        # literal text the author wrote.
        t, fields = 1, []
        if t < end and buf[t] == S.FIELDS_MARK:
            t += 1
            while t + 3 <= end and buf[t] == S.SYM:
                fields.append(_sym(syms, S.u16(buf, t + 1)))
                t += 3
                if t < end and buf[t] == S.ARGJOIN:
                    t += 1
                    continue
                break
        if t >= end or buf[t] != S.ON_MARK:
            raise Unsupported("SORT ON clause missing")
        t += 1
        keys = []
        while t + 3 <= end and buf[t] == S.SYM:
            key = _sym(syms, S.u16(buf, t + 1))
            t += 3
            if t < end and buf[t] == S.STR:
                flag, t = _dec_str_arg(buf, t, end)
                key += " " + flag
            keys.append(key)
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        if not keys or t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("SORT TO clause missing")
        target, t = _r50_operand(buf, t + 1, end, syms, "SORT TO")
        if t != end:
            raise Unsupported("SORT trailing bytes")
        line = "SORT ON %s TO %s" % (", ".join(keys), target)
        if fields:
            line += " FIELDS " + ", ".join(fields)
        return CommandLine(line)
    if lead == S.TOTAL_LEAD:
        # r50-leadsweep: `TOTAL ON <field> TO <file>` — the same 20 ON mark
        # INDEX ON and SORT ON carry, with the key in a group of its own.
        if end > 2 and buf[1] == S.ON_MARK and buf[2] == S.FC:
            es, t = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) == 1 and t < end and buf[t] == S.FD:
                t += 1
                if t < end and buf[t] == S.TO_MARK:
                    target, t = _r50_operand(buf, t + 1, end, syms, "TOTAL TO")
                    if t == end:
                        return CommandLine("TOTAL ON %s TO %s"
                                           % (_emit(es[0]), target))
        raise Unsupported("statement lead 0x4e")
    if lead == S.MENU_LEAD:
        # r50-leadsweep: `MENU BAR <array>, <n>` — the same 06 BAR mark DEFINE
        # BAR spends, then the ordinary 07 argument joiner.
        if end > 1 and buf[1] == S.BAR_MARK:
            arr, t = _r50_operand(buf, 2, end, syms, "MENU BAR")
            if t < end and buf[t] == S.ARGJOIN and buf[t + 1:t + 2] == \
                    bytes([S.FC]):
                es, t = _dec_expr(buf, t + 2, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) == 1 and t == end:
                    return CommandLine("MENU BAR %s, %s"
                                       % (arr, _emit(es[0])))
        raise Unsupported("statement lead 0x5d")
    if lead == S.SCROLL_LEAD:
        # r50-leadsweep: `SCROLL <r1>, <c1>, <r2>, <c2>, <n>` — five ordinary
        # groups joined by the universal 07, the last one's fd reader-stripped.
        parts, t = [], 1
        while True:
            if t >= end or buf[t] != S.FC:
                raise Unsupported("SCROLL operand missing")
            es, t = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SCROLL operand unresolved")
            parts.append(_emit(es[0]))
            if t < end and buf[t] == S.FD:
                t += 1
            if t == end:
                break
            if buf[t] != S.ARGJOIN:
                raise Unsupported("SCROLL trailing bytes")
            t += 1
        if len(parts) != 5:
            raise Unsupported("SCROLL operand count %d unmeasured" % len(parts))
        return CommandLine("SCROLL " + ", ".join(parts))
    if lead == S.SIZE_LEAD:
        # r50-leadsweep: `SIZE WINDOW <w> TO <rows>, <cols>` — the same 2c
        # WINDOW mark SHOW / HIDE / MOVE / ZOOM all spend.
        if end > 4 and buf[1] == S.DEFINE_WINDOW_KW and buf[2] == S.SYM:
            win = _sym(syms, S.u16(buf, 3))
            t = 5
            if t < end and buf[t] == S.TO_MARK:
                t += 1
                dims = []
                while True:
                    if t >= end or buf[t] != S.FC:
                        break
                    es, t = _dec_expr(buf, t + 1, end, syms,
                                      stop_bytes=_IF_COND_STOP)
                    if len(es) != 1:
                        break
                    dims.append(_emit(es[0]))
                    if t < end and buf[t] == S.FD:
                        t += 1
                    if t == end:
                        break
                    if buf[t] != S.ARGJOIN:
                        break
                    t += 1
                if len(dims) == 2 and t == end:
                    return CommandLine("SIZE WINDOW %s TO %s, %s"
                                       % (win, dims[0], dims[1]))
        raise Unsupported("statement lead 0x89")
    if lead == S.PRINTEEE:
        # r50-leadsweep: `??? <expr>` is `79 fc <expr>` — the raw-output
        # sibling of ? (02) and ?? (03), with no format list of its own.
        if end > 1 and buf[1] == S.FC:
            es, t = _dec_expr(buf, 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) == 1 and (t == end
                                 or (t + 1 == end and buf[t] == S.FD)):
                return CommandLine("??? " + _emit(es[0]))
        raise Unsupported("statement lead 0x79")
    if lead == S.BACKSLASH2_LEAD:
        # r50-leadsweep: `\\ <text>` is the no-line-feed sibling of `\` (8d),
        # the same fb envelope running to end-of-statement.
        if end >= 4 and buf[1] == S.STR and 4 + S.u16(buf, 2) == end:
            return BackslashLine(_payload_text(buf[4:end]), feed=False)
        raise Unsupported("statement lead 0x8e")
    if lead == S.UPDATE_SQL_LEAD:
        # r50-leadsweep: `UPDATE <table> [FROM <src>] SET <col> = <expr>[, …]
        # [WHERE <cond>]` is `70 <table> [15 <src>] ca <col> 10 fc <expr>
        # (fd 07 <col> 10 fc <expr>)* [fd c6 fc <cond>]`. The SET mark is the
        # same `ca` INDEX TAG spends, and WHERE is the `c6` SELECT-SQL's own
        # WHERE carries. The compiler canonicalises FROM in front of SET; the
        # emission writes the source order, which recompiles to one frame.
        table, t = _r50_operand(buf, 1, end, syms, "UPDATE")
        src = None
        if t < end and buf[t] == S.FROM_MARK:
            src, t = _r50_operand(buf, t + 1, end, syms, "UPDATE FROM")
        if t >= end or buf[t] != S.SQL_SET_MARK:
            raise Unsupported("UPDATE SET clause missing")
        t += 1
        sets = []
        while True:
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("UPDATE SET column missing")
            col = _sym(syms, S.u16(buf, t + 1))
            t += 3
            if t + 1 >= end or buf[t] != S.EQ or buf[t + 1] != S.FC:
                raise Unsupported("UPDATE SET value missing")
            es, t = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("UPDATE SET value unresolved")
            sets.append("%s = %s" % (col, _emit(es[0])))
            if t == end:
                break
            if buf[t] != S.FD:
                raise Unsupported("UPDATE SET trailing bytes")
            t += 1
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        where = None
        if t < end and buf[t] == S.SQL_WHERE_MARK:
            if buf[t + 1:t + 2] != bytes([S.FC]):
                raise Unsupported("UPDATE WHERE clause unwrapped")
            wes, t = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(wes) != 1:
                raise Unsupported("UPDATE WHERE unresolved")
            where = _emit(wes[0])
        if t != end:
            raise Unsupported("UPDATE trailing bytes")
        line = "UPDATE %s SET %s" % (table, ", ".join(sets))
        if src is not None:
            line += " FROM %s" % src
        if where is not None:
            line += " WHERE %s" % where
        return CommandLine(line)
    if lead == S.SQL_DELETE_LEAD:
        # r52-sqldelete: `71 15 <target> [c6 <cond group>]` — the universal 15
        # FROM mark and the c6 WHERE mark SELECT-SQL already spends. The
        # target takes the same two spellings a SET TO-value does: a BARE fb
        # name for `DELETE FROM tt`, or its own fc..fd group carrying the 03
        # runtime-paren postfix for every parenthesised form. The condition
        # rides one group whose closer is reader-stripped at statement end.
        if end > 2 and buf[1] == S.FROM_MARK:
            target, t = _r50_operand(buf, 2, end, syms, "DELETE FROM")
            if t == end:
                return CommandLine("DELETE FROM %s" % target)
            if t + 1 < end and buf[t] == S.SQL_WHERE_MARK \
                    and buf[t + 1] == S.FC:
                es, k = _dec_expr(buf, t + 2, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) == 1:
                    if k < end and buf[k] == S.FD:
                        k += 1
                    if k == end:
                        return CommandLine("DELETE FROM %s WHERE %s"
                                           % (target, _emit(es[0])))
        raise Unsupported("statement lead 0x71")
    if lead == S.DROP_LEAD:
        # r50-leadsweep: `DROP TABLE <name>` is `6a 31 <name>` — the same 31
        # TABLE mark CLOSE TABLES / ADD TABLE / ALTER TABLE spend — and
        # `DROP VIEW <name>` rides c4 in the same slot.
        if end > 1 and buf[1] in S.DROP_KINDS:
            name, t = _r50_operand(buf, 2, end, syms, "DROP")
            if t == end:
                return CommandLine("DROP %s %s" % (S.DROP_KINDS[buf[1]], name))
        raise Unsupported("statement lead 0x6a")
    if lead in (S.TYPE_LEAD, S.COMPILE_LEAD, S.RUNSCRIPT_LEAD,
                S.LOAD_LEAD, S.CALL_LEAD):
        # r50-leadsweep, the single-operand file verbs. TYPE puts its TO
        # PRINTER clause IN FRONT of the file, which is where the compiler
        # wrote it; COMPILE's DATABASE kind rides c2; the rest are verb plus
        # operand.
        word = {S.TYPE_LEAD: "TYPE", S.COMPILE_LEAD: "COMPILE",
                S.RUNSCRIPT_LEAD: "RUNSCRIPT", S.LOAD_LEAD: "LOAD",
                S.CALL_LEAD: "CALL"}[lead]
        t, head, tail = 1, "", ""
        if lead == S.TYPE_LEAD and t + 1 < end and buf[t] == S.TO_MARK \
                and buf[t + 1] == S.PRINTER_KW:
            tail, t = " TO PRINTER", t + 2
        elif lead == S.COMPILE_LEAD and t < end and buf[t] == S.DATABASE_KW:
            head, t = "DATABASE ", t + 1
        name, t = _r50_operand(buf, t, end, syms, word)
        if t != end:
            raise Unsupported("%s trailing bytes" % word)
        return CommandLine("%s %s%s%s" % (word, head, name, tail))
    if lead == S.PLAY_LEAD:
        # r50-leadsweep: PLAY MACRO <name> is `81 1a <name>` — the same 1a
        # MACROS keyword SAVE and RESTORE spend on their own macro files.
        if end > 1 and buf[1] == S.MACROS_KW:
            name, t = _r50_operand(buf, 2, end, syms, "PLAY MACRO")
            if t == end:
                return CommandLine("PLAY MACRO " + name)
        raise Unsupported("statement lead 0x81")
    if lead == S.BUILD_LEAD:
        # r50-leadsweep: BUILD <kind> <name> FROM <source>, the kind a byte
        # (PROJECT c5, APP bd, EXE be) and FROM the universal 15 mark.
        # r51-carriers: DLL c6 and MTDLL c8 join the bank, each carrying the
        # EXE frame byte for byte, and RECOMPILE appends one cb to any of them.
        if end > 1 and buf[1] in S.BUILD_KINDS:
            kind = S.BUILD_KINDS[buf[1]]
            name, t = _r50_operand(buf, 2, end, syms, "BUILD")
            if t < end and buf[t] == S.FROM_MARK:
                src, t = _r50_operand(buf, t + 1, end, syms, "BUILD FROM")
                tail = ""
                if t < end and buf[t] == S.BUILD_RECOMPILE_WORD:
                    tail, t = " RECOMPILE", t + 1
                if t == end:
                    return CommandLine("BUILD %s %s FROM %s%s"
                                       % (kind, name, src, tail))
        raise Unsupported("statement lead 0x8f")
    if lead in (S.SAVE_LEAD, S.RESTORE_LEAD):
        # r50-leadsweep: SAVE and RESTORE are one grammar with two direction
        # marks — SAVE's target rides the universal 28 TO and RESTORE's source
        # the universal 15 FROM. The optional kind byte in front selects what
        # is saved: MACROS 1a, SCREEN 26, WINDOW 2c (whose window name follows
        # the file). SAVE TO's ALL tail is the same `03 18` LIKE / `03 bc`
        # EXCEPT pair PRIVATE ALL carries; RESTORE FROM's ADDITIVE is a bare
        # 01 appended to the frame.
        save = lead == S.SAVE_LEAD
        word, mark = ("SAVE", S.TO_MARK) if save else ("RESTORE", S.FROM_MARK)
        prep = "TO" if save else "FROM"
        t, kind = 1, ""
        if t < end and buf[t] in S.SAVE_RESTORE_KINDS:
            kind, t = S.SAVE_RESTORE_KINDS[buf[t]], t + 1
        if t == end:
            if not kind:
                raise Unsupported("%s target missing" % word)
            return CommandLine("%s %s" % (word, kind))
        if buf[t] != mark:
            raise Unsupported("%s %s clause missing" % (word, prep))
        name, t = _r50_operand(buf, t + 1, end, syms, word)
        win = ""
        if kind == "WINDOW":
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("%s WINDOW name missing" % word)
            win = " " + _sym(syms, S.u16(buf, t + 1))
            t += 3
        tail = ""
        if save and t + 2 < end and buf[t] == S.PAREN \
                and buf[t + 1] in S.ALL_QUALIFIERS:
            qual = S.ALL_QUALIFIERS[buf[t + 1]]
            skel, t = _r50_operand(buf, t + 2, end, syms, word)
            tail = " ALL %s %s" % (qual, skel)
        elif not save and t + 1 == end and buf[t] == S.RESTORE_ADDITIVE:
            tail, t = " ADDITIVE", t + 1
        if t != end:
            raise Unsupported("%s trailing bytes" % word)
        head = (kind + win + " ") if kind else ""
        return CommandLine("%s %s%s %s%s" % (word, head, prep, name, tail))
    if lead == S.GETEXPR_LEAD:
        # r50-leadsweep: `GETEXPR [<prompt>] TO <var> [TYPE <c>] [DEFAULT <e>]`
        # — the prompt an optional leading group, the target behind the
        # universal 28 TO, then TYPE d4 and DEFAULT 0e, each its own group.
        t, prompt = 1, ""
        if t < end and buf[t] == S.FC:
            txt, t = _r50_operand(buf, t, end, syms, "GETEXPR")
            prompt = " " + txt
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("GETEXPR TO clause missing")
        target, t = _r50_operand(buf, t + 1, end, syms, "GETEXPR TO")
        tail = ""
        for mark, kw in ((S.GETEXPR_TYPE_MARK, "TYPE"),
                         (S.GETEXPR_DEFAULT_MARK, "DEFAULT")):
            if t < end and buf[t] == mark:
                val, t = _r50_operand(buf, t + 1, end, syms, "GETEXPR " + kw)
                tail += " %s %s" % (kw, val)
        if t != end:
            raise Unsupported("GETEXPR trailing bytes")
        return CommandLine("GETEXPR%s TO %s%s" % (prompt, target, tail))
    if lead in _R50_BARE_COMMANDS:
        word, mods = _R50_BARE_COMMANDS[lead]
        if end == 1:
            return (word,)
        if end == 2 and buf[1] in mods:
            return (word + " " + mods[buf[1]],)
        raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
    if lead in _R50_TRANSACTION:
        if end == 2 and buf[1] == S.TRANSACTION_KW:
            return (_R50_TRANSACTION[lead],)
        raise Unsupported("statement lead 0x%02x" % lead)
    if lead == S.PRINTJOB_LEAD:
        # r50-leadsweep: PRINTJOB opens a block with the universal jump tail
        # and ENDPRINTJOB closes it with a bare 77 — the SCAN/FOR frame shape.
        rel, t = _jump_target(buf, 1, end, "PRINTJOB", with_fd=False)
        if t != end:
            raise Unsupported("PRINTJOB trailing bytes")
        return PrintJobStmt(rel_target=rel)
    if lead == S.ENDPRINTJOB_LEAD:
        if end != 1:
            raise Unsupported("ENDPRINTJOB trailing bytes")
        return ("ENDPRINTJOB",)
    if lead == S.IMPLEMENTS_LEAD:
        # r50-leadsweep: `IMPLEMENTS izz IN "zz.dll"` is
        # b9 fb <IZZ> 16 fb <zz.dll> — the interface a bare identifier the
        # compiler uppercases, the library behind the same 0x16 IN mark FOR
        # EACH's collection rides, keeping its own text. Measured on a plain
        # class and on an OLEPUBLIC session, which compile to one frame.
        if end > 3 and buf[1] == S.STR:
            iface, t = _dec_str_arg(buf, 1, end)
            if t + 1 < end and buf[t] == S.FOREACH_IN_MARK \
                    and buf[t + 1] == S.STR:
                lib, t = _dec_str_arg(buf, t + 1, end)
                if t == end:
                    return ImplementsStmt(iface, '"%s"' % lib)
        raise Unsupported("statement lead 0xb9")
    raise Unsupported(f"statement lead 0x{lead:02x}")


# ---------- section lift --------------------------------------------------------------------------
def statement_source(stream, syms):
    """Decode and emit ONE compiled statement to canonical source.

    Raises :class:`Unsupported` outside the slice — the per-statement building block
    lift_section is built from, exposed for tooling that must account for every blocking
    schema in a method individually (foxlift.impact) rather than stopping at the first.
    """
    return _emit_line(dec_statement(stream, syms))


def _blank_or_payload(line):
    """A line to keep when a PROCEDURE body drops its blanks.

    r47-textblock: an EMPTY TEXT body line is `fb 00 00` on the wire and must
    survive; only a blank the emitter itself produced may be dropped."""
    return line != "" or line.startswith(VERBATIM_MARK)


def lift_section(sec, syms_override=None, keep_marks=False):
    """Lift one Section into canonical source lines; raises Unsupported outside the slice.

    ``syms_override`` replaces the section's own symbol table (module-wide fallback for
    multi-section records where per-section tables are incomplete).

    Block frames (WITH, IF/ELSE) are walked here because their extent spans statements:
    a frame's body runs until its matching end-sentinel, paired BY TYPE. Measured jump
    targets are verified against the real layout at walk time — a mismatch is corruption,
    and corruption is Unsupported, never guessed around. ALL frame jump targets anchor
    to the post-prologue code base."""
    # Frame targets anchor to the post-prologue code base; the prologue width follows the
    # section's measured framing (u16 field -> 3 bytes, u32 field -> 5, docs/FORMAT.md §3).
    # getattr: lightweight Section stand-ins in tests predate the framing attribute and
    # model the dominant u16 layout.
    code_base = sec.offset + (PROLOGUE_U32 if getattr(sec, "framing", "u16") == "u32"
                              else PROLOGUE_U16)
    eff = syms_override if syms_override is not None else sec.symbols
    # The DEFINE BAR system-menu table has one historical variant whose two
    # colliding ids can only be told apart by their siblings in the SAME method
    # (round-40 lane E, _menu_bar_shifted_section). Module state for the same
    # reason dec_statement uses it: the reader sits deep under the walk and
    # statement decoding is single-threaded and never nested.
    global _MENU_SHIFTED_BLOCK, _PAYLOAD_CODEC, _SYM_TABLE_HI
    outer = _MENU_SHIFTED_BLOCK
    prev_codec = _PAYLOAD_CODEC
    prev_hi = _SYM_TABLE_HI
    _MENU_SHIFTED_BLOCK = _menu_bar_shifted_section(sec.statements)
    _PAYLOAD_CODEC = getattr(sec, "codec", None) or "latin1"
    # r49-clauseorder: the walk runs in source order, so "used by an earlier
    # statement" is knowable here and nowhere else. Outside this window the
    # high-water is None and every canonicalised clause order stays canonical.
    _SYM_TABLE_HI = -1
    try:
        out, _ = _walk_block(sec.statements, 0, len(sec.statements), eff,
                             code_base=code_base)
    finally:
        _MENU_SHIFTED_BLOCK = outer
        _PAYLOAD_CODEC = prev_codec
        _SYM_TABLE_HI = prev_hi
    return out if keep_marks else _strip_verbatim_marks(out)


def _class_header_line(ident):
    line = "DEFINE CLASS %s AS %s" % (ident.name, ident.as_base)
    if ident.olepublic:
        line += " OLEPUBLIC"
    return line


def _is_class_init_section(sec):
    leads = (bytes([S.CLASS_INIT_METHOD]),
             bytes([S.CLASS_INIT_PROTECTED]),
             bytes([S.CLASS_INIT_HIDDEN]))
    return any(s.text is None and s.stream[:1] in leads
               for s in sec.statements)


def _method_index_count(sec):
    leads = (bytes([S.CLASS_INIT_METHOD]),
             bytes([S.CLASS_INIT_PROTECTED]),
             bytes([S.CLASS_INIT_HIDDEN]))
    return sum(1 for st in sec.statements if st.stream[:1] in leads)


# Hits include LINENO() and LINENO(1) so a rewrite of an earlier fold does
# not drop it from the pairing. Replacement still targets the bare call.
_LN_HIT_RE = _re.compile(r"\bLINENO\s*\(\s*(?:1)?\s*\)", _re.I)
_LN_BARE_RE = _re.compile(r"\bLINENO\s*\(\s*\)", _re.I)


def _lineno_stored(mod):
    """Stored u32 of every folded LINENO in module order, strings skipped."""
    out = []
    for sec in mod.sections:
        if sec.is_empty:
            continue
        for st in sec.statements:
            buf = st.stream or b""
            i, n = 0, len(buf)
            while i < n:
                b = buf[i]
                if b in (0xFB, 0xD9) and i + 3 <= n:
                    ln = int.from_bytes(buf[i + 1:i + 3], "little")
                    if i + 3 + ln <= n:
                        i += 3 + ln
                        continue
                if b == S.INT32 and i + 6 <= n:
                    d = buf[i + 1]
                    v = _struct.unpack_from("<i", buf, i + 2)[0]
                    if d == _LINENO_ESCAPE and 0 <= v <= _INT16_LITERAL_MAX:
                        out.append(v)
                    i += 6
                    continue
                i += 1
    return out


def _lineno_hits(lines):
    hits = []
    for i, ln in enumerate(lines):
        for _ in _LN_HIT_RE.finditer(ln):
            hits.append(i)
    return hits


def _proc_line(lines, idx):
    """1-based PROCEDURE/FUNCTION line at or before idx, or None."""
    for j in range(idx, -1, -1):
        s = lines[j].lstrip().upper()
        if s.startswith("PROCEDURE ") or s.startswith("FUNCTION "):
            return j + 1
        if (s.startswith("ENDPROC") or s.startswith("ENDFUNC")
                or s.startswith("ENDDEFINE")):
            return None
    return None


def _place_lineno(lines, mod):
    """Put each fold-bearing statement on its stored line (r67-lineno).

    LINENO() counts 1-based program lines; LINENO(1) counts the procedure
    body with PROCEDURE excluded. Blanks are inserted before the statement
    when the reconstruction is behind. Ahead is a named refusal.
    """
    stored = _lineno_stored(mod)
    if not stored:
        return lines
    lines = list(lines)
    for i, S in enumerate(stored):
        hits = _lineno_hits(lines)
        if len(hits) != len(stored) or i >= len(hits):
            break
        P = hits[i] + 1
        proc = _proc_line(lines, hits[i])
        body = None if proc is None else P - proc
        can_file = S >= P
        can_body = proc is not None and body is not None and S >= body
        if can_file and (not can_body or (S - P) <= (S - body)):
            pad, form = S - P, "()"
        elif can_body:
            pad, form = S - body, "(1)"
        else:
            raise Unsupported(
                "lineno_reconstruction_ahead: stored %d at reconstructed "
                "line %d" % (S, P))
        if form == "(1)":
            lines[hits[i]] = _LN_BARE_RE.sub("LINENO(1)", lines[hits[i]],
                                             count=1)
        if pad:
            lines[hits[i]:hits[i]] = [""] * pad
    return lines


def lift_program(mod):
    """Lift every section of a parsed module into one source.

    Class modules (r43-fxphdr post-section directory) emit DEFINE CLASS
    <name> AS <base> [OLEPUBLIC] around members. Procedure bodies become
    PROCEDURE <name> when the method directory in front of class-init
    supplies names; PROTECTED/HIDDEN follow the 0xa3/0x9e index. 0xa2/0xa3/0x9e
    class-init index statements have no source line. Non-class modules pair
    procedure-directory names against every section, including empty
    PROCEDURE bodies (r44-stmtcount).
    """
    span_end = mod.extent if mod.extent else len(mod.data)
    ids = class_identities(mod.data, mod.offset, span_end)
    if not ids:
        procs = procedure_names(mod.data, mod.offset, span_end)
        secs = list(mod.sections)
        nonempty = [sec for sec in secs if not sec.is_empty]
        out = []
        # r61-binding: the record's OWN directory binds each name to one
        # section by its u32 (r43-G3, r48-nonames), so wherever every entry
        # binds, that IS the pairing and a count arm that happens to match
        # cannot outrank it. Measured on `fondo.FXP#0`: 536 declared members,
        # an arm matches on the non-empty count and pairs the names one section
        # early, while the record's directory names an EMPTY member section in
        # the middle of the run. A section the directory does not name stays
        # module body, which is also what keeps an unclaimed section from being
        # dropped instead of emitted.
        bound = ({o + PROLOGUE_BASE: n for n, o in
                  procedure_directory(mod.data, mod.offset, span_end)}
                 if procs else {})
        # Pair names against every section, including empty PROCEDURE
        # bodies (r44-stmtcount: Activate compiles to an empty section).
        # Nonempty-only matching concatenates those bodies into one
        # program and is the table-path statement_count family.
        if bound:
            main = [sec for sec in secs if sec.offset not in bound]
            named = [sec for sec in secs if sec.offset in bound]
            procs = [bound[sec.offset] for sec in named]
        elif procs and len(procs) == len(secs):
            main, named = [], secs
        elif procs and len(procs) == len(secs) - 1:
            main, named = [secs[0]], secs[1:]
        elif procs and len(procs) == len(nonempty):
            main, named = [], nonempty
        elif procs and len(procs) == len(nonempty) - 1:
            main, named = [nonempty[0]], nonempty[1:]
        elif not procs and len(secs) > 2 and secs[0].is_empty:
            # r47-nonames: a form record's OBJCODE can carry a section
            # directory and NO procedure-name directory at all. Concatenating
            # every section into one body writes a different program: the
            # sections merge and every statement count moves, which is the
            # table-path statement_count family this arm closes. A procedure's
            # NAME never reaches its section's frames, so the sections pair
            # positionally against synthetic names — section 0 is the module
            # body and a trailing empty is the footer false section.
            body = secs[1:-1] if secs[-1].is_empty else secs[1:]
            main, named = [secs[0]], body
            # r48-nonames: the directory IS in the record, behind the empty
            # footer section the last-section scan stops at, and each entry's
            # u32 binds it to a section offset. Names are read off that binding;
            # a record that really carries none keeps the synthetic naming.
            bound = dict(
                (o + PROLOGUE_BASE, n)
                for n, o in procedure_directory(mod.data, mod.offset, span_end))
            procs = [bound.get(sec.offset) or "_m%d" % (i + 1)
                     for i, sec in enumerate(body)]
        elif procs:
            # r57-procdir: the four counts above are the shapes an authored PRG
            # takes, and a record carrying a false section beyond the leading
            # pad matches none of them. What this arm did then was set
            # procs = [] and concatenate the bodies, so every declared member
            # left NO trace — not a header, not a placeholder, not a refusal.
            # Reaching here means the record declares members and the binding
            # above found none, so rule 26 gets a NAMED refusal; what it
            # forbids is silence.
            raise Unsupported(
                "procedure directory unbound: %d declared members over "
                "%d sections (%d non-empty) bind to none of them"
                % (len(procs), len(secs), len(nonempty)))
        else:
            # A module that declares no members at all is a plain program and
            # falls here legitimately: its sections ARE the body.
            main, named, procs = nonempty, [], []
        for sec in main:
            out.extend(lift_section(sec))
        for sec, name in zip(named, procs):
            out.append("PROCEDURE %s" % name)
            out.extend(ln for ln in lift_section(sec, keep_marks=True)
                       if _blank_or_payload(ln))
            out.append("ENDPROC")
        if not out:
            for si, sec in enumerate(mod.sections):
                out.append("* --- section %d%s ---" % (
                    si, " (empty)" if sec.is_empty else ""))
                out.extend(lift_section(sec))
        return _place_lineno(_strip_verbatim_marks(out), mod)
    nclass = len(ids)
    secs = list(mod.sections)
    if not secs:
        out = []
        for ident in ids:
            out.append(_class_header_line(ident))
            out.append("ENDDEFINE")
        return _strip_verbatim_marks(out)
    top, rest = [], secs
    if secs[0].statements and not _is_class_init_section(secs[0]):
        # mixed: top-level code then the class
        top = lift_section(secs[0])
        rest = secs[1:]
    elif secs[0].is_empty:
        rest = secs[1:]
    # r57-classinit: the class-init sections are the last nclass sections of
    # the module counting EMPTY ones — a class with no methods and no PEM
    # assignments spends an EMPTY class-init, and it is still spent and still
    # in class order. `class_init_offsets` applies that rule and tells a real
    # empty class-init from the FXP footer phantom the way class_identities
    # already does: the class directory sits behind the last class-init.
    init_offs = set(class_init_offsets(mod.data, mod.offset, span_end))
    # r46-classinit: drop a trailing phantom empty (footer false section)
    # when rest already has a nonempty member. Keep a lone trailing empty
    # — that is an empty class with no methods (mixed top-level + class) —
    # and keep one the rule above says is a class-init.
    if (rest and rest[-1].is_empty and any(not s.is_empty for s in rest[:-1])
            and rest[-1].offset not in init_offs):
        rest = rest[:-1]
    rest_ne = [s for s in rest if not s.is_empty]
    inits = [s for s in rest if s.offset in init_offs]
    if len(inits) != nclass:
        inits = rest_ne[-nclass:] if len(rest_ne) >= nclass else []
    if inits:
        # r47-emptymethod: a method with an empty body still occupies a section
        # in source order and still spends its class-init a2 index, so an empty
        # section inside the body region is a method slot. Dropping it renames
        # every later method by one and leaves the last class short of bodies.
        # r51-emptymethod: the same holds for a LEADING empty, which r47 read
        # as module padding without measuring it. The class-init indices say
        # how many members the body region holds, so only the SURPLUS over that
        # count is padding — measured over every position an empty body can
        # take, with and without top-level code in front of the class, under
        # PROTECTED and HIDDEN, and across two classes in one module. Reading
        # the whole run as padding drops the first member of any class whose
        # first method is empty and renames every later one.
        first_init = next(i for i, sec in enumerate(rest) if sec is inits[0])
        slots = sum(_method_index_count(sec) for sec in inits)
        lead = 0
        while lead < first_init - slots and rest[lead].is_empty:
            lead += 1
        procs = rest[lead:first_init]
    else:
        inits, procs = rest_ne, []
    counts = [_method_index_count(sec) for sec in inits]
    split_procs = []
    i = 0
    for n in counts:
        split_procs.append(procs[i:i + n])
        i += n
    leftover_procs = procs[i:]
    while len(split_procs) < nclass:
        split_procs.append([])
    out = list(top)
    index_leads = (bytes([S.CLASS_INIT_METHOD]),
                   bytes([S.CLASS_INIT_PROTECTED]),
                   bytes([S.CLASS_INIT_HIDDEN]))
    for ci, ident in enumerate(ids):
        out.append(_class_header_line(ident))
        methods = list(ident.methods)
        vis = list(ident.method_vis)
        init = inits[ci] if ci < len(inits) else None
        pem_lines = []
        pem_before = False
        if init is not None:
            pem_lines = [ln for ln in lift_section(init, keep_marks=True)
                         if _blank_or_payload(ln)]
            # r46-classinit: HEIGHT= before PROCEDURE compiles to 54 then a2;
            # PROCEDURE then HEIGHT compiles to a2 then 54. Emit PEMs first
            # when the class-init section starts with a non-index statement.
            if init.statements and init.statements[0].stream[:1] not in index_leads:
                pem_before = True
        if pem_before:
            out.extend(pem_lines)
        for pi, psec in enumerate(split_procs[ci] if ci < len(split_procs) else []):
            body = [ln for ln in lift_section(psec, keep_marks=True)
                    if _blank_or_payload(ln)]
            name = methods[pi] if pi < len(methods) else ("_m%d" % (pi + 1))
            prefix = (vis[pi] + " ") if pi < len(vis) and vis[pi] else ""
            out.append("%sPROCEDURE %s" % (prefix, name))
            out.extend(body)
            out.append("ENDPROC")
        if not pem_before:
            out.extend(pem_lines)
        out.append("ENDDEFINE")
    if leftover_procs:
        used = {n for ident in ids for n in ident.methods}
        extra_names = []
        if secs:
            prev = secs[-nclass - 1] if len(secs) > nclass else None
            if prev is not None:
                extra_names = [
                    n for n in _method_names(
                        mod.data, prev.end + 2, inits[0].offset)
                    if n not in used
                ]
        for pi, psec in enumerate(leftover_procs):
            body = [ln for ln in lift_section(psec, keep_marks=True)
                    if _blank_or_payload(ln)]
            name = extra_names[pi] if pi < len(extra_names) else (
                "_m%d" % (pi + 1))
            out.append("PROCEDURE %s" % name)
            out.extend(body)
            out.append("ENDPROC")
    return _place_lineno(_strip_verbatim_marks(out), mod)


def _walk_block(stmts, i, stop, syms, stops=frozenset(), code_base=None,
                stop_rel=None):
    """Emit stmts[i:stop]. Stops BEFORE any statement whose lead is in ``stops`` (the
    caller consumes it) and fails if a required sentinel never appears.

    ``stop_rel`` stops before the statement at that code-base distance whatever
    its lead. A DO CASE clause's own trailer names the next mark of its bank
    (r54-macrocase), and a mark stored verbatim carries no lead to test — the
    distance is the only thing that identifies it."""
    out = []
    while i < stop:
        s = stmts[i]
        if stop_rel is not None and s.offset - code_base == stop_rel:
            return out, i
        if s.text is not None:
            # r42-macrocp: 01/b4 payload follows the table codec, same as
            # fb/d9 (I11). .text is the latin-1 byte carrier; emit the codec view.
            vtext = _payload_text(s.raw_text) if s.raw_text is not None else s.text
            if s.jump_rel is None:
                out.append(_emit_line(Verbatim(vtext)))
                i += 1
                continue
            # MEASURED framed verbatim block opener (docs/VERBATIM.md, n=35 dev-draw
            # statements): <u16> 01 <line> f9 05 <u16>. The trailer anchors to the
            # post-prologue code base exactly like a compiled 25-opener: distance to the
            # matching depth-0 ELSE (4 measured: mainmenu.scx::Command5,
            # bincode20161212.scx::Command4, mainmenu20131117.scx::Command8,
            # snake.scx::TmrColl) or bare 1e ENDIF (23 measured). A target that misses
            # both is corruption — Unsupported, never guessed around.
            v_ast = Verbatim(vtext, jump_rel=s.jump_rel)
            # r49-residual: a macro statement is stored verbatim and never
            # compiled, so a macro-opened block leaves NO opener frame while
            # its closer is compiled as usual — `SCAN ALL FOR &cond` is
            # `01 <line> f9 05 <u16>` and its ENDSCAN a plain 7f. The walk
            # therefore pairs a framed verbatim opener with whichever block
            # sentinel its own jump target lands on, and that target check is
            # what keeps a real orphan sentinel a hard error.
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops=_VERBATIM_BLOCK_CLOSERS,
                                  code_base=code_base)
            want = stmts[j].offset - code_base
            if s.jump_rel != want:
                raise Unsupported(
                    "verbatim-if jump target %d != %s code-base distance %d"
                    % (s.jump_rel,
                       "ELSE" if stmts[j].stream[0] == S.ELSE_LEAD else "ENDIF",
                       want))
            v_ast.closer = _VERBATIM_BLOCK_CLOSERS[stmts[j].stream[0]]
            v_ast.body = body
            if stmts[j].stream[0] == S.ELSE_LEAD:
                else_stmt = stmts[j]
                _, else_target = dec_statement(else_stmt.stream, syms)
                v_ast.else_target = else_target
                body2, k = _walk_block(stmts, j + 1, stop, syms,
                                       stops={S.ENDIF_LEAD}, code_base=code_base)
                v_ast.else_body = body2
                want_end = stmts[k].offset - code_base
                if else_target != want_end:
                    raise Unsupported(f"else jump target {else_target} != ENDIF "
                                      f"code-base distance {want_end}")
                i = k + 1
            else:
                i = j + 1
            out.extend(_emit_line(v_ast).split("\n"))
            continue
        lead = s.stream[0]
        if lead in stops:
            return out, i
        if lead in (S.ENDWITH, S.ENDIF_LEAD, S.ELSE_LEAD, S.ENDCASE_LEAD,
                    S.CASE_CLAUSE, S.ENDDO_LEAD, S.ENDFOR_LEAD,
                    S.ENDEACH_LEAD,
                    S.CATCH_LEAD, S.ENDTRY_LEAD, S.ENDTEXT_LEAD):
            # a sentinel for a frame type we are not inside — never emit it
            raise Unsupported("block sentinel without its opener")
        if lead == S.STR:
            # fb-led statements are verbatim TEXT-frame body lines (round-23);
            # outside that frame their meaning is unmeasured and stays rejected
            raise Unsupported("verbatim text line outside a TEXT frame")
        if lead == S.WITH:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDWITH}, code_base=code_base)
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.TEXT_LEAD:
            # TEXT frame: body lines are standalone verbatim fb statements, each
            # `fb <u16 len excluding newline> <bytes>` (round-23 FORCED); the
            # length field is attacker-shaped data and must degrade to Unsupported
            # on any overrun or mismatch. Closed by the standalone 1f sentinel.
            ast = dec_statement(s.stream, syms)
            j = i + 1
            while True:
                if j >= stop:
                    raise Unsupported("TEXT frame left open")
                sj = stmts[j]
                if sj.text is None and sj.stream == bytes([S.ENDTEXT_LEAD]):
                    break
                b = sj.stream if sj.text is None else b""
                if len(b) < 3 or b[0] != S.STR \
                        or 3 + int.from_bytes(b[1:3], "little") != len(b):
                    raise Unsupported("non-verbatim statement inside TEXT frame")
                ast.body.append(TextLine(_payload_text(b[3:])))
                j += 1
            block = _emit_line(ast).split("\n")
            # r47-textblock: the body lines between the TEXT header and ENDTEXT
            # ARE their stored payloads; an enclosing block must not indent them.
            out.extend(block[:1]
                       + [VERBATIM_MARK + x for x in block[1:1 + len(ast.body)]]
                       + block[1 + len(ast.body):])
            i = j + 1
            continue
        if lead == S.TRY_LEAD:
            # TRY frame walk: measured forms only; the measured target rides on
            # statement decoding and is verified against the bound sentinel.
            #   TRY     ba f9 05 <u16>   target = NEXT clause mark - code_base:
            #                            the CATCH prefix when one follows, else
            #                            the FINALLY prefix (measured pimutilselect
            #                            cmdPrint / forest FrmSmartSystem), else
            #                            the ENDTRY prefix
            #   CATCH   bb f9 05 <u16>   target = NEXT clause mark - code_base:
            #                            the FINALLY prefix when one follows, else
            #                            the ENDTRY prefix (measured _reportlistener)
            #   CATCH WHEN bb d2 fc <cond> fd f9 05 <u16>
            #   CATCH TO   bb 28 (f7 <sym> | f5 0d f7 <sym>) f9 05 <u16>
            #   CATCH TO..WHEN (combined clause form, foxchartsbeta s14)
            #   FINALLY bc f9 05 <u16>   target = matching ENDTRY prefix - code_base
            #   ENDTRY  be
            try_ast = dec_statement(s.stream, syms)
            try_rel = try_ast.target
            depth = 0
            catch_at = None
            finally_at = None
            end_at = None
            j = i + 1
            while j < stop:
                sj = stmts[j]
                if sj.text is not None:
                    j += 1
                    continue
                lj = sj.stream[0]
                if lj == S.TRY_LEAD:
                    depth += 1                      # nested TRY binds its own pair
                elif lj == S.CATCH_LEAD:
                    if depth == 0:
                        if catch_at is not None:
                            raise Unsupported("multiple CATCH clauses")
                        catch_at = j
                elif lj == S.FINALLY_LEAD:
                    if depth == 0:
                        if finally_at is not None:
                            raise Unsupported("multiple FINALLY clauses")
                        finally_at = j
                elif lj == S.ENDTRY_LEAD:
                    if depth == 0:
                        end_at = j
                        break
                    depth -= 1
                j += 1
            if end_at is None:
                raise Unsupported("TRY without ENDTRY")
            if finally_at is not None and catch_at is not None \
                    and finally_at < catch_at:
                raise Unsupported("FINALLY precedes CATCH")
            # MEASURED (round-35, pimutilselect cmdPrint / forest FrmSmartSystem):
            # with no CATCH the TRY word binds the FINALLY prefix when one follows
            # (TRY@0 t=616 -> FINALLY@616 -> ENDTRY@624; forest identical +8), so
            # the opener targets its NEXT clause mark exactly as in the CATCH rule.
            if catch_at is not None:
                bound_at = catch_at
            elif finally_at is not None:
                bound_at = finally_at
            else:
                bound_at = end_at
            bound_off = stmts[bound_at].offset - code_base
            if try_rel != bound_off:
                raise Unsupported(
                    "TRY target %d != %s code-base distance %d"
                    % (try_rel,
                       "CATCH" if catch_at is not None
                       else ("FINALLY" if finally_at is not None else "ENDTRY"),
                       bound_off))
            # the depth-scan already located every depth-0 sentinel, so plain
            # index bounds are authoritative here (a stops-list would trip the
            # frame-left-open guard when the sentinel IS the boundary index)
            body = _walk_block(stmts, i + 1, bound_at, syms,
                               code_base=code_base)[0]
            ast = TryStmt(body)
            ast.target = try_rel
            end_off = stmts[end_at].offset - code_base
            if catch_at is not None:
                # the measured target rides on statement decoding (bare, WHEN and
                # TO forms alike); the walker verifies it against its clause mark
                catch_ast = dec_statement(stmts[catch_at].stream, syms)
                if not isinstance(catch_ast, CatchWhen):
                    raise Unsupported(
                        "unsupported CATCH form (TO / FINALLY-adjacent)")
                handler_end = finally_at if finally_at is not None else end_at
                want_catch = stmts[handler_end].offset - code_base
                if catch_ast.target != want_catch:
                    raise Unsupported(
                        "CATCH target %d != %s code-base distance %d"
                        % (catch_ast.target,
                           "FINALLY" if finally_at is not None else "ENDTRY",
                           want_catch))
                handler, _ = _walk_block(stmts, catch_at + 1, handler_end, syms,
                                         code_base=code_base)
                ast.catch_cond = catch_ast.cond
                ast.catch_var = catch_ast.var
                ast.catch_body = handler
                ast.catch_target = catch_ast.target
            if finally_at is not None:
                fin_ast = dec_statement(stmts[finally_at].stream, syms)
                if not isinstance(fin_ast, FinallyClause):
                    raise Unsupported("unsupported FINALLY clause")
                if fin_ast.target != end_off:
                    raise Unsupported(
                        "FINALLY target %d != ENDTRY code-base distance %d"
                        % (fin_ast.target, end_off))
                fin_body, _ = _walk_block(stmts, finally_at + 1, end_at, syms,
                                          code_base=code_base)
                ast.finally_body = fin_body
            out.extend(_emit_line(ast).split("\n"))
            i = end_at + 1
            continue
        if lead == S.FOR_LEAD:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDFOR_LEAD}, code_base=code_base)
            want_end = stmts[j].offset - code_base
            if ast.rel_target != want_end:
                raise Unsupported(f"for jump target {ast.rel_target} != ENDFOR "
                                  f"code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.FOR_EACH_LEAD:
            # FOR EACH frame walk: body runs until the matching bare ENDEACH;
            # the opener's jump word is verified against the ENDEACH code-base
            # distance (held at every corpus occurrence)
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDEACH_LEAD}, code_base=code_base)
            want_end = stmts[j].offset - code_base
            if ast.rel_target != want_end:
                raise Unsupported(f"for-each jump target {ast.rel_target} != "
                                  f"ENDEACH code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.DO_CASE_LEAD and s.stream[1] == S.DOWHILE_MARK:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDDO_LEAD}, code_base=code_base)
            want_end = stmts[j].offset - code_base
            if ast.rel_target != want_end:
                raise Unsupported(f"do-while jump target {ast.rel_target} != ENDDO "
                                  f"code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.SCAN_LEAD:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDSCAN_LEAD}, code_base=code_base)
            # Round-32 corruption guard: on the measured 2b (WHILE) frames the
            # trailing locator word binds as ENDSCAN prefix - code_base; a
            # mismatch is corruption and stays Unsupported. Legacy 03/13 frames
            # carry rel_target None by policy (see ScanStmt) and are not checked.
            if getattr(ast, "rel_target", None) is not None:
                want_end = stmts[j].offset - code_base
                if ast.rel_target != want_end:
                    raise Unsupported(f"scan jump target {ast.rel_target} != "
                                      f"ENDSCAN code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.ENDSCAN_LEAD:
            raise Unsupported("block sentinel without its opener")
        if lead == S.PRINTJOB_LEAD:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ENDPRINTJOB_LEAD},
                                  code_base=code_base)
            want_end = stmts[j].offset - code_base
            if ast.rel_target != want_end:
                raise Unsupported(f"printjob jump target {ast.rel_target} != "
                                  f"ENDPRINTJOB code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        if lead == S.ENDPRINTJOB_LEAD:
            raise Unsupported("block sentinel without its opener")
        if lead == S.DO_CASE_LEAD and len(s.stream) > 1 \
                and s.stream[1] == S.DO_CASE_FRAME_MARK:
            # second byte 0x48 (DO_CASE_FRAME_MARK) marks the DO CASE frame
            # subtype (dec_statement's measured split); every other 0x18 stream
            # is a plain DO <program> call and must fall through to the generic
            # statement handler
            ast = dec_statement(s.stream, syms)
            if ast.t_first == ast.t_end:
                # MEASURED zero-width region (round-35, pidocchk CdQuery s0
                # stmt28 <-> stored L34/L35 'DO CASE / DO CASE'): equal opener
                # words are the frame's own ENDCASE prefix - code_base (1759
                # both), so the region holds no clauses; only complete nested
                # frames may sit before that ENDCASE. Anything else at region
                # top level keeps the stray-statement verdict, and a closer at
                # any other distance stays loud.
                depth = 0
                end_at = None
                j = i + 1
                while j < stop:
                    sj = stmts[j]
                    if sj.text is None:
                        lj = sj.stream[0]
                        if lj == S.DO_CASE_LEAD and len(sj.stream) > 1 \
                                and sj.stream[1] == S.DO_CASE_FRAME_MARK:
                            depth += 1      # a nested case binds its own ENDCASE
                        elif lj == S.ENDCASE_LEAD:
                            if depth == 0:
                                end_at = j
                                break
                            depth -= 1
                        elif depth == 0:
                            raise Unsupported(
                                "unexpected statement inside DO CASE")
                    elif depth == 0:
                        # verbatim lines ride no clause region of their own
                        raise Unsupported("unexpected statement inside DO CASE")
                    j += 1
                if end_at is None:
                    raise Unsupported("DO CASE without ENDCASE")
                want_end = stmts[end_at].offset - code_base
                if ast.t_end != want_end:
                    raise Unsupported(f"do-case end target {ast.t_end} != "
                                      f"ENDCASE distance {want_end}")
                ast.body = _walk_block(stmts, i + 1, end_at, syms,
                                       code_base=code_base)[0]
                out.extend(_emit_line(ast).split("\n"))
                i = end_at + 1
                continue
            collected = []                      # (clause, stmt) in order
            otherwise_body = None
            oth_off = None                      # OTHERWISE mark, when one follows
            pos = i + 1
            while True:
                if pos >= stop:
                    raise Unsupported("DO CASE without ENDCASE")
                s2 = stmts[pos]
                if s2.text is None and s2.stream[0] == S.ENDCASE_LEAD:
                    break
                if s2.text is None and s2.stream[0] == S.OTHERWISE_LEAD:
                    oth_off = s2.offset - code_base
                    oth = dec_statement(s2.stream, syms)
                    otherwise_body, pos = _walk_block(
                        stmts, pos + 1, stop, syms,
                        stops={S.ENDCASE_LEAD}, code_base=code_base,
                        stop_rel=oth.rel_target)
                    want_oth = stmts[pos].offset - code_base
                    if oth.rel_target != want_oth:
                        raise Unsupported(f"otherwise jump target {oth.rel_target} "
                                          f"!= ENDCASE distance {want_oth}")
                    break
                if s2.text is not None:
                    # MEASURED (r54-macrocase, 20/20): a CASE whose condition
                    # holds a macro is never compiled — the line is stored
                    # verbatim and carries the SAME f9 05 trailer a 0c mark
                    # carries, aimed at the same next mark. An UNFRAMED
                    # verbatim line has no trailer and so is not a clause.
                    if s2.jump_rel is None:
                        raise Unsupported("unexpected statement inside DO CASE")
                    vtext = (_payload_text(s2.raw_text)
                             if s2.raw_text is not None else s2.text)
                    clause = CaseClause(None, [], rel_target=s2.jump_rel,
                                        verbatim=vtext)
                elif s2.stream[0] != S.CASE_CLAUSE:
                    # stray statement between clauses: unforced shape
                    raise Unsupported("unexpected statement inside DO CASE")
                else:
                    clause = dec_statement(s2.stream, syms)
                # MEASURED: a clause's false-jump lands on its NEXT clause mark.
                # Verify the PREVIOUS clause now that its successor is known.
                if collected:
                    prev_c = collected[-1][0]   # collected holds (clause, stmt)
                    want_prev = s2.offset - code_base
                    if prev_c.rel_target != want_prev:
                        raise Unsupported(f"case jump target {prev_c.rel_target} != "
                                          f"next-clause distance {want_prev}")
                body, pos2 = _walk_block(stmts, pos + 1, stop, syms,
                                         stops={S.CASE_CLAUSE, S.OTHERWISE_LEAD,
                                                S.ENDCASE_LEAD},
                                         code_base=code_base,
                                         stop_rel=clause.rel_target)
                clause.body = body
                collected.append((clause, s2))
                pos = pos2
            if not collected:
                raise Unsupported("DO CASE without any CASE clause")
            last_c = collected[-1][0]
            # MEASURED: the last clause obeys the same next-clause-mark rule —
            # its false-jump targets the OTHERWISE mark when one follows, else
            # the ENDCASE mark (9 corpus methods; never "any target").
            want_last = (oth_off if oth_off is not None
                         else stmts[pos].offset - code_base)
            if last_c.rel_target != want_last:
                raise Unsupported(f"case jump target {last_c.rel_target} != "
                                  f"{'OTHERWISE' if oth_off is not None else 'ENDCASE'} "
                                  f"distance {want_last}")
            want_first = stmts[i + 1].offset - code_base
            if ast.t_first != want_first:
                raise Unsupported(f"do-case first target {ast.t_first} != "
                                  f"first CASE distance {want_first}")
            want_end = stmts[pos].offset - code_base
            if ast.t_end != want_end:
                raise Unsupported(f"do-case end target {ast.t_end} != ENDCASE "
                                  f"distance {want_end}")
            ast.clauses = collected
            if otherwise_body is not None:
                ast.otherwise_body = otherwise_body
            out.extend(_emit_line(ast).split("\n"))
            i = pos + 1
            continue
        if lead == S.IF_LEAD:
            ast = dec_statement(s.stream, syms)
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ELSE_LEAD, S.ENDIF_LEAD},
                                  code_base=code_base)
            has_else = stmts[j].stream[0] == S.ELSE_LEAD
            if has_else:
                else_stmt = stmts[j]
                _, else_target = dec_statement(else_stmt.stream, syms)
                want_else = else_stmt.offset - code_base
                if ast.rel_target != want_else:
                    raise Unsupported(f"if jump target {ast.rel_target} != ELSE "
                                      f"code-base distance {want_else}")
                ast.else_target = else_target
                ast.body = body
                body2, k = _walk_block(stmts, j + 1, stop, syms,
                                       stops={S.ENDIF_LEAD}, code_base=code_base)
                ast.else_body = body2
                want_end = stmts[k].offset - code_base
                if else_target != want_end:
                    raise Unsupported(f"else jump target {else_target} != ENDIF "
                                      f"code-base distance {want_end}")
                out.extend(_emit_line(ast).split("\n"))
                i = k + 1
                continue
            # CORRECTION (iter. 20): ALL frame targets anchor to the post-prologue
            # code base — ground truth 103/103 IF pairs (the earlier statement-relative
            # reading came from a 4-sample measurement where IFs happened to sit at the
            # section head, making both anchors coincide)
            want_end = stmts[j].offset - code_base
            if ast.rel_target != want_end:
                raise Unsupported(f"if jump target {ast.rel_target} != ENDIF "
                                  f"code-base distance {want_end}")
            ast.body = body
            out.extend(_emit_line(ast).split("\n"))
            i = j + 1
            continue
        ast = dec_statement(s.stream, syms)
        if isinstance(ast, ClassMethodIndex):
            i += 1
            continue
        out.append(_emit_line(ast))
        i += 1
    if stops:
        raise Unsupported("block frame left open")
    return out, i




# ---------- emitter ------------------------------------------------------------------------------
_BUILTIN_TABLES = {
    "builtin": S.BUILTIN_ESCAPES,
    "bare_builtin": S.BUILTIN_BARE,
    "x1a_builtin": S.BUILTIN_X1A,
}


def _emit_vfp_string(text, dq):
    """VFP string literal. r44-codepage (vmlock r44-codepage):

    `''''` does not compile (two empty strings). A lone quote is `[']`
    (fb 01 00 27, same as the bracket probe). CJK stays in the Python str for
    gbk encode at METHODS write.

    r47-gbkstring: a high-byte (GBK) payload that also contains brackets
    compiles cleanly QUOTED — single or double — and the fb/d9 payload is then
    the source bytes verbatim. What r44-codepage measured as failing on that
    charset was the BRACKET delimiter, which this function only ever reaches
    for a lone quote (a one-character text with no high bytes). Spelling such
    a literal as a CHR() chain instead wrote a call run where the wire holds a
    string literal, so the chain is gone.
    """
    if text == "'":
        # r46-quote: d9 01 00 27 is "'" (q_squote); fb 01 00 27 is ['].
        # Collapsing both to ['] costs the mainmenu WORKER-concat frames.
        if dq:
            return "\"'\""
        return "[']"
    # VFP has no escape inside a literal: the delimiter must be a character
    # the payload does not contain. Prefer the one the wire recorded, then the
    # other quote, then brackets.
    if dq and '"' not in text:
        return '"' + text + '"'
    if not dq and "'" not in text:
        return "'" + text + "'"
    if '"' not in text:
        return '"' + text + '"'
    if "'" not in text:
        return "'" + text + "'"
    if "[" not in text and "]" not in text:
        return "[" + text + "]"
    # No delimiter spells this payload — a quote, an apostrophe and a bracket
    # all occur in it (gridtree.vcx KeyPress charset). VFP cannot write it as
    # one literal at all, so the CHR() chain is the only source that compiles.
    return " + ".join(
        ("CHR(%d)" % ord(c)) if ord(c) < 256 else _emit_vfp_string(c, dq)
        for c in text) or "''"


def _emit(node):
    if isinstance(node, ByrefSym):
        # r38 M1/M2: '@' + name exactly — never a paren form ('@(' is
        # compiler-rejected, a0005) and never a bare '@' (a0006).
        return "@" + node.name
    if isinstance(node, Sym):
        return node.name
    if isinstance(node, ArrayRef):
        o, c = ("[", "]") if node.bracket else ("(", ")")
        return "%s%s%s%s" % (node.name, o,
                              ", ".join(_emit(x) for x in node.subs), c)
    if isinstance(node, MemberRef):
        return "THIS." + node.name
    if isinstance(node, WithRef):
        return "." + node.name
    if isinstance(node, WithMemberPath):
        return "." + ".".join(node.names)
    if isinstance(node, Num):
        # r38 M4/M5 emission case analysis. The width byte is source-spelling
        # provenance; canonical emission restores ONE measured spelling per
        # width class so identity recompiles reproduce the stored unit:
        #   decimal family  w == len(str(v)) incl sign/zeros (f1_lit, d0005
        #                   '00', b0006 '007') -> plain str(v);
        #   width 05, <=4 hexdigits -> pinned lowercase '0x%04x' (d0003/a0001/
        #                   b0003/b0005; stored f8 05 1a recompiles f8 05 1a);
        #   the ONE measured negative hex shape b0008 (-0x001A -> f9 06 e6ff);
        #   unpadded hex when w == hexdigit_count+1 and the decimal family
        #                   does not explain the wire (round-37 C01/C02,
        #                   probe A2 'qq = 0x100' -> f9 04) -> '0x%x';
        #   zero-padded decimal for positive values whose width exceeds their
        #                   plain decimal length otherwise (the measured law
        #                   that makes '007' ride 3 — the band the strict
        #                   equality would otherwise block, breaking coverage
        #                   neutrality);
        #   anything else raises Unsupported — never normalize silently, never
        #   guess the unmeasured 5..7-padded-hex band or other negative widths.
        w = node.width
        if w is None:
            return node.spelling
        v = int(node.spelling)
        dec = len(node.spelling)
        if w == dec:
            return node.spelling
        if v >= 0:
            if w == 5 and len("%x" % v) <= 4:
                return "0x%04x" % v
            if w == len("%x" % v) + 1:
                return "0x%x" % v
            if w > dec:
                return "%0*d" % (w, v)
        elif v == -26 and w == 6:
            return "-0x%04x" % abs(v)
        raise Unsupported(
            "f8/f9 literal width byte %d fits no measured spelling for "
            "value %s" % (w, node.spelling))
    if isinstance(node, Flt):
        # r41-C: restore the written spelling from the fa header (width, decimals).
        # Corpus-forced over the whole census: 1003 of 1003 fa literals that align
        # to their stored source agree on BOTH bytes — width is the literal's full
        # character count (a bare '.5' counts its implied leading zero, so the
        # canonical rendering is '0.5') and decimals is the digit count after the
        # point. So '0.00' rides fa 04 02 and '00000.00' rides fa 08 02, while the
        # incumbent repr() collapsed both to '0.0'.
        #
        # Where the header's own rendering does not fit its width, or is not
        # the canonical spelling of the stored double at the header's own
        # precision, the incumbent repr() stays.
        #
        # r48-foldmark: the round-trip test used to be `float(s) == v` alone,
        # which asks PYTHON to re-parse the token. That is not quite the right
        # comparator: VFP's own decimal parser is not correctly rounded, so the
        # stored double for '5.94' is one ulp below the one Python produces
        # (oracle: `x = 5.94` compiles fa 04 02 c2f5285c8fc21740) and a genuine
        # written literal was refused. One ulp is the whole tolerance — a
        # header whose rendering lands further away is describing a value the
        # token does not spell, and 104.16666666666667 under `fa 05 00` still
        # falls back rather than becoming '00104'.
        #
        # A MARKED literal (0xCC) is a value that was not a bare token. Where
        # the header spells one, re-parenthesising restores the marker; where
        # it does not, the header describes an arithmetic result and the
        # round-47 cap stands. `fa` is itself the DOUBLE literal, so a token
        # with no decimals whose value fits int32 compiles to an integer
        # opcode instead — such a spelling would write a different frame and is
        # refused.
        if node.width is None:
            return node.spelling
        v = float(node.spelling)
        s = "%0*.*f" % (node.width, node.decimals, v)
        fits = len(s) == node.width and (
            float(s) == v or abs(float(s) - v) <= _math.ulp(v))
        if fits and node.marked:
            fits = node.decimals > 0 or abs(v) > 2147483647
        if not fits:
            return node.spelling
        return "(%s)" % s if node.marked else s
    if isinstance(node, ByrefMemvarRef):
        # r41 a01: '@' + the m.-qualified name exactly — the paren form and
        # bare '@' are compiler-rejected m.-qualified too (e04/e05).
        return "@m." + node.name
    if isinstance(node, MemvarRef):
        return "m." + node.name
    if isinstance(node, WorkAreaRef):
        return node.letter
    if isinstance(node, QualField):
        return "%s.%s" % (node.letter, node.name)
    if isinstance(node, SqlAgg):
        return "%s(%s)" % (node.name, node.inner)
    if isinstance(node, MemberPath):
        return ".".join(node.names)
    if isinstance(node, IndexedMemberRef):
        # <obj>.<member>(<sub>).<prop> — round-22 v1/v2 PUT-target form
        o, c = ("[", "]") if getattr(node, "bracket", False) else ("(", ")")
        return "%s.%s%s%s%s.%s" % (node.obj, node.member, o,
                                   _emit(node.sub), c, node.prop)
    if isinstance(node, IndexedElemRef):
        # <arr>(<subs>).<prop> — round-28 e5 PUT-target form; the closer byte
        # decides '( … )' vs '[ … ]' exactly as on ArrayRef/LOCAL dims
        o, c = ("[", "]") if node.bracket else ("(", ")")
        txt = "%s%s%s%s" % (node.base, o,
                             ", ".join(_emit(x) for x in node.subs), c)
        if node.prop:
            txt += "." + node.prop
        return txt
    if isinstance(node, ObjectChain):
        # r40 group43: a chain link's receiver ROOT may itself be a completed
        # chain value ('loNodes.Item(lnNode)' under '.ChildNodes.Item(0)'),
        # so render non-string receiver elements the way MethodCall already
        # does. Every historical ObjectChain carries strings only, so this
        # cannot change an existing emission. The per-link bracket spelling
        # (r40 lane D) rides through unchanged.
        text = ".".join(p if isinstance(p, str) else _emit(p)
                        for p in node.recv)
        for n, (name, args) in enumerate(node.calls):
            o, c = ("[", "]") if _chain_bracket(node, n) else ("(", ")")
            text += "." + name + o + ", ".join(_emit(a) for a in args) + c
            hops = node.link_hops[n] if n < len(node.link_hops) else ()
            if hops:
                text += "." + ".".join(hops)
        if node.tail:
            text += "." + ".".join(node.tail)
        return text
    if isinstance(node, Str):
        return _emit_vfp_string(node.text, node.dq)
    if isinstance(node, Bool):
        return ".T." if node.value else ".F."
    if isinstance(node, Null):
        return ".NULL."
    if isinstance(node, BinHexLit):
        # Canonical 0h spelling: whole bytes, uppercase hex, empty literal stays "0h"
        # (all three recompile to the measured wire forms b1/b5/b6).
        return "0h" + node.payload.hex().upper()
    if isinstance(node, DateLit):
        if node.ymd is None:
            return "{}"
        return "{^%04d-%02d-%02d}" % node.ymd
    if isinstance(node, DateTimeLit):
        # The explicit time is what keeps the e6 opcode on recompile — midnight
        # datetimes exist on the wire (corpus {^1900.01.01,00:00:00} replicas).
        return "{^%04d-%02d-%02d %02d:%02d:%02d}" % (node.ymd + node.hms)
    if isinstance(node, CurrencyLit):
        return node.spelling
    if isinstance(node, EmptyArg):
        # omitted call-argument slot: empty between the commas (round-22 d2/d3/d4)
        return ""
    if isinstance(node, ByrefCall):
        # r38 M3/a0004: '@arr(subscript)' — '@' prefixes the whole call
        # spelling; no '@(' synthesis.
        return "@" + _emit(Call(node.func, node.args))
    if isinstance(node, Call):
        args = ", ".join(_emit(a) for a in node.args)
        kind, which = node.func
        if kind == "user":
            name = which
        else:
            table = _BUILTIN_TABLES.get(kind)
            if table is None:
                raise Unsupported(f"unknown builtin namespace {kind!r}")
            name = table.get(which)
        if name is None:
            raise Unsupported(f"builtin callee {kind} {which:#04x} unmapped")
        if kind == "x1a_builtin" and which == 0x0F:
            if len(node.args) != 2 or not isinstance(node.args[1], Str):
                raise Unsupported("CAST argument/type shape")
            return "CAST(%s AS %s)" % (_emit(node.args[0]), node.args[1].text)
        return "%s(%s)" % (name, args)
    if isinstance(node, MidCall):
        # round-27 args-before-receiver call VALUE: receiver names ride
        # verbatim (system-object roots, 'm.'-prefixed memvar roots), the
        # terminal property read is optional (s2/w1/w2/r3a have one, r5's
        # inner call feeds its enclosing receiver without one).
        open_b, close_b = ("[", "]") if getattr(node, "bracket", False) \
            else ("(", ")")
        text = "%s.%s%s%s%s" % (".".join(node.recv), node.name, open_b,
                                ", ".join(_emit(a) for a in node.args),
                                close_b)
        if node.prop is not None:
            text += "." + node.prop
        return text
    if isinstance(node, MethodCall):
        recv = ".".join(p if isinstance(p, str) else _emit(p) for p in node.recv)
        if node.recv_with:
            recv = "." + recv
        args = ", ".join(_emit(a) for a in node.args)
        if node.name:
            if not node.recv and node.recv_with:
                # r37-p8 blocking-defect repair (measured, canonical gate): a
                # WITH-scoped call on the WITH object itself ('e2 f6 <name>'
                # callee tail — '.Refresh()' / '.SetAll(...)' statements, 600
                # lifted population sections at the acc8b0f baseline) must
                # render ONE leading dot. The historical join emitted the
                # recv_with dot AND the format dot ('..SetAll(...)'), which is
                # not valid VFP: the abandoned P8 lane's oracle recompile of
                # its six released sections failed on exactly this corruption
                # (reproduced before implementation; see RECEIPT).
                return recv + node.name + "(%s)" % args
            return "%s.%s(%s)" % (recv, node.name, args)
        # empty-name call-form (iter. 44) — an indexed reference, so it carries
        # the source's own subscript spelling when the wire recorded one
        o, c = ("[", "]") if node.bracket else ("(", ")")
        return "%s%s%s%s" % (recv, o, args, c)
    if isinstance(node, ScopeRef):
        head = ".".join(list(node.hops) + [node.cls]) if node.hops else node.cls
        if node.args is None:
            return "%s::%s" % (head, node.member)
        return "%s::%s(%s)" % (head, node.member,
                               ", ".join(_emit(a) for a in node.args))
    if isinstance(node, ArrayElement):
        if node.method_receiver:
            raise Unsupported("array-element receiver without method callee")
        return "%s[%s]" % (_emit(node.base),
                           ", ".join(_emit(x) for x in node.subs))
    if isinstance(node, Mod):
        # r48-modulus: `a % b` and `MOD(a, b)` are ONE group on the wire,
        # `43 <a> <b> 47` — measured identical for leaf operands. An explicit
        # paren is a node of its own and costs an `03`, so the operator
        # spelling cannot reproduce a stored group whose operand is compound
        # and carries no `03`; and the unparenthesised operator spelling is
        # not the alternative, because `%` binds tighter than `-`
        # (`a - 1 % 28` is `a - MOD(1, 28)`, a different tree). Where an
        # operand would need parens the group is spelled MOD(...), which needs
        # none; where neither does, the incumbent `%` spelling stays.
        if _forces_paren(node.a, 6) or _forces_paren(node.b, 7):
            return "MOD(%s, %s)" % (_emit(node.a), _emit(node.b))
        return "%s %% %s" % (_side(node.a, 6), _side(node.b, 7))
    if isinstance(node, SqlSubquery):
        return (node.prefix + " " if node.prefix else "") + node.text
    if isinstance(node, Bin):
        p = _PREC[node.op]
        return "%s %s %s" % (_side(node.l, p), node.op, _side(node.r, p + 1))
    if isinstance(node, ShortCircuit):
        # r37 sql-closure: precedence-aware left side, symmetric with the
        # right. The stock unconditional wrap emitted phantom parens around
        # every non-leaf left operand ('(a = b) OR c', '((NOT x) OR y)'):
        # VFP records an explicit-paren marker 03 for each (oracle probes
        # s0004-s0007), so those spellings could never recompile to a stored
        # bare wire. Paren nodes keep their own measured parens via _side.
        left = _side(node.l, _PREC[node.op])
        return "%s %s %s" % (left, node.op, _side(node.r, _PREC[node.op]))
    if isinstance(node, Neg):
        # -y compiles bare per f6_una; forced parens would add an 03 marker the original lacks
        return "-" + _side(node.x, 8)
    if isinstance(node, Not):
        # NOT binds looser than comparisons in VFP: NOT y > 1 needs no inner parens
        return "NOT " + _side(node.x, 3)
    if isinstance(node, Paren):
        return "(%s)" % _emit(node.x)
    raise Unsupported(f"emitter node {type(node).__name__}")


def _forces_paren(node, min_prec):
    """True when `_side` would ADD parentheses this slot's precedence demands.

    An explicit Paren node is excluded: its parens are the ones the wire
    recorded, not ones the emitter is inventing."""
    return not isinstance(node, Paren) and _own_prec(node) < min_prec


def _side(node, min_prec):
    """Render a child, parenthesizing when its own precedence is below what this slot demands.
    Explicit Paren nodes always render with their parens (they carry measured provenance)."""
    txt = _emit(node)
    if not _forces_paren(node, min_prec):
        return txt
    return "(" + txt + ")"


def _own_prec(node):
    if isinstance(node, Bin):
        return _PREC[node.op]
    if isinstance(node, Mod):
        return 6
    if isinstance(node, ShortCircuit):
        return _PREC[node.op]
    if isinstance(node, Not):
        return 3
    if isinstance(node, Neg):
        return 8
    return 9   # leaves / calls / refs


def _fmt_param(n):
    """One LPARAMETERS/PARAMETERS entry: plain name, typed member
    (name, class, library) from the round-24 extension, or — since the
    round-28 corpus census — the same triple with library None for the
    measured AS-without-OF spelling ('af f7 0000 51 fb' x19)."""
    if isinstance(n, tuple):
        nm, typ, lib = n
        if typ is None:
            # r50-sysapp: an AS mark the compiler kept no type behind. The
            # annotation is unrecoverable, so it is not written.
            return nm
        if lib is None:
            return "%s AS %s" % (nm, typ)
        return "%s AS %s OF %s" % (nm, typ, lib)
    return n


def _dim_declarator(name, dims, bracket):
    """One DIMENSION declarator in the SOURCE's own subscript spelling.

    The dimension list's closing byte carries the spelling the author wrote —
    03 for '( … )', 16 for '[ … ]' — and the two are not interchangeable on the
    wire, so re-emitting it verbatim is what keeps a recompile byte-equal. Same
    provenance and same rule as ArrayRef, IndexedElemRef and the LOCAL
    dimension tail."""
    o, c = ("[", "]") if bracket else ("(", ")")
    return "%s%s%s%s" % (name, o, ", ".join(_emit(d) for d in dims), c)


def _emit_line(ast):
    if isinstance(ast, Verbatim):
        if ast.jump_rel is None:
            return ast.text
        # framed block opener: the verbatim line IS the IF line — emit it byte-exact
        # (trailing spaces/tabs included) and frame the lifted body like If does
        lines = [ast.text]
        lines += _indent(ast.body)
        if ast.else_body or ast.else_target >= 0:
            lines.append("ELSE")
            lines += _indent(ast.else_body)
        lines.append(getattr(ast, "closer", "ENDIF"))
        return "\n".join(lines)
    if isinstance(ast, Assign):
        return "%s = %s" % (_emit(ast.lv), _emit(ast.expr))
    if isinstance(ast, Store):
        return "STORE %s TO %s" % (_emit(ast.expr), ", ".join(_emit(t) for t in ast.targets))
    if isinstance(ast, Print):
        head = "??" if ast.ee else "?"
        return (head + " " + ", ".join(_emit(a) for a in ast.args)).rstrip()
    if isinstance(ast, Local):
        parts = []
        for entry in ast.names:
            n, typ = entry[0], entry[1]
            pack = entry[2] if len(entry) > 2 else None
            of_lib = entry[3] if len(entry) > 3 else None
            if pack:
                dims, close = pack
                # measured per-declarator spelling: the closer byte records whether
                # the source used '( ... )' (03) or '[ ... ]' (16); see dec side
                o, c = ("(", ")") if close == ")" else ("[", "]")
                txt = "%s%s%s%s" % (n, o, ", ".join(dims), c)
            else:
                txt = n
            if typ:
                txt = "%s AS %s" % (txt, typ)
                if of_lib:
                    txt += " OF " + of_lib
            parts.append(txt)
        return "LOCAL " + ", ".join(parts)
    if isinstance(ast, LParams):
        return "LPARAMETERS " + ", ".join(_fmt_param(n) for n in ast.names)
    if isinstance(ast, ParametersStmt):
        return "PARAMETERS " + ", ".join(_fmt_param(n) for n in ast.names)
    if isinstance(ast, DefineStmt):
        if ast.kind == "WINDOW":
            if ast.frm:
                txt = "DEFINE WINDOW %s FROM %s, %s TO %s, %s" % (
                    ast.name, _emit(ast.frm[0]), _emit(ast.frm[1]),
                    _emit(ast.frm[2]), _emit(ast.frm[3]))
            else:
                txt = "DEFINE WINDOW %s AT %s, %s SIZE %s, %s" % (
                    ast.name, _emit(ast.at[0]), _emit(ast.at[1]),
                    _emit(ast.size[0]), _emit(ast.size[1]))
            # Clauses render in VFP's documented DEFINE WINDOW order, which the
            # wire does not keep: the attribute run is wire-reordered (f17 ==
            # f18 prove the source order is unrecoverable) and SYSTEM even rides
            # behind the TITLE/IN groups. The COLOR SCHEME group stays ahead of
            # the attribute words exactly as round-24 m1/m4 established.
            if ast.in_window is not None:
                txt += " IN WINDOW " + _emit(ast.in_window)
            if ast.font:
                txt += " FONT " + ", ".join(_emit(e) for e in ast.font)
            if ast.title is not None:
                txt += " TITLE " + _emit(ast.title)
            if ast.scheme is not None:
                txt += " COLOR SCHEME " + _emit(ast.scheme)
            if ast.flags:
                txt += " " + " ".join(ast.flags)
            if ast.obj_name is not None:
                txt += " NAME " + _emit(ast.obj_name)
            return txt
        if ast.kind == "POPUP":
            # clause words before FROM follow VFP's DEFINE POPUP grammar; the
            # word ORDER is the measured wire order (workerchart: RELATIVE then
            # SHORTCUT)
            txt = "DEFINE POPUP %s" % ast.name
            if ast.scheme is not None:
                txt += " COLOR SCHEME " + _emit(ast.scheme)
            if ast.flags:
                txt += " " + " ".join(ast.flags)
            if ast.frm:
                txt += " FROM " + ", ".join(_emit(e) for e in ast.frm)
            return txt
        if ast.kind == "PAD":
            txt = "DEFINE PAD %s OF %s" % (ast.name, ast.of_popup)
            if ast.prompt is not None:
                txt += " PROMPT " + _emit(ast.prompt)
            if ast.at:
                txt += " AT %s, %s" % (_emit(ast.at[0]), _emit(ast.at[1]))
            if ast.before_name:
                txt += " BEFORE " + ast.before_name
            if ast.font:
                txt += " FONT " + ", ".join(_emit(e) for e in ast.font)
            if ast.style is not None:
                txt += " STYLE " + _emit(ast.style)
            if ast.message is not None:
                txt += " MESSAGE " + _emit(ast.message)
            if ast.mark is not None:
                txt += " MARK " + _emit(ast.mark)
            if ast.negotiate:
                txt += " NEGOTIATE " + ast.negotiate
            if ast.skip_for is not None:
                txt += " SKIP FOR " + _emit(ast.skip_for)
            if ast.scheme is not None:
                txt += " COLOR SCHEME " + _emit(ast.scheme)
            if ast.key is not None:
                txt += " KEY " + ast.key[0]
                if ast.key[1] is not None:
                    txt += ", " + _emit(ast.key[1])
            return txt
        txt = "DEFINE BAR %s OF %s" % (ast.bar_num, ast.of_popup)
        if ast.prompt is not None:
            txt += " PROMPT " + _emit(ast.prompt)
        if ast.font:
            txt += " FONT " + ", ".join(_emit(e) for e in ast.font)
        if ast.style is not None:
            txt += " STYLE " + _emit(ast.style)
        # the wire puts BEFORE/AFTER between the STYLE and MESSAGE clauses
        if getattr(ast, "neighbour_word", None):
            txt += " %s %s" % (ast.neighbour_word, ast.neighbour)
        if ast.message is not None:
            txt += " MESSAGE " + _emit(ast.message)
        if ast.key is not None:
            txt += " KEY " + ast.key[0]
            if ast.key[1] is not None:
                txt += ", " + _emit(ast.key[1])
        if ast.skip_for is not None:
            txt += " SKIP FOR " + _emit(ast.skip_for)
        if ast.scheme is not None:
            txt += " COLOR SCHEME " + _emit(ast.scheme)
        if ast.mark is not None:
            txt += " MARK " + _emit(ast.mark)
        if ast.picture is not None:
            txt += " PICTURE " + _emit(ast.picture)
        if ast.pictres is not None:
            txt += " PICTRES " + ast.pictres
        return txt
    if isinstance(ast, ActivatePopup):
        out = "ACTIVATE POPUP %s" % ast.name
        if ast.at is not None:
            out += " AT %s, %s" % (_emit(ast.at[0]), _emit(ast.at[1]))
        return out
    if isinstance(ast, DeactivatePopup):
        return "DEACTIVATE POPUP %s" % ast.name
    if isinstance(ast, MovePopup):
        return "MOVE POPUP %s TO %s, %s" % (ast.name, _emit(ast.row),
                                            _emit(ast.col))
    if isinstance(ast, ActivateScreen):
        return "ACTIVATE SCREEN"
    if isinstance(ast, BrowseWindow):
        # r53-browsehead: a clause list needs no head, so the head-less form is
        # only "BROWSE" when there is no clause at all — returning it early on
        # an empty FIELDS list would drop a TITLE or a TIMEOUT standing alone.
        txt = ("BROWSE" if ast.window is None
               else "BROWSE WINDOW %s" % ast.window)
        if ast.fields:
            cols = []
            for fname, width, pic, heading, order in ast.fields:
                # r49-menusweep measured that a field spec stores the SOURCE's
                # attribute order, and r53-browsefield that every ordering
                # exists, so emission follows the order the frame recorded
                col = fname
                for attr in order:
                    if attr == "w":
                        col += ":%s" % width
                    elif attr == "h":
                        col += " :H = %s" % _emit(heading)
                    else:
                        col += " :P = %s" % _emit(pic)
                cols.append(col)
            txt += " FIELDS " + ", ".join(cols)
        if ast.title is not None:
            txt += " TITLE " + _emit(ast.title)
        if ast.timeout is not None:
            txt += " TIMEOUT " + _emit(ast.timeout)
        for word, operand in ast.clauses:
            # the clause order the source wrote is not recoverable from the
            # frame — the wire stores one canonical order (r53-browsehead) —
            # so these go out in that order, which recompiles to the same frame
            if operand is None:
                txt += " " + word
            elif isinstance(operand, str):
                # a name clause hands back rendered text, quoting and all
                txt += " %s %s" % (word, operand)
            elif isinstance(operand, list):
                txt += " %s %s" % (word,
                                   ", ".join(_emit(o) for o in operand))
            else:
                txt += " %s %s" % (word, _emit(operand))
        if ast.for_cond is not None:
            # source order: 'BROWSE WINDOWS wBrowse TITLE .. TIMEOUT 20 FOR ..'
            txt += " FOR " + _emit(ast.for_cond)
        return txt
    if isinstance(ast, OnStmt):
        if ast.keyword == "KEY LABEL":
            return "ON KEY LABEL %s %s" % (ast.label, ast.handler)
        if ast.keyword == "PAD":
            return "ON PAD %s OF %s %s" % (ast.popup, ast.of_menu, ast.handler)
        if ast.keyword in ("SELECTION BAR", "BAR"):
            return "ON %s %s OF %s %s" % (
                ast.keyword, _emit(ast.bar), ast.popup, ast.handler)
        if ast.popup is not None:
            return "ON %s %s %s" % (ast.keyword, ast.popup, ast.handler)
        return "ON %s %s" % (ast.keyword, ast.handler)
    if isinstance(ast, DeclareDllStmt):
        head = "DECLARE "
        if ast.ret:
            head += ast.ret + " "
        head += "%s IN %s" % (ast.func, ast.lib)
        if ast.alias:
            head += " AS " + ast.alias
        if ast.params:
            head += " " + ", ".join(ast.params)
            if ast.trailing_comma:
                head += ","
        return head
    if isinstance(ast, EraseStmt):
        operand = ast.name if isinstance(ast.name, str) else _emit(ast.name)
        return "ERASE " + operand + (" RECYCLE" if ast.recycle else "")
    if isinstance(ast, RenameStmt):
        # wording pinned by the four stored RENAME lines (purtcmanage L122/L123,
        # pidocchk L174/L175) — identical to the lane-B simulation output
        new = ast.new_name if isinstance(ast.new_name, str) \
            else _emit(ast.new_name)
        return "RENAME %s TO %s" % (ast.old_name, new)
    if isinstance(ast, DeleteFor):
        head = "DELETE ALL FOR" if ast.all_scope else "DELETE FOR"
        return "%s %s" % (head, _emit(ast.cond))
    if isinstance(ast, DeleteScopeStmt):
        if ast.kind == "FILE":
            operand = ast.target if isinstance(ast.target, str) \
                else _emit(ast.target)
            return "DELETE FILE %s" % operand
        if ast.kind == "VIEW":
            return "DELETE VIEW %s" % ast.target
        # r54-inalias: the record-scoped bank in SOURCE order. Stored sources
        # spell the scope word, then the conditions, then the work area
        # ('DELETE FOR workbook = tnWB IN c_cells') even though the wire is
        # IN-clause-first; mirror that order like ReplaceStmt does.
        out = "DELETE"
        if ast.kind:
            out += " " + ast.kind
            if ast.target is not None:
                out += " " + _emit(ast.target)
        if ast.cond is not None:
            out += " FOR " + _emit(ast.cond)
        if ast.while_cond is not None:
            out += " WHILE " + _emit(ast.while_cond)
        if ast.alias is not None:
            out += " IN " + ast.alias
        if ast.nooptimize:
            out += " NOOPTIMIZE"
        return out
    if isinstance(ast, Return):
        if ast.expr is None:
            return "RETURN"
        return "RETURN %s%s" % ("@" if ast.by_ref else "", _emit(ast.expr))
    if isinstance(ast, Dim):
        return "DIMENSION " + _dim_declarator(ast.name, ast.dims, ast.bracket)
    if isinstance(ast, DimList):
        return "DIMENSION " + ", ".join(
            _dim_declarator(n, dims, br) for n, dims, br in ast.items)
    if isinstance(ast, With):
        head = "WITH " + _emit(ast.expr)
        if getattr(ast, "as_class", None):
            head += " AS " + ast.as_class
        if getattr(ast, "of_library", None):
            head += " OF " + ast.of_library
        lines = [head]
        lines += _indent(ast.body)
        lines.append("ENDWITH")
        return "\n".join(lines)
    if isinstance(ast, TextStmt):
        # flags already hold the canonical wire order (round-23 t6: the compiler
        # normalises scrambled source order, so canonical emission is safe)
        if ast.target is None:
            head = "TEXT"
        else:
            head = "TEXT TO " + _emit(ast.target)
            for fl in ast.flags:
                head += " " + fl
        lines = [head]
        lines += [ln.text for ln in ast.body]
        lines.append("ENDTEXT")
        return "\n".join(lines)
    if isinstance(ast, TextLine):
        return ast.text
    if isinstance(ast, SelectStmt):
        return "SELECT %s" % ast.name
    if isinstance(ast, SqlSelectColumns):
        # sole owner of the d7/cd spellings: exactly one tag per statement, in the
        # INTO-clause slot VFP documents them in ('INTO CURSOR c [NOFILTER]')
        return ast.text + (" READWRITE" if ast.readwrite else "") \
            + (" NOFILTER" if ast.nofilter else "") \
            + getattr(ast, "tail_text", "") \
            + "".join(" " + w for w in getattr(ast, "display", ()))
    if isinstance(ast, SqlSelectIntoCursor):
        d = " DESC" if ast.desc else ""
        w = ""
        if ast.where is not None:
            w = " WHERE " + _emit(ast.where)
        o = ""
        if ast.order_expr is not None:
            o = " ORDER BY " + _emit(ast.order_expr) + d
        rw = " READWRITE" if ast.readwrite else ""
        return (f"SELECT * FROM {ast.table}{w}{o} INTO CURSOR {ast.cursor}{rw}")
    if isinstance(ast, ReplaceStmt):
        body = ", ".join("%s WITH %s" % (_emit(lv), _emit(e))
                         for lv, e in ast.pairs)
        # r49-clauseorder: ALL rides the same byte wherever the source put the
        # word, and the symbol table is what says where that was
        if ast.all_scope and getattr(ast, "all_first", False):
            return "REPLACE ALL " + body
        text = "REPLACE " + body
        if ast.all_scope:
            text += " ALL"
        if ast.for_cond is not None:
            text += " FOR " + _emit(ast.for_cond)
        if getattr(ast, "in_spec", None) is not None:
            spec = ast.in_spec
            if isinstance(spec, tuple):
                text += " IN (" + _emit(spec[1]) + ")"
            else:
                text += " IN " + str(spec)
        return text
    if isinstance(ast, PublicStmt):
        return ("PRIVATE " if getattr(ast, "private", False) else "PUBLIC ") \
            + ", ".join(_fmt_param(n) if isinstance(n, tuple) else n
                        for n in ast.names)
    if isinstance(ast, PrivateAllLike):
        if ast.skeleton is None:
            return "PRIVATE ALL"
        return "PRIVATE ALL %s %s" % (ast.word, ast.skeleton)
    if isinstance(ast, ClearStmt):
        if ast.clause == "DLLS" and ast.names:
            ops = list(ast.name_ops) + [S.STR] * (len(ast.names)
                                                  - len(ast.name_ops))
            out = []
            for nm, op in zip(ast.names, ops):
                if op == S.STR2:
                    out.append('"%s"' % nm)      # d9: the author's own case
                elif nm == nm.upper():
                    out.append(nm)               # fb, upper: written bare
                else:
                    out.append("'%s'" % nm)      # fb, mixed: quoted, r42 canon
            return "CLEAR DLLS " + ", ".join(out)
        if ast.expr is not None:
            # r54-clearbank: a wrapped operand carries its own spelling, so the
            # expression emitter renders the quotes or parentheses the source
            # wrote. RESOURCES has held one since round 28.
            return "CLEAR %s %s" % (ast.clause, _emit(ast.expr))
        if ast.clause in ("CLASS", "CLASSLIB") and ast.names:
            # a bare name rides verbatim — the compiler upper-cases neither
            return "CLEAR %s %s" % (ast.clause, ast.names[0])
        # r54-clearbank: every payload-less operand is its own word, and the
        # bare spelling of a payload operand is that word alone
        if ast.clause == "READ ALL" or ast.clause in S.CLEAR_KEYWORDS.values():
            return "CLEAR " + ast.clause
        raise Unsupported("CLEAR clause unmeasured")
    if isinstance(ast, ThrowStmt):
        if ast.expr is None:
            return "THROW"
        return "THROW %s" % _emit(ast.expr)
    if isinstance(ast, SumStmt):
        exprs = ", ".join(_emit(e) for e in ast.expr)
        clause = ""
        scope = getattr(ast, "scope", None)
        if scope is not None:
            word, count = scope
            clause += " " + word + ("" if count is None
                                    else " " + _emit(count))
        if getattr(ast, "for_cond", None) is not None:
            clause += " FOR " + _emit(ast.for_cond)
        if getattr(ast, "while_cond", None) is not None:
            clause += " WHILE " + _emit(ast.while_cond)
        to = " TO %s%s" % ("ARRAY " if getattr(ast, "to_array", False) else "",
                           ", ".join(_emit(t) for t in ast.target))
        # r49-clauseorder: the table recovers a clause the source wrote first
        if clause and getattr(ast, "for_first", False):
            return "SUM %s%s%s" % (exprs, clause, to)
        return "SUM %s%s%s" % (exprs, to, clause)
    if isinstance(ast, CountStmt):
        # VFP doc clause order: scope/FOR precedes TO, and both source orders
        # compile to the same frame; round-32 adds ALL and WHILE to the matrix,
        # and r49-clauseorder recovers a TO the source wrote first from the
        # symbol table's own order
        clause = ""
        scope = getattr(ast, "scope", None)
        if scope is not None:
            word, count = scope
            clause += " " + word + ("" if count is None
                                    else " " + _emit(count))
        elif getattr(ast, "count_all", False):
            clause += " ALL"
        if ast.for_cond is not None:
            clause += " FOR %s" % _emit(ast.for_cond)
        if getattr(ast, "while_cond", None) is not None:
            clause += " WHILE %s" % _emit(ast.while_cond)
        to = "" if ast.target is None else " TO %s" % _emit(ast.target)
        if clause and getattr(ast, "to_first", False):
            return "COUNT%s%s" % (to, clause)
        return "COUNT%s%s" % (clause, to)
    if isinstance(ast, CatchWhen):
        if ast.var is not None and ast.cond is not None:
            return "CATCH TO %s WHEN %s" % (ast.var, _emit(ast.cond))
        if ast.cond is not None:
            return "CATCH WHEN " + _emit(ast.cond)
        return "CATCH"
    if isinstance(ast, SetStmt):
        return ast.text
    if isinstance(ast, ExternalStmt):
        return "EXTERNAL %s %s" % (ast.kind, ast.name)
    if isinstance(ast, OpenDatabaseStmt):
        return "OPEN DATABASE %s%s" % (ast.name, " SHARED" if ast.shared else "")
    if isinstance(ast, GoTop):
        text = "GO"
        if ast.selector == "BOTTOM":
            text += " BOTTOM"
        elif ast.selector is not None:
            text += " " + _emit(ast.selector)
        else:
            text += " TOP"
        if ast.in_target is not None:
            text += " IN " + _emit(ast.in_target)
        return text
    if isinstance(ast, SetDatasessionTo):
        if ast.paren:
            return "SET DATASESSION TO (%s)" % _emit(ast.expr)
        return "SET DATASESSION TO %s" % _emit(ast.expr)
    if isinstance(ast, NodefaultStmt):
        return "NODEFAULT"
    if isinstance(ast, ClassMethodIndex):
        return ""
    if isinstance(ast, ProtectedProp):
        return "%s %s" % (ast.word, ", ".join([ast.name] + list(ast.more)))
    if isinstance(ast, CommandLine):
        return ast.text
    if isinstance(ast, PrintJobStmt):
        return "\n".join(["PRINTJOB"] + _indent(ast.body) + ["ENDPRINTJOB"])
    if isinstance(ast, ImplementsStmt):
        return "IMPLEMENTS %s IN %s" % (ast.name, ast.library)
    if isinstance(ast, AddObjectStmt):
        line = "ADD OBJECT %s AS %s" % (ast.name, ast.class_name)
        if ast.with_pairs:
            parts = ["%s = %s" % (n, _emit(e)) for n, e in ast.with_pairs]
            line += " WITH " + ", ".join(parts)
        return line
    if isinstance(ast, UseStmt):
        if ast.name is None and ast.in_area is None and not ast.exclusive \
                and not ast.shared and not ast.noupdate and not ast.again \
                and ast.alias is None:
            return "USE"
        # canonical clause order reproduces every measured source spelling:
        # 'USE LU3 IN 0 EXCLUSIVE', 'USE (e) EXCLUSIVE ALIAS (…)',
        # 'USE (e) SHARED NOUPDATE ALIAS (…)',
        # 'USE (e) AGAIN SHARED NOUPDATE ALIAS FRX' (fxlistener s38).
        parts = ["USE " + ast.name] if ast.name else ["USE"]
        if ast.again:
            parts.append("AGAIN")
        if ast.shared:
            parts.append("SHARED")
        if ast.noupdate:
            parts.append("NOUPDATE")
        if ast.in_area is not None:
            parts.append("IN " + ast.in_area)
        if ast.exclusive:
            parts.append("EXCLUSIVE")
        if ast.alias is not None:
            parts.append("ALIAS " + ast.alias)
        if getattr(ast, "order", None) is not None:
            parts.append("ORDER " + ast.order)
        if getattr(ast, "nodata", False):
            parts.append("NODATA")
        if getattr(ast, "norequery", False):
            parts.append("NOREQUERY")
        return " ".join(parts)
    if isinstance(ast, (ScatterStmt, GatherStmt)):
        return _emit_scatter_gather(ast)
    if isinstance(ast, ErrorStmt):
        return "ERROR " + ", ".join(_emit(a) for a in ast.args)
    if isinstance(ast, ReleaseAll):
        return "RELEASE ALL"
    if isinstance(ast, ReleaseStmt):
        return "RELEASE " + ", ".join(ast.names)
    if isinstance(ast, AtCommand):
        txt = "@ %s, %s" % (_emit(ast.row), _emit(ast.col))
        if ast.corner is not None:
            txt += " TO %s, %s" % (_emit(ast.corner[0]), _emit(ast.corner[1]))
        if ast.say is not None:
            txt += " SAY %s" % _emit(ast.say)
        if ast.picture is not None:
            txt += " PICTURE %s" % _emit(ast.picture)
        return txt
    if isinstance(ast, LocateFor):
        head = "LOCATE"
        if ast.all_scope:
            head += " ALL"
        elif getattr(ast, "scope_word", None):
            head += " " + ast.scope_word
            if getattr(ast, "scope_expr", None) is not None:
                head += " " + _emit(ast.scope_expr)
        for_txt = "" if ast.cond is None else " FOR %s" % _emit(ast.cond)
        while_txt = ("" if ast.while_cond is None
                     else " WHILE %s" % _emit(ast.while_cond))
        if getattr(ast, "while_first", False) and for_txt and while_txt:
            return head + while_txt + for_txt
        return head + for_txt + while_txt
    if isinstance(ast, ForStmt):
        lines = ["FOR %s = %s TO %s" % (
            _emit(ast.var), _emit(ast.start), _emit(ast.end))]
        if ast.step is not None:
            lines[-1] += " STEP %s" % _emit(ast.step)
        lines += _indent(ast.body)
        lines.append("ENDFOR")
        return "\n".join(lines)
    if isinstance(ast, ForEachStmt):
        head = "FOR EACH %s" % _emit(ast.var)
        if ast.as_class:
            head += " AS %s" % ast.as_class
            if ast.of_lib:
                head += " OF %s" % ast.of_lib
        head += " IN %s" % _emit(ast.collection)
        if ast.foxobject:
            head += " FOXOBJECT"
        lines = [head]
        lines += _indent(ast.body)
        lines.append("ENDFOR")   # stored sources spell NEXT and ENDFOR alike
        return "\n".join(lines)
    if isinstance(ast, ScanStmt):
        head = "SCAN"
        if getattr(ast, "nooptimize", False):
            # the wire stores 0x30 first whatever position the source wrote it in
            head += " NOOPTIMIZE"
        if ast.scan_all:
            head += " ALL"
        elif getattr(ast, "scope_word", ""):
            head += " " + ast.scope_word
            if getattr(ast, "scope_expr", None) is not None:
                head += " " + _emit(ast.scope_expr)
        if ast.cond is not None:
            head += " FOR " + _emit(ast.cond)
        if getattr(ast, "while_cond", None) is not None:
            head += " WHILE " + _emit(ast.while_cond)
        lines = [head]
        lines += _indent(getattr(ast, "body", []))
        lines.append("ENDSCAN")
        return "\n".join(lines)
    if isinstance(ast, TryStmt):
        lines = ["TRY"]
        lines += _indent(ast.body)
        if ast.catch_body is not None:
            # canonical CATCH aligns with TRY; nested indentation comes from the
            # enclosing body's indentation, not from the frame keywords
            if ast.catch_var and ast.catch_cond is not None:
                lines.append("CATCH TO %s WHEN %s"
                             % (ast.catch_var, _emit(ast.catch_cond)))
            elif ast.catch_var:
                lines.append("CATCH TO " + ast.catch_var)
            else:
                lines.append("CATCH" if ast.catch_cond is None
                             else "CATCH WHEN " + _emit(ast.catch_cond))
            lines += _indent(ast.catch_body or [])
        if ast.finally_body is not None:
            lines.append("FINALLY")
            lines += _indent(ast.finally_body)
        lines.append("ENDTRY")
        return "\n".join(lines)
    if isinstance(ast, FinallyClause):
        # The frame walker consumes FINALLY (target walker-verified, never
        # rendered, same contract as CatchWhen targets); this bare rendering
        # only serves per-statement probing outside any TRY frame.
        return "FINALLY"
    if isinstance(ast, CreateCursor):
        parts = []
        for fname, tchar, width, decimals, autoinc, nullable in ast.fields:
            p = "%s %s" % (fname, tchar)
            if width is not None:
                p += "(%s)" % width
                if decimals is not None:
                    p = p[:-1] + ",%s)" % decimals
            if nullable:
                # column nullability clause (round-29 d6, r54-cursornull's
                # 0a d6); the wire places it before AUTOINC and so does this
                p += " " + nullable
            if autoinc is not None:
                p += " AUTOINC NEXTVALUE %s" % autoinc
            parts.append(p)
        # round-33 CODEPAGE clause rides between name and field list exactly
        # as the stored sources spell it ('CREATE CURSOR c_strings
        # CODEPAGE = 620 (id I, ...)').
        out = "CREATE %s %s" % ("TABLE" if ast.table else "CURSOR", ast.name)
        if ast.free:
            out += " FREE"          # r47-createtable
        if ast.codepage is not None:
            out += " CODEPAGE = %s" % ast.codepage
        if ast.from_array is not None:
            return out + " FROM ARRAY %s" % ast.from_array
        return out + " (%s)" % ", ".join(parts)
    if isinstance(ast, CreateStmt):
        if ast.sql_view is not None:
            out = "CREATE SQL VIEW %s" % ast.sql_view
            if ast.remote:
                out += " REMOTE"
            out += " CONNECTION %s" % ast.remote_connection
            if ast.share:
                out += " SHARE"
            return out + " AS %s" % ast.as_query
        if ast.name is not None:
            return "CREATE %s" % ast.name
        return "CREATE REPORT %s FROM %s" % (_emit(ast.report_file),
                                             _emit(ast.report_from))
    if isinstance(ast, InsertInto):
        target = ast.target if isinstance(ast.target, str) else _emit(ast.target)
        out = "INSERT INTO %s" % target
        if ast.columns:
            out += " (%s)" % ", ".join(ast.columns)
        if ast.from_name is not None:
            return out + " FROM NAME %s" % ast.from_name
        if ast.select is not None:
            return out + " " + ast.select
        if ast.values is None:
            return out + " FROM MEMVAR"
        return out + " VALUES (%s)" % ", ".join(_emit(v) for v in ast.values)
    if isinstance(ast, tuple) and len(ast) == 1 and (
            ast[0] in (
                "APPEND", "APPEND BLANK", "QUIT", "CLEAR", "DELETE", "ENDSCAN",
                "PUSH KEY", "POP KEY", "PACK", "ZAP", "CANCEL", "DOEVENTS",
                "CLOSE TABLES", "CLOSE DATABASES", "CLOSE DATABASES ALL",
                "CLOSE TABLES ALL", "CLOSE ALL", "CLOSE INDEXES",
                "CLOSE PROCEDURE", "READ", "REINDEX", "REINDEX COMPACT",
                "WAIT", "DEBUG",
                "CONTINUE", "LIST", "ENDTEXT", "ENDEACH", "ENDPRINTJOB",
                # r50-leadsweep: the one-byte command bank and its measured
                # one-byte modifiers, plus the two TRANSACTION frames
                "ASSIST", "CHANGE", "DIR", "DISPLAY", "DISPLAY MEMORY",
                "DISPLAY STATUS", "EDIT", "EJECT", "EJECT PAGE", "RESUME",
                "RETRY", "LOGOUT", "UNLOCK", "UNLOCK ALL", "FLUSH",
                "FLUSH FORCE", "BLANK", "RESET", "ROLLBACK",
                "BEGIN TRANSACTION", "END TRANSACTION",
                "DELETE ALL", "BROWSE", "PUSH KEY CLEAR", "LOCATE", "RECALL",
                "INSERT", "INSERT BEFORE",
                "INSERT BLANK", "INSERT BEFORE BLANK", "SUSPEND")
            or ast[0].startswith("PUSH MENU ")
            or ast[0].startswith("POP MENU ")
            or ast[0].startswith("ZAP IN ")
            or ast[0].startswith("APPEND BLANK IN ")):
        return ast[0]
    if isinstance(ast, BackslashLine):
        return ("\\" if ast.feed else "\\\\") + ast.text
    if isinstance(ast, HelpStmt):
        out = "HELP"
        if ast.id_expr is not None:
            out += " ID " + _emit(ast.id_expr)
        if ast.nowait:
            out += " NOWAIT"
        if ast.topic:
            # r51-helptopic: the fb payload is the VERBATIM tail of the source
            # line after the verb and its clauses — the separator space and the
            # source's own quoting are inside it, `HELP    "abc"` stores four
            # spaces and `HELP abc def` stores two bare words. Every spelling
            # of one topic stores a different payload, which a string VALUE
            # could not do, so it is written back as it stands. Round 29 had
            # only empty-topic carriers and single-quoted the guess.
            out += ast.topic
        return out
    if isinstance(ast, KeyboardStmt):
        out = "KEYBOARD " + _emit(ast.keys)
        return out + " PLAIN" if ast.plain else out
    if isinstance(ast, ShowWindowStmt):
        out = "%s WINDOW %s" % (getattr(ast, "verb", "SHOW"), _emit(ast.name))
        if getattr(ast, "modifier", ""):
            out += " " + ast.modifier
        if ast.in_window is not None:
            out += " IN WINDOW " + _emit(ast.in_window)
        return out
    if isinstance(ast, ActivateWindowStmt):
        out = "ACTIVATE WINDOW " + _emit(ast.name)
        if ast.in_window is not None:
            out += " IN WINDOW " + _emit(ast.in_window)
        if ast.noshow:
            out += " NOSHOW"
        if ast.same:
            out += " SAME"
        return out
    if isinstance(ast, ZoomWindowStmt):
        return "ZOOM WINDOW %s %s" % (ast.name, ast.mode)
    if isinstance(ast, SeekStmt):
        return "SEEK " + _emit(ast.key)
    if isinstance(ast, DebugoutStmt):
        return "DEBUGOUT " + _emit(ast.expr)
    if isinstance(ast, MouseStmt):
        # documented clause order; the wire order is canonical either way
        out = "MOUSE"
        if getattr(ast, "action", ""):
            out += " " + ast.action
        out += " %s %s, %s" % ("TO" if getattr(ast, "to_coords", False)
                               else "AT", _emit(ast.row), _emit(ast.col))
        if ast.window is not None:
            out += " WINDOW %s" % _emit(ast.window)
        if getattr(ast, "pixels", True):
            out += " PIXELS"
        return out
    if isinstance(ast, CdStmt):
        return "CD " + ast.path
    if isinstance(ast, MkdirStmt):
        return ("RMDIR " if ast.remove else "MKDIR ") + ast.path
    if isinstance(ast, ListToFileStmt):
        out = "LIST"
        if ast.clause is not None:
            out += " " + ast.clause
        if ast.like_pattern is not None:
            out += " LIKE " + ast.like_pattern
        # measured spellings differ: plain TO under a clause byte (foxcharts
        # L3306/L3310), TO FILE on the bare form (VFPxWorkbookXLSX L516 family)
        out += " TO" + ("" if ast.clause is not None else " FILE")
        out += " " + _emit(ast.target)
        if ast.noconsole:
            out += " NOCONSOLE"
        return out
    if isinstance(ast, RunStmt):
        return "RUN " + ast.text
    if isinstance(ast, OnBareStmt):
        if ast.label is not None:
            return "ON KEY LABEL " + ast.label
        return "ON " + ast.keyword
    if isinstance(ast, AppendFromStmt):
        # r47-appendfrom: an ungrouped fb/d9 operand is the bare filename
        # spelling; quoting it recompiles to the fc-grouped frame instead.
        out = "APPEND FROM " + (ast.source.text if ast.bare_name
                                else _emit(ast.source))
        if ast.cond is not None:
            out += " FOR " + _emit(ast.cond)
        if ast.fields:
            out += " FIELDS " + ", ".join(ast.fields)
        if getattr(ast, "file_type", ""):
            if ast.type_word:
                out += " TYPE"          # r47-typeword: d4 is the TYPE keyword
            out += " " + ast.file_type
            if ast.delimited is not None:
                out += (" WITH TAB" if ast.delimited[0] == "TAB"
                        else " WITH CHARACTER '%s'" % ast.delimited[1])
        return out
    if isinstance(ast, AppendGeneralStmt):
        out = "APPEND GENERAL %s" % ast.field_name
        if ast.class_expr is not None:
            out += " CLASS %s" % _emit(ast.class_expr)
        if ast.data_expr is not None:
            out += " DATA %s" % _emit(ast.data_expr)
        return out
    if isinstance(ast, AppendMemoStmt):
        return "APPEND MEMO %s FROM %s%s" % (
            ast.field_name, _emit(ast.source),
            " OVERWRITE" if ast.overwrite else "")
    if isinstance(ast, CopyStmt):
        if ast.memo is not None:
            return "COPY MEMO %s TO %s" % (ast.memo, ast.target)
        if ast.to_array:
            return "COPY TO ARRAY %s FIELDS %s" % (
                ast.target, ",".join(ast.fields))
        if ast.structure:
            return "COPY STRUCTURE TO %s" % ast.target
        out = ("COPY FILE %s TO %s" % (ast.source, ast.target)
               if ast.source is not None else "COPY TO %s" % ast.target)
        if ast.fields:
            out += " FIELDS " + ", ".join(ast.fields)
        if ast.delimited is not None:
            if ast.type_word:
                out += " TYPE"          # r47-typeword: d4 is the TYPE keyword
            if ast.delimited[0] == "TAB":
                out += " DELIMITED WITH TAB"
            else:
                out += " DELIMITED WITH CHARACTER '%s'" % ast.delimited[1]
        elif getattr(ast, "file_type", ""):
            if ast.type_word:
                out += " TYPE"
            out += " " + ast.file_type
        return out
    if isinstance(ast, LoopStmt):
        return "LOOP"
    if isinstance(ast, OtherwiseClause):
        return "OTHERWISE"
    if isinstance(ast, ExitStmt):
        return "EXIT"
    if isinstance(ast, DoWhile):
        lines = ["DO WHILE " + _emit(ast.cond)]
        lines += _indent(ast.body)
        lines.append("ENDDO")
        return "\n".join(lines)
    if isinstance(ast, DoStmt):
        prog = _emit(ast.prog) if not isinstance(ast.prog, str) else ast.prog
        line = ("DO FORM %s" if ast.form else "DO %s") % prog
        if ast.in_target is not None:
            if ast.in_target == "":
                line += " IN"
            elif isinstance(ast.in_target, str):
                line += " IN " + ast.in_target
            else:
                line += " IN " + _emit(ast.in_target)
        if ast.name_target is not None:
            line += " NAME " + _emit(ast.name_target)
        if ast.to_target is not None:
            line += " TO " + _emit(ast.to_target)
        if ast.args:
            line += " WITH " + ", ".join(_emit(a) for a in ast.args)
        for fl in ast.flags or []:
            line += " " + fl
        return line
    if isinstance(ast, SkipStmt):
        if ast.n is None and ast.in_area is None:
            return "SKIP"
        out = "SKIP" if ast.n is None else "SKIP %s" % _emit(ast.n)
        if ast.in_area is not None:
            out += " IN " + ast.in_area
        return out
    if isinstance(ast, DoCase):
        # ast.clauses holds (CaseClause, source-statement) pairs — the statement is
        # kept so walk-time target verification stays traceable to its bytes
        lines = ["DO CASE"]
        if ast.body is not None:
            # round-35 zero-width region: nested frames only, no clauses ever
            lines += _indent(ast.body)
        else:
            # two levels, but through _indent both times: a CASE body may hold
            # a TEXT frame, and a verbatim payload line's column position is
            # part of its bytes (r49 — excelxml.vcx's `\t\t   <FreezePanes/>`
            # recompiled as eight spaces because a raw prepend put the indent
            # in front of the VERBATIM_MARK and the NUL then truncated the
            # line for the compiler)
            for cl, _st in ast.clauses:
                # r54-macrocase: a macro clause IS its stored line — re-emit it
                # rather than rebuilding a CASE the compiler never compiled
                lines.append("    " + cl.verbatim if cl.verbatim is not None
                             else "    CASE " + _emit(cl.cond))
                lines += _indent(_indent(cl.body))
            if ast.otherwise_body is not None:
                lines.append("    OTHERWISE")
                lines += _indent(_indent(ast.otherwise_body))
        lines.append("ENDCASE")
        return "\n".join(lines)
    if isinstance(ast, WaitStmt):
        if ast.clear:
            return "WAIT CLEAR"
        if ast.expr is None:
            head = "WAIT"
        else:
            head = ("WAIT %s" if ast.bare_wait
                    else "WAIT WINDOW %s") % _emit(ast.expr)
        tail = ""
        if ast.noclear:
            tail += " NOCLEAR"
        if ast.nowait:
            tail += " NOWAIT"
        if getattr(ast, "at", None):
            tail += " AT %s, %s" % (_emit(ast.at[0]), _emit(ast.at[1]))
        if ast.timeout is not None:
            tail += " TIMEOUT %s" % _emit(ast.timeout)
        return head + tail
    if isinstance(ast, ExprStmt):
        # 86 = explicit "= expr" form; 99 = bare form (FINDINGS: both fc-wrapped)
        prefix = "" if getattr(ast, "bare", False) else "= "
        if isinstance(ast.expr, ExprList):
            return prefix + ", ".join(_emit(e) for e in ast.expr.exprs)
        return prefix + _emit(ast.expr)
    if isinstance(ast, ObjectChain):
        # Same receiver rendering as the expression-position twin in _emit: a
        # chain link's receiver root may itself be a completed chain value, and
        # a bare ".".join over it raises TypeError. The two renderers must agree
        # -- a statement-position chain reaches THIS one. Output-neutral for the
        # string-only receivers every historical ObjectChain carries.
        text = ".".join(p if isinstance(p, str) else _emit(p)
                        for p in ast.recv)
        for n, (name, args) in enumerate(ast.calls):
            o, c = ("[", "]") if _chain_bracket(ast, n) else ("(", ")")
            text += "." + name + o + ", ".join(_emit(a) for a in args) + c
        if ast.tail:
            text += "." + ".".join(ast.tail)
        return text
    if isinstance(ast, If):
        lines = ["IF " + _emit(ast.cond)]
        lines += _indent(ast.body)
        if ast.else_body or ast.else_target >= 0:
            lines.append("ELSE")
            lines += _indent(ast.else_body)
        lines.append("ENDIF")
        return "\n".join(lines)
    if isinstance(ast, IndexOnStmt):
        text = "INDEX ON %s TAG %s" % (_emit(ast.expr), ast.tag)
        if ast.for_cond is not None:
            text += " FOR " + _emit(ast.for_cond)
        if ast.descending:
            text += " DESCENDING"
        if ast.ascending:
            # round-33 index lane: ASCENDING rides before ADDITIVE exactly as
            # the _webbrowser3 s15 carrier spells it ('.. ASCENDING ADDITIVE')
            text += " ASCENDING"
        if ast.candidate:
            text += " CANDIDATE"
        if ast.additive:
            text += " ADDITIVE"
        return text
    if isinstance(ast, AssertStmt):
        text = "ASSERT %s" % _emit(ast.expr)
        if ast.message is not None:
            text += " MESSAGE %s" % _emit(ast.message)
        return text
    if isinstance(ast, AverageStmt):
        text = "AVERAGE %s TO %s" % (
            ", ".join(_emit(e) for e in ast.expr),
            ", ".join(_emit(t) for t in ast.target))
        if ast.for_cond is not None:
            text += " FOR " + _emit(ast.for_cond)
        return text
    if isinstance(ast, AlterTableStmt):
        table = ast.table if isinstance(ast.table, str) else _emit(ast.table)
        text = "ALTER TABLE %s %s COLUMN %s %s" % (
            table, ast.action, ast.column, ast.type)
        if ast.widths:
            text += "(%s)" % ", ".join(_emit(w) for w in ast.widths)
        if ast.null:
            text += " NULL"
        return text
    if isinstance(ast, ModifyStmt):
        target = ast.target if isinstance(ast.target, str) else _emit(ast.target)
        text = "MODIFY %s %s" % (ast.kind, target)
        if ast.noedit:
            text += " NOEDIT"
        if ast.range_args:
            text += " RANGE %s" % ", ".join(_emit(a) for a in ast.range_args)
        if ast.nowait:
            text += " NOWAIT"
        # documented clause order; the wire canonicalises it either way
        if getattr(ast, "codepage", None) is not None:
            text += " AS " + _emit(ast.codepage)
        if getattr(ast, "window", None) is not None:
            text += " WINDOW " + ast.window
        if getattr(ast, "in_window", None) is not None:
            text += (" IN SCREEN" if ast.in_window.upper() == "SCREEN"
                     else " IN WINDOW " + ast.in_window)
        if getattr(ast, "same", False):
            text += " SAME"
        if getattr(ast, "nomenu", False):
            text += " NOMENU"
        if getattr(ast, "save", False):
            text += " SAVE"
        return text
    if isinstance(ast, CalculateStmt):
        items = ", ".join("%s(%s)" % (fn, ", ".join(_emit(a) for a in args))
                          for fn, args in ast.items)
        clause = ""
        scope = getattr(ast, "scope", None)
        if scope is not None:
            word, count = scope
            clause += " " + word + ("" if count is None
                                    else " " + _emit(count))
        if getattr(ast, "for_cond", None) is not None:
            clause += " FOR " + _emit(ast.for_cond)
        if getattr(ast, "while_cond", None) is not None:
            clause += " WHILE " + _emit(ast.while_cond)
        to = ""
        if ast.targets:
            to = " TO %s%s" % ("ARRAY " if getattr(ast, "to_array", False)
                               else "",
                               ", ".join(_emit(t) for t in ast.targets))
        if getattr(ast, "clause_first", True):
            return "CALCULATE %s%s%s" % (items, clause, to)
        return "CALCULATE %s%s%s" % (items, to, clause)
    if isinstance(ast, ReportFormStmt):
        form = ast.form if isinstance(ast.form, str) else _emit(ast.form)
        text = "REPORT FORM %s" % form
        parts = _emit_report_clauses(ast.clauses)
        return text + "".join(parts)
    if isinstance(ast, RemoveTableStmt):
        return "REMOVE TABLE %s%s" % (ast.name, " DELETE" if ast.delete else "")
    raise Unsupported(f"emit statement {type(ast).__name__}")
