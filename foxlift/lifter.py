# ABOUTME: The thin lifter: schema-driven RPN -> AST -> canonical VFP text, exact inverse shapes.
# ABOUTME: Verbatim families (01 macro / b4 rejected line) pass through as their stored text.

import struct as _struct
import math as _math
from dataclasses import dataclass, field
from datetime import date as _date

from foxlift import schemas as S
from foxlift.container import (
    PROLOGUE_U16, PROLOGUE_U32, class_identities, procedure_names,
    _method_names,
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
    an outer f6 receiver (r5 nesting `m.loA.B(m.x).C(m.y)`)."""
    recv: list              # receiver member names; a system-object root rides verbatim
    name: str               # called method symbol
    args: list              # argument ASTs collected from before the receiver
    prop: str | None = None


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
    'DO FORM Texture WITH EVL(.TextureTheme,\'\') TO lcNew')."""
    prog: object            # str | expr
    args: list
    form: bool = False
    to_target: object = None


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
    """df e3 <class> f7 <member> -- CLASS::MEMBER scope resolution."""
    cls: str
    member: str


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
    """PRIVATE ALL LIKE <skeleton> — measured as 35 03 18 fb<string>."""
    skeleton: str


@dataclass
class ClearStmt:
    """CLEAR <clause> — EVENTS / DLLS <names> (round-24), plus round-28 W4
    carrier-settled forms: RESOURCES bare or with one grouped operand
    ('CLEAR RESOURCES' vfp_skins s5[3]; 'CLEAR RESOURCES (This._tempfile)'
    foxchartsbeta pattern s3[13] et al.), CLASS <name> ('clea class OO'
    txtcollect frmtxtcollect s0 stmt90 <-> 0e 4f f7<sym>), and TYPEAHEAD
    (_reports.vcx cmdGetReport s0[4] 'CLEAR TYPEAHEAD' <-> bare 0e d4).
    Round-42: WINDOW is 0e2c — WINDOW/WINDOWS/named collapse (r42-clear)."""
    clause: str
    names: list = field(default_factory=list)
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
      tail [d4] be d1 bf fb<char> | [d4] be d1 c4 (preorder1 Command3 s0[4]/[11]).
    Round-32 carrier-aligned additions (lane-r32-2), each bound to its stored
    METHODS line and admitted ONLY in the measured operand spelling:
      memo=<field> is 'COPY MEMO <field> TO <target>' (_webview.vcx::
      _webbrowser3 s21 stmt13 <-> 11 1b f7<field> 28 <target-group>; field
      measured only as an f7 symbol, no tail clauses, and the target envelope
      hardened post-review to EXACTLY fc f7<u16> 03 at statement end — the
      runtime-parenthesised symbol target; literal/fc-string/paren-less
      spellings reject);
      to_array+fields is 'COPY TO ARRAY <arr> FIELDS <a,b,…>'
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
    order is normalised by the compiler to FOR-clause-first on the wire;
    emission follows the wire order (FOR first, THEN ' WHILE <cond2>'), the
    same normalised-wire convention as DELETE IN."""
    cond: object
    all_scope: bool = False
    while_cond: object | None = None   # `2b fc <rpn>` WHILE clause unit


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
    kind="IN": round-31 — `14 16 f7 <alias> [13 fc <cond>]`, the compiled IN-
      work-area clause, clause-first under the lead exactly like REPLACE's
      measured `3e 16 …` wire (same file: 'REPLACE .. WITH True IN c_cells').
      Carriers all VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx and aligned to their
      own stored lines: bare 'DELETE IN c_sheets' deletesheet s21 stmts10/18,
      resetcolumnwidth s68 stmt2, unmergedcells s105 stmt6; scoped
      'DELETE FOR workbook = tnWB .AND. sheet = lnSheet IN c_cells'
      deletesheet s21 stmt24 and 'DELETE FOR workbook = tnWB IN <alias>'
      deleteworkbook s22 stmts5-9. The authored FOR..IN order is normalised by
      the compiler to IN-clause-first; emission restores the stored source
      order (FOR before IN), mirroring ReplaceStmt."""
    kind: str
    target: object
    cond: object = None       # IN-kind only: the FOR condition when wired


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
    s0[40]; d4 = traceless TYPE word). The runtime-paren marker 03 is admitted
    ONLY inside the FROM group here; generalising it stays OPEN for its own lane."""
    source: object
    cond: object = None
    fields: list = field(default_factory=list)
    delimited: tuple | None = None


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


@dataclass
class ScatterStmt:
    """Lead 0x5e — round-17 oracle-measured forms ONLY (probes/oracle_harvest/
    round17_streams.json): SCATTER TO <array> (5e 28 f7 <arr>) and
    SCATTER MEMVAR MEMO (5e 1b c2). Round-28 W4 carrier-aligned additions:
    SCATTER NAME <m.x | THIS.path> (5e 4a ...; xfrxlib Xfrxcmd1 s0 stmt21
    'SCATTER NAME m.loForm') and the full 5e 08 1b 4a <path> 11 bc fb<skeleton>
    form ('SCATTER MEMO BLANK NAME THIS.evaluateContentsValues FIELDS LIKE
    FOXRecno' _reportlistener s54[7]). Round-42 I8 adds the two exact-length
    NAME-bare forms measured on the six validation keys:
    5e 1b 4a f7 <sym> (SCATTER MEMO NAME) and 5e 08 1b 4a f7 <sym>
    (SCATTER MEMO BLANK NAME). Every other 5e shape stays Unsupported."""
    target: str | None = None   # array symbol for the TO form
    memvar: bool = False        # 1b clause (round17_findings: MEMVAR)
    memo: bool = False          # c2 clause (round17_findings: MEMO)
    name_obj: str | None = None # NAME clause operand, rendered
    like_skeleton: str | None = None  # FIELDS LIKE skeleton after NAME
    memo_blank: bool = False    # the 08 1b flag pair of the full form


@dataclass
class GatherStmt:
    """Lead 0x5f — round-17-measured GATHER FROM <array> (5f 15 f7 <arr>);
    15 is contextual beneath this lead, never a global token. Round-28 W4:
    5f 4a <path> = 'GATHER NAME THIS.evaluateContentsValues'
    (_reportlistener s54[12])."""
    source: str | None = None
    name_obj: str | None = None


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
    """PROTECTED <prop> in class-init: a1 f7 <u16> (r43-class)."""
    name: str


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
    '\\', census charts.scx::foxcharts1 s2 stmt73 empty form 8dfb0000)."""
    text: str


@dataclass
class HelpStmt:
    """HELP [ID <expr>] [NOWAIT] <topic> — round-29. Both measured shapes end
    in an fb topic string that is EMPTY on every carrier (oracle bare '24fb0000',
    census cmdHelp '2449 .. 3a fb0000'); a non-empty topic renders single-quoted."""
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
    """SHOW WINDOW <name> IN WINDOW <parent> — round-29 corpus shape; the wire
    carries the IN-WINDOW (16) argument FIRST, both operands fc-groups."""
    name: object
    in_window: object


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
    """MOUSE AT <row>, <col> WINDOW <w> PIXELS — round-29 corpus xfcont s16
    shape ad ca 2c <w-group> 05 <r-group> 07 <c-group>; ca rides PIXELS."""
    row: object
    col: object
    window: object


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
    call-tail machinery (measured v3, already decoding at bind time)."""
    obj: str           # receiver object name (single measured f4 token)
    member: str        # indexed member name
    sub: object        # subscript expression AST
    prop: str          # terminal property name


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
    the spelling so each tag is emitted EXACTLY once."""
    text: str
    readwrite: bool = False
    nofilter: bool = False


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
    """SET DATASESSION TO (<expr>) — forced subset of the SET family."""
    expr: object


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

    def __init__(self, target, expr, for_cond=None):
        # accept legacy single pair or parallel lists
        self.target = target if isinstance(target, list) else [target]
        self.expr = expr if isinstance(expr, list) else [expr]
        self.for_cond = for_cond


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
    1, ...)' s13[0]). nullable = the contextual column-NULL clause byte d6,
    measured round-29 ONLY directly after a per-field closer 03 and before the
    07 join / list closer (dashboard1/dashboard3/dashboard123.scx cluster:
    'CREATE CURSOR sales1 (Chart1 n(8,2) NULL, Color i, Hide_Slice l)'); d6 in
    any other field-list position keeps raising field tail.
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
    meaning everywhere outside this slot."""
    name: str
    fields: list
    codepage: str | None = None   # rendered value of the CODEPAGE clause; None
                                  # when the statement carried none
    table: bool = False           # True when second byte is 0x31 (CREATE TABLE);
                                  # False when 0xBD (CREATE CURSOR)


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
    _reportlistener.vcx::xmllistener, xfrxlib.vcx::_cookie)."""
    target: object              # fb/d9 table-name literal, or expression node
    columns: list | None = None # bare f7 field names of the (col, ..) section
    values: list | None = None  # VALUES expressions; None => FROM MEMVAR form


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
    the width (source spells both ':10 :H = ..' and ':h=..:10'), and a lead-
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


@dataclass
class Return:
    expr: object         # None for bare RETURN


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
    lines (round-30: mainmenur.scx::grdmain stmt[107], ELSE-anchored)."""
    text: str
    jump_rel: int | None = None
    body: list = field(default_factory=list)
    else_body: list = field(default_factory=list)
    else_target: int = -1


ENDWITH_SENTINEL = ("ENDWITH",)


_SUBSCRIPT_STARTERS = frozenset({S.INT8, S.INT16, S.INT32,
    S.SYM, S.MEMBER, S.NAME, S.WITHREF, S.FLOAT, S.TRUE, S.FALSE})
# SET toggle ids measured by the command-id sweep (HARVEST.md "SET-command id
# space — MEASURED (43/43 forms)": CENTURY 05; suffixes OFF=1f / ON=20). Only ids
# absent from schemas.SET_ONOFF_NAMES are listed here. Value settings measured with
# a trailing `28 + expression`: an expressionless bare TO after them is Unsupported,
# EXCEPT CENTURY, whose bare '47 05 28' is now corpus-pinned ('SET CENTURY TO',
# oaremotionweb.scx::rtx Init) and admitted via schemas.SET_BARE_TO_NAMES.
_SET_MEASURED_ONOFF_IDS = {0x05: "CENTURY"}

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
         "LIKE": 4,
         "+": 5, "-": 5, "*": 6, "/": 6, "%": 6, "^": 7}

_POSTFIX = {S.PAREN, S.NEG, S.NOT}

# A 43-group ends at a namespace-specific callee. Round-14 oracle probes prove
# that arguments always precede the closer in bare, ea, and x1a namespaces.
# Only bare ids with a unique measured name and usable arity join the generated
# set; the smaller curated set retains its established unconstrained behavior.
_ENABLE_EXTRA_BARE = frozenset(
    S.DECODER_ENABLED_BARE - S.CORPUS_ALIGNED_BARE_CLOSERS)
_GROUP_CLOSERS = frozenset(
    {S.NAME, S.ESCAPE, S.X1A_ESCAPE, S.BARE_BYREF, S.MOD_APPLY}
    | S.CORPUS_ALIGNED_BARE_CLOSERS
    | set(_ENABLE_EXTRA_BARE)
    | set(S.MEASURED_LOCAL_GROUP_CLOSERS)
)
_IF_COND_STOP = frozenset({S.FD})   # the IF condition ends at its fd (FINDINGS §IF)


def _sym(syms, idx):
    if idx >= len(syms):
        raise Unsupported(f"symbol index {idx} beyond table ({len(syms)})")
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
_ARENA = []                  # live operand stacks, innermost last
_GROUP_DEPTH = 0              # live 43-group frames (the packet-nesting test
                              # of the W15-close residual gates on this)
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


def _arena_fallback(stack):
    """Nearest enclosing live operand stack holding a value, or None."""
    for fb in reversed(_ARENA):
        if fb is not stack and fb:
            return fb
    return None


def _dec_expr(buf, i, end, syms, stop_at_one=False, stop_bytes=frozenset(),
              member_callee_tail=False):
    stack = []
    _ARENA.append(stack)
    try:
        return _dec_expr_run(buf, i, end, syms, stack,
                             stop_at_one=stop_at_one, stop_bytes=stop_bytes,
                             member_callee_tail=member_callee_tail)
    finally:
        _ARENA.pop()


def _dec_expr_run(buf, i, end, syms, stack, stop_at_one=False,
                  stop_bytes=frozenset(), member_callee_tail=False):
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
                hex_digits = "%x" % v
                pad = digits - S.HEX_LITERAL_PREFIX_CHARS - len(hex_digits)
                if pad >= 0:
                    # Hex-literal member of the e9 family: the digits byte counts the
                    # source token INCLUDING '0x' (corpus alignment, schemas.
                    # HEX_LITERAL_PREFIX_CHARS provenance: paiche1.scx::FrmGoods Init
                    # '0x00080000' -> e9 0a 00000800). Re-emitting the zero-padded
                    # spelling reproduces the measured digits byte exactly. Only a
                    # mismatch fitting NEITHER family stays the folded zero-arg
                    # builtin call (funcnum table pending).
                    stack.append(Num("0x" + "0" * pad + hex_digits)); i += 6
                    continue
                if pad == -1 and digits != len(str(v)) and v > 0:
                    # Round-37 P1 correction (probes/oracle_harvest/
                    # ROUND37_FINDINGS.md C01/C02): an UNPADDED hex spelling rides
                    # digits byte = hexdigit_count + 1 ('0xFFFF' -> 05,
                    # '0x10000' -> 06, oracle-measured A1/A3). This is the family
                    # the six corpus systray carriers actually belong to: their
                    # stored sources spell '* 0x10000' and an authored replica
                    # compiles the census fragment BYTE-EXACTLY incl. operator
                    # position (e906 00000100 04, probe A4), while the r36
                    # trailing-dot reading of the same bytes is REFUTED
                    # end-to-end — authored '65536.' renders e9 05 and its dot
                    # emission failed canonical recompile (MISMATCH, frame 2).
                    # Emit the canonical lowercase unpadded spelling so the
                    # recompiled digits byte equals the stored one exactly.
                    # The `digits != len(str(v))` guard resolves the
                    # ambiguous-width overlap conservatively: wherever BOTH
                    # readings explain the wire — EXACTLY when hexdigit_count+1
                    # == len(str(v)), a set far wider than the all-nibble
                    # examples 15/255/4095/65535 (probe A3 measured at 65535;
                    # whole bands collide too, e.g. 10-15, 100-255, 1000-4095,
                    # 10000-65535) — the incumbent decimal spelling is kept,
                    # so already-lifting text never drifts. v == 0 stays
                    # unmeasured outside this arm (keeps the pinned fallback
                    # below).
                    stack.append(Num("0x" + hex_digits)); i += 6
                    continue
            if digits == len(str(v)) + 1 and v > 0:
                # Residual of the retired r36 trailing-dot arm. The dot READING
                # of the six carriers was refuted by the round-37 oracle lane
                # (C02): trailing-dot is wire-IDENTICAL to plain decimal
                # ('qq = lnV * 65536.' and '... * 65536' compile byte-for-byte
                # equal, probes A5 == A6), so nothing produces
                # digits == len(str(v)) + 1 this way, and the carriers moved to
                # the unpadded-hex arm above. For positive v this branch is now
                # unreachable by arithmetic (len(str(v)) >= hexdigit_count(v),
                # and the padded arm above already absorbed digits >=
                # hexdigit_count + 2), and the whole-population replays show
                # zero keys reaching it; it is retained so any future
                # not-fitting-any-family shape keeps the exact pre-existing
                # behavior instead of silently changing envelope accounting.
                stack.append(Num("%d." % v)); i += 6
                continue
            if len(str(v)) != digits:
                # Measured discriminator (fn_LINENO probe): a genuine int32 literal's digits
                # byte always equals len(str(value)). When it does not, this is a FOLDED
                # zero-argument builtin call (LINENO() folds to its line number) — the
                # digits byte carries the function's escape number instead. Lifting those
                # needs the funcnum->name table; unsupported until that lands.
                raise Unsupported(
                    f"zero-arg builtin call (escape 0x{digits:02x}, payload {v}) "
                    f"— funcnum table pending")
            stack.append(Num(str(v))); i += 6
        elif op == S.FLOAT:
            v = _struct.unpack_from("<d", buf, i + 3)[0]
            # r41-C: the fa header's (width, decimals) is source-spelling provenance
            # for a WRITTEN literal only. A literal carrying the 0xCC
            # constant-folded marker (see the 0xCC arm below) is a computed result
            # whose header describes the fold, not any token the author typed —
            # '2^16' reaches the wire as fa 0a 00 <65536.0> cc. Those keep the
            # incumbent value spelling; folding is irreversible either way.
            folded = i + 11 < end and buf[i + 11] == 0xCC
            stack.append(Flt(_fmt_float(v),
                             None if folded else buf[i + 1],
                             None if folded else buf[i + 2])); i += 11
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
                if jk > i and jk + 6 <= end and buf[jk] == S.ARRAY_ELEM_CALL \
                        and (buf[jk + 3] == S.SYM
                             or (buf[jk + 3] in (S.NAME, S.MEMBER,
                                                 S.ARRAY_ELEM_CALL)
                                 and _EXPR_RETRY_ACTIVE)):
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
            else:
                stack.append(WithMemberPath([nm]))
            i += 3
        elif op == S.SCOPE_OP:
            # df e3 <class-sym> f7 <member-sym>
            if i + 7 > end or buf[i + 1] != S.SCOPE_CLASS or buf[i + 4] != S.SYM:
                raise Unsupported("scope-ref shape")
            stack.append(ScopeRef(_sym(syms, S.u16(buf, i + 2)),
                                  _sym(syms, S.u16(buf, i + 5))))
            i += 7
            continue
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
                node, i = _dec_group(buf, i, end, syms)
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
    if t + 2 > end or buf[t + 1] not in (S.STR, S.STR2):
        raise Unsupported("%s AS clause without class" % what)
    typ, t = _dec_str_arg(buf, t + 1, end)
    if t >= end or buf[t] != S.PARAM_OF_MARK:
        return (name, typ, None), t
    if t + 2 > end or buf[t + 1] not in (S.STR, S.STR2):
        raise Unsupported("%s OF library unresolved" % what)
    lib, t = _dec_str_arg(buf, t + 1, end)
    return (name, typ, lib), t


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
    if j < end and buf[j] == S.NAME and allow_callee_tail:
        # RECEIVER shape: the run carries no terminal f7, so this path is the
        # object the following f6 names a method on (MemberPath.receiver).
        return MemberPath(names, receiver=True), j   # callee byte left for _dec_group
    if len(names) == 1:
        return MemberRef(names[0]), i + 3
    raise Unsupported("member path without terminal property")


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
    tail = []
    while True:
        if j >= end:
            break
        b = buf[j]
        if b in (S.SYM, S.MEMBER) and j + 3 <= end:
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
    return ObjectChain(recv, calls, tail, brackets), j


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


def _dec_group(buf, i, end, syms):
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
        return _dec_group_run(buf, i, end, syms, stack)
    finally:
        _GROUP_DEPTH -= 1
        _ARENA.pop()


def _dec_group_run(buf, i, end, syms, stack):
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
            return Call(("user", name), stack), j + 3
        if peek == S.ESCAPE:
            if j + 2 > end:
                raise Unsupported("ea callee truncated")
            ident = buf[j + 1]
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
                member_callee_tail=True)
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
            # SystemObject path prefix: e1 43 f7 <sym> acts as an object-path
            # opener (NO group closer follows); frmmainform 'this.oHost=.NULL.'
            # class assignments (iter. 38 token-walk aligned)
            return MemberPath([_sym(syms, S.u16(buf, i + 3))]), i + 5
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
        if j >= end or buf[j] != 0x03:
            raise Unsupported("indexed-member property component missing")
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
            return IndexedMemberRef(obj_name, member_name, subs[0], prop), j
        return ObjectChain([obj_name], [(member_name, subs)],
                           hops + [prop]), j
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
    # round-40 lane E: the clause head. Wire order is canonical (COLOR SCHEME,
    # SHADOW, MARGIN, IN, FROM), pinned by e01/e09/e10 against D4's all-clause
    # statement; EVERY clause is optional, the FROM list included — the stock
    # arm required it and rejected the three xfrxSHPopup* / MHGLMENUS carriers.
    scheme = None
    head_words = []
    if j + 2 <= end and buf[j:j + 2] == bytes(S.WIN_SCHEME_MARK):
        scheme, j = _fc_group(buf, j + 2, end, syms)
    if j < end and buf[j] == S.POPUP_SHADOW_MARK:
        head_words.append("SHADOW")
        j += 1
    if j < end and buf[j] == S.POPUP_MARGIN_MARK:
        head_words.append("MARGIN")
        j += 1
    if j + 4 <= end and buf[j] == S.POPUP_IN_MARK and buf[j + 1] == S.SYM:
        head_words.append("IN " + _sym(syms, S.u16(buf, j + 2)))
        j += 4
    frm = []
    if j < end and buf[j] == S.DEFINE_FROM_MARK:
        j += 1
        while True:
            e, j = _fc_group(buf, j, end, syms)
            frm.append(e)
            if j < end and buf[j] == S.ARGJOIN:
                j += 1
                continue
            break
    words = {S.POPUP_RELATIVE_MARK: "RELATIVE", S.POPUP_SHORTCUT_MARK: "SHORTCUT"}
    flags = list(head_words)
    seen = set()
    while j < end:
        word = words.get(buf[j])
        if word is None:
            raise Unsupported(
                "DEFINE POPUP clause 0x%02x unmeasured" % buf[j])
        if word in seen:
            raise Unsupported("duplicate DEFINE POPUP clause")
        seen.add(word)
        flags.append(word)
        j += 1
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
    return _fc_group(buf, j, end, syms)


def _dec_define_bar(buf, end, syms):
    # g3/g4 byte-exact: 73 06 fc<n>fd c3 f7<popup>
    #   [22 fc<PROMPT>fd] [41 fc<STYLE>fd] [1d fc<MESSAGE>fd]
    #   [17 fb<KEY>[07 fc<label>fd]] [c9 13 fc<SKIP FOR>fd] [c2 fc<PICTURE>fd]
    # canonical wire order PROMPT -> STYLE -> MESSAGE -> SKIP -> PICTURE
    # regardless of source order (round-40 e02 vs e03 compile identically, e11
    # pins the full run); the LAST present group's fd may be reader-stripped.
    j = 2
    num, j = _menu_bar_number(buf, j, end, syms)
    if isinstance(num, Paren):
        num = num.x               # source spells the ordinal bare ('Define Bar 1 Of …')
    bar_num = num if isinstance(num, str) else _emit(num)
    if j >= end or buf[j] != S.DEFINE_BAR_OF:
        raise Unsupported("DEFINE BAR OF missing")
    j += 1
    if j + 3 <= end and buf[j] == S.SYM:
        of_popup = _sym(syms, S.u16(buf, j + 1))
        j += 3
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
    if j < end and buf[j] == S.BAR_STYLE_MARK:
        j += 1
        style, j = _fc_group(buf, j, end, syms)
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
            bid = buf[j + 2]
            j += 3
            if j < end and buf[j] == S.FD:
                j += 1
            if bid not in S.MENU_BAR_IDS:
                raise Unsupported(
                    "DEFINE BAR PICTRES id 0x%02x unmeasured" % bid)
            pictres = S.MENU_BAR_IDS[bid]
        else:
            node, j = _fc_group(buf, j, end, syms)
            pictres = _emit(node)
    if j != end:
        raise Unsupported(
            "DEFINE BAR clause 0x%02x unmeasured" % buf[j])
    return DefineStmt("BAR", bar_num=bar_num, of_popup=of_popup, prompt=prompt,
                      style=style, message=message, key=key,
                      skip_for=skip_for, picture=picture, pictres=pictres)


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
    # closer); optional c0 separator; 02 opens the field list.
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
    if j < end and buf[j] == 0xC0:
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
        nullable = False
        if had_size:
            if j >= end or buf[j] != 0x03:
                raise Unsupported("CREATE CURSOR field tail 0x%02x" % buf[j])
            j += 1
            # round-29 contextual column-NULL clause: d6 measured ONLY here,
            # directly after the per-field closer (15-carrier dashboard*.scx
            # cluster). Any other position still raises field tail below.
            if j < end and buf[j] == 0xD6:
                nullable = True
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
    return CreateCursor(name, fields, codepage, table=(buf[1] == 0x31))


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
    if j < end and buf[j] == S.DEFINE_FROM_MARK:          # FROM MEMVAR tail
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
    raise Unsupported("INSERT INTO body missing")


def dec_set_value(buf, i, end, syms):
    """One SET TO-value, both measured spellings (population lane SET):
    - grouped: 'fc <expr> [03-paren] [fd]'  ('SET CLASSLIB TO (THIS.x) …',
      '(m.liDeci)' — the 03 is the PAREN postfix INSIDE the group);
    - bare:    ONE fb string operand        ('SET ORDER TO Revert',
      'SET CLASSLIB TO foxchartsBeta.vcx').
    Returns (node, next_index); anything else raises Unsupported."""
    if i < end and buf[i] == S.FC:
        es, k = _dec_expr(buf, i + 1, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("SET variant outside forced subset")
        if k < end and buf[k] == S.FD:
            k += 1
        return es[0], k
    if i + 3 <= end and buf[i] == S.STR:
        n = S.u16(buf, i + 1)
        if i + 3 + n > end:
            raise Unsupported("SET variant outside forced subset")
        return Str(_payload_text(buf[i + 3:i + 3 + n])), i + 3 + n
    raise Unsupported("SET variant outside forced subset")


def _emit_set_order_tag(node):
    """SET ORDER TO tag. r42-kwperm: quote characters ride in the fb payload
    (`Revert` / `'Revert'` / `"Revert"` are three frames). Emit the payload
    as spelled; do not wrap a bare tag as a string literal."""
    if isinstance(node, Str):
        return node.text
    return _emit(node)


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
    raise Unsupported(
        "SCATTER/GATHER variant outside measured round-17 forms")


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


@dataclass
class CalculateStmt:
    """7d 28 <targets> (<fn> 02 fc <expr> fd 03)+ - CALCULATE, targets first;
    item selectors c2=SUM (CMD_SWEEP row + fxresetpagetotal gold pair) and
    be=MAX (managecode.scx gold pair 'CALCULATE MAX(KEYID) TO X')."""
    targets: list     # lvalue nodes
    items: list       # (function-name, expr-node) pairs


@dataclass
class ReportFormStmt:
    """3f 14 <form> [28 12 fc..fd] [2e d4 fc..fd] [c1] [3a] - REPORT FORM;
    TO FILE (28+12), OBJECT TYPE (2e+d4), PREVIEW c1 / NOWAIT 3a per the
    foxchartsbeta / buyswwprint / pidocchk gold pairs."""
    form: object
    objtype: object = None
    to_file: object = None
    preview: bool = False
    nowait: bool = False


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
    """
    if i >= end or buf[i] != S.CALL_OPEN:
        return None
    j = i + 1
    distinct = False
    if j + 1 < end and buf[j] == S.ESCAPE and buf[j + 1] == S.SQLSEL_AGG_DISTINCT:
        distinct = True
        j += 2
    if j < end and buf[j] == S.SQLSEL_AGG_STAR:
        inner = "*"
        j += 1
    elif j + 2 < end and buf[j] == S.SYM:
        inner = _sym(syms, S.u16(buf, j + 1))
        j += 3
    else:
        return None
    if j + 1 >= end or buf[j] != S.ESCAPE:
        return None
    name = S.SQLSEL_AGG.get(buf[j + 1])
    if name is None:
        return None
    j += 2
    if distinct:
        inner = "DISTINCT " + inner
    return SqlAgg(name, inner), j


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
    global _EXPR_RETRY_ACTIVE, _STMT_MIDWINDOW_FIRED
    _reset_arg_byref_close()   # r38: no 18-f6 flag may cross a statement edge
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


def _dec_statement(buf, syms):
    end = len(buf)
    lead = buf[0]
    j = 1
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
            if ak < end and buf[ak] == 0x16:
                closer = buf[ak]
                ak += 1
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
                # NO recv_with here: the wire encodes scoped and plain member
                # array puts identically (e2 f6 <sym> ...), and the frozen
                # already-lifted corpus pins the undotted rendering for the
                # cmdEnter/_dialogs carriers whose stored source happens to
                # spell '.aChoices[lnItemID]' dotted. Dot fidelity for WITH-
                # scoped put targets is W3's shared walker decision; widening
                # it here costs 3 lines of text-drift on already-lifted
                # methods (diffsrc gate), so the historical form stands.
                # The SUBSCRIPT spelling is a different question and is
                # recorded: this arm is entered only on the 16 closer, i.e. on
                # a source that wrote '[ … ]' (_reportlistener's own stored
                # 'THIS.ReportPages[1] = 0' beside its paren-spelled
                # 'DIME THIS.reportPages(THIS.ReportFileNames.Count,2)').
                return Assign(MethodCall(list(recv), "", aes,
                                         bracket=closer == 0x16), es[0])
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
        if lead == 0x35 and end >= 3 and buf[1:3] == bytes([0x03, 0x18]):
            if end == 3:
                raise Unsupported("PRIVATE ALL LIKE pattern missing")
            skeleton, t = _dec_str_arg(buf, 3, end)
            if t != end:
                raise Unsupported("PRIVATE ALL LIKE trailing bytes")
            return PrivateAllLike(skeleton)
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
                # '35 f5 0d f7' (foxchartsbeta _drawcone-family stmt4, x2)
                if t + 3 <= end and buf[t] == S.SYM:
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
                if t + 4 > end or buf[t + 1] not in (S.STR, S.STR2):
                    raise Unsupported("LOCAL type clause unwrapped")
                ln = S.u16(buf, t + 2)
                if t + 4 + ln > end:
                    raise Unsupported("LOCAL type clause truncated")
                typ = _payload_text(buf[t + 4:t + 4 + ln])
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
                    t += 3 + ln
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
        # round-24 m5 byte-exact: 09 2c f7<w> [27 fc<TITLE>fd] [ce fc<TIMEOUT>fd];
        # the trailing TIMEOUT group's fd is reader-stripped when final.
        # Round-28 W4 measured widenings: bare 09 = plain BROWSE (corpus x71,
        # getbom cdYes s0 stmt57); leading 11 = FIELDS clause whose items are
        # `f7 <field> [c9 <int>] [c2 10 fc<picture>[fd]]` joined by 07
        # (pricelistdetail Command1 s0 stmt16, preorder Command4 s0 stmt35,
        # bincode CdCost s0 stmt39 — WINDOW/TITLE/TIMEOUT follow FIELDS on the
        # wire exactly as in those carriers).
        # Round-31 measured widenings (alignment-table.md, same-record stored
        # sources): FIELDS items may carry `bf 10 fc<heading>fd` = :H='<..>'
        # (testrecord/attendancereadrecord frmattendancerecord s3 'code:10 :H =
        # ..' and s4 'code:h=..:10'), and a lead-position `13 fc<cond>fd` =
        # BROWSE .. FOR <cond> (attendanceset frmWeixiu s1 stmts 25/34; 13 =
        # SCAN/LOCATE FOR marker byte).
        # Round-31 hardening: the per-item attribute grammar is the FINITE
        # sequence matrix
        #   ∅ | W | P | W P      — everything the pre-round-31 fixed reader
        #                          admitted (name, then optional one width,
        #                          then optional one picture)
        #   W H | H W            — exactly the two orders the round-31
        #                          carriers spell on the wire (s3 ':10 :H =',
        #                          s4 ':h=..:10')
        # each attribute at most once; any repetition or other interleaving
        # raises. FOR composes with the WINDOW head only — no carrier shows
        # FOR + FIELDS, so that pair rejects.
        if end == 1:
            return ("BROWSE",)
        t = 1
        for_cond = None
        if t + 1 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
            for_cond, t = _fc_group(buf, t + 1, end, syms)
        fields = []
        if t < end and buf[t] == S.COPY_LEAD:   # 11 FIELDS, context-local under 09
            t += 1
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
                        if order not in ([], ["h"]):
                            raise Unsupported(
                                "BROWSE FIELDS attribute sequence unmeasured")
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
                        if order not in ([], ["w"]):
                            raise Unsupported(
                                "BROWSE FIELDS attribute sequence unmeasured")
                        order.append("p")
                        t += 2
                        try:
                            pic, t = _fc_group(buf, t, end, syms)
                        except Unsupported:
                            raise Unsupported("BROWSE FIELDS picture unresolved")
                    elif buf[t] == 0xBF:
                        # :H heading — only the measured sub-op 10 (the same EQ
                        # byte the :P arm reads after c2) is admitted
                        t += 1
                        if t >= end or buf[t] != S.EQ:
                            raise Unsupported(
                                "BROWSE clause 0xbf unmeasured")
                        if order not in ([], ["w"]):
                            raise Unsupported(
                                "BROWSE FIELDS attribute sequence unmeasured")
                        order.append("h")
                        try:
                            heading, t = _fc_group(buf, t + 1, end, syms)
                        except Unsupported:
                            raise Unsupported("BROWSE FIELDS heading unresolved")
                    else:
                        break
                # exact membership: the allowed set is exactly [], W, P,
                # W P (parent reader) plus the carrier-measured W H / H W.
                # The partial guards above only bound transitions; this
                # closes the matrix — heading-only [H] has no carrier and
                # must not lift.
                if order not in ([], ["w"], ["p"], ["w", "p"],
                                 ["w", "h"], ["h", "w"]):
                    raise Unsupported(
                        "BROWSE FIELDS attribute sequence unmeasured")
                fields.append((fname, width, pic, heading))
                if t >= end:
                    break
                if buf[t] == S.ARGJOIN:
                    t += 1
                    continue
                break
            if for_cond is not None:
                # measured FOR carriers carry a WINDOW head, never FIELDS;
                # this composition stays unmeasured
                raise Unsupported("BROWSE FOR + FIELDS composition unmeasured")
        window = None
        title = timeout = None
        if t < end and buf[t] == S.DEFINE_WINDOW_KW:
            if t + 3 > end or buf[t + 1] != S.SYM:
                raise Unsupported("BROWSE WINDOW frame shape")
            window = _sym(syms, S.u16(buf, t + 2))
            t += 4                      # 2c f7 <u16>
        elif len(fields) == 0:
            # a lone 13-FOR prefix (or FOR/TITLE without a head) stays here:
            # the measured envelope always carries WINDOW or FIELDS after it
            raise Unsupported("BROWSE WINDOW frame shape")
        if t < end and buf[t] == S.BROWSE_TITLE_MARK:
            title, t = _fc_group(buf, t + 1, end, syms)
        if t < end and buf[t] == S.BROWSE_TIMEOUT_MARK:
            timeout, t = _fc_group(buf, t + 1, end, syms)
        if t != end:
            raise Unsupported(
                "BROWSE clause 0x%02x unmeasured" % buf[t])
        return BrowseWindow(window, title=title, timeout=timeout,
                            fields=fields, for_cond=for_cond)
    if lead == S.CREATE_CURSOR_LEAD:
        return _dec_create_cursor(buf, end, syms)
    if lead == S.CREATE_LEAD:
        return _dec_create(buf, end, syms)
    if lead == S.INSERT_LEAD:
        return _dec_insert_into(buf, end, syms)
    if lead == S.RETURN:
        if j == end:
            return Return(None)
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
        return Return(es[0])
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
        # TEXT frame opener — round-23 FORCED: bare '4d', else 4d 28 <target>
        # [flags]. Target is an alias-M run (m.x spelling, f5 0d f7) or a plain
        # f7 name; flags are the canonical wire subset 60/ce/01. Round-28 W4
        # measured target widenings: WITH-scoped refs (e2, foxchartsbeta
        # _drawcone s21[17] / radialgauge addshape s8[5]) and member paths with
        # a terminal sym ('TEXT TO This.oNode.something' workerchart
        # showmemberinfo s4[1] = f4 f4 f7 chain).
        if end == 1:
            return TextStmt(None, [])
        if end < 2 or buf[1] != S.TO_MARK:
            raise Unsupported("TEXT TO frame shape")
        t = 2
        if t + 5 <= end and buf[t] == S.WORKAREA_REF and buf[t + 1] == 0x0D \
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
        flag_names = {S.TEXT_FLAG_TEXTMERGE: "TEXTMERGE",
                      S.TEXT_FLAG_NOSHOW: "NOSHOW",
                      S.TEXT_FLAG_ADDITIVE: "ADDITIVE"}
        flags = []
        while t < end:
            if buf[t] == S.TEXT_FLAG_PRETEXT:
                # round-37 C07/J1 (oracle probe J1, byte-exact): PRETEXT rides
                # THIRD in the fixed opener order 60 -> ce -> c3 and carries its
                # numeric argument as an fc-wrapped INT8 literal —
                # 'PRETEXT 2' = c3 fc f8 01 02 (J1). Corpus twins measure the
                # same envelope for exactly TWO flag prefixes: aatest.scx::
                # frstestharn '{TEXTMERGE,NOSHOW} PRETEXT 14' = fc f8 02 0e,
                # sstextbox.scx::Edit1 '{NOSHOW} PRETEXT 1' = fc f8 01 01.
                # Measured shapes ONLY: those two prefixes and nothing else —
                # bare c3, {60,c3}, ADDITIVE mixes (relative order to c3 never
                # measured), duplicates and reorders are unmeasured and stay
                # loudly Unsupported; the argument must be exactly
                # fc f8 <digits> <u8> with digits == len(str(v)) ending the
                # statement — truncated, wider, non-f8 or trailing-byte shapes
                # likewise. Never guessed around.
                if flags not in (["TEXTMERGE", "NOSHOW"], ["NOSHOW"]):
                    raise Unsupported(
                        "TEXT flag order violates measured 60->ce->c3")
                if t + 5 != end or buf[t + 1] != S.FC \
                        or buf[t + 2] != S.INT8:
                    raise Unsupported("TEXT PRETEXT argument shape")
                val = buf[t + 4]
                if buf[t + 3] != len(str(val)):
                    raise Unsupported(
                        "TEXT PRETEXT literal digits byte %d" % buf[t + 3])
                flags.append("PRETEXT %d" % val)
                break
            fl = flag_names.get(buf[t])
            if fl is None:
                raise Unsupported(
                    f"TEXT clause flag 0x{buf[t]:02x} unmeasured")
            flags.append(fl)
            t += 1
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
        return ForEachStmt(var, coll, fox, rel_target=rel)
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
    if lead == 0x0B or lead == 0xB7:
        # CANCEL / DOEVENTS: oracle-bound one-byte statements (CMD_SWEEP.md
        # bound-command rows CANCEL '0b' and DOEVENTS 'b7'). Corpus-aligned as
        # bare single bytes only: 0b x17 (charts.scx::CmdPrint s0 stmt13,
        # print.scx::cgPrint s4 stmt4, ...) and b7 x7 (_webview.vcx
        # refreshsource s17..s19, _webbrowser3 s45..s47).
        if end != 1:
            raise Unsupported("statement lead 0x%02x trailing bytes" % lead)
        return ("CANCEL",) if lead == 0x0B else ("DOEVENTS",)
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
        if end == 2 and buf[1] in (0x31, 0xC2):
            return ("CLOSE TABLES",) if buf[1] == 0x31 \
                else ("CLOSE DATABASES",)
        if end == 3 and buf[1] in (0x31, 0xC2) and buf[2] == S.PAREN:
            kw = "CLOSE TABLES" if buf[1] == 0x31 else "CLOSE DATABASES"
            return (kw + " ALL",)
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
            # ID is census-measured ONLY together with its NOWAIT marker
            # (cmdHelp 'HELP ID (...) NOWAIT'); an ID clause without the 3a
            # byte is an unmeasured spelling and rejects (round-29 review).
            t += 1
            id_expr, t = _fc_group(buf, t, end, syms)
            if t >= end or buf[t] != 0x3A:
                raise Unsupported("statement lead 0x24 trailing bytes")
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
    if lead == 0x80:
        # SHOW WINDOW <name> IN WINDOW <parent>: census fxtherm s16 stmt17 /
        # updatelistener s29 'SHOW WINDOW (.Name) IN WINDOW
        # (m.lcParentFormName)' <-> 80 2c 16 <parent-group> <name-group>; the
        # wire carries the IN-WINDOW argument FIRST and both operands arrive
        # as parenthesised fc-groups. Other SHOW WINDOW clauses stay blocked.
        if end < 4 or buf[1] != 0x2C or buf[2] != 0x16:
            raise Unsupported("statement lead 0x80")
        in_win, t = _fc_group(buf, 3, end, syms)
        name, t = _fc_group(buf, t, end, syms)
        if t != end:
            raise Unsupported("statement lead 0x80 trailing bytes")
        return ShowWindowStmt(name, in_win)
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
        # MOUSE AT <row>, <col> WINDOW <w> PIXELS: exact five-part corpus
        # shape xfcont s16 stmt48 'MOUSE AT liMTop,liMLeft WINDOW
        # (Thisform.Name) PIXELS' <-> ad ca 2c <w-group> 05 <r-group>
        # 07 <c-group>. ca rides this carrier's PIXELS word; the sweep CLICK
        # row ('adc305..') binds c3 separately and stays unimplemented here.
        if end < 4 or buf[1] != 0xCA or buf[2] != 0x2C:
            raise Unsupported("statement lead 0xad")
        window, t = _fc_group(buf, 3, end, syms)
        if t >= end or buf[t] != 0x05:
            raise Unsupported("MOUSE AT clause missing")
        row, t = _fc_group(buf, t + 1, end, syms)
        if t >= end or buf[t] != S.ARGJOIN:
            raise Unsupported("MOUSE coordinate pair malformed")
        col, t = _fc_group(buf, t + 1, end, syms)
        if t != end:
            raise Unsupported("statement lead 0xad trailing bytes")
        return MouseStmt(row, col, window)
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
        if t < end and buf[t] == S.FC:
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SKIP expression unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            elif k != end:
                raise Unsupported("SKIP expression unresolved")
            n_expr = es[0]
            t = k
        if t < end and buf[t] == S.GO_IN_CLAUSE:
            t += 1
            if t + 3 <= end and buf[t] == S.SYM:
                area = _sym(syms, S.u16(buf, t + 1))
                t += 3
            else:
                raise Unsupported("SKIP IN area unresolved")
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
        if t < end and buf[t] == 0xCC:
            structure = True
            t += 1
        elif t < end and buf[t] in (0xD4, 0xBE):
            # DELIMITED WITH chain; d4 is the traceless TYPE noise word when
            # the source spells 'TYPE DELIMITED'. Measured shape is exactly
            # [d4] be d1 bf {fb/d9 <char> | c4(TAB)}: goods.txt/containers.txt
            # carry the string form, attendanceforcheck cdget s0[40] the TAB
            # form ('APPEND FROM \'KQ.txt\' TYPE DELIMITED WITH TAB').
            if buf[t] == 0xD4:
                t += 1
            if t >= end or buf[t] != 0xBE:
                raise Unsupported("COPY trailing bytes")
            t += 1
            if t + 2 >= end or buf[t] != 0xD1 or buf[t + 1] != 0xBF:
                raise Unsupported("COPY trailing bytes")
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
                        delimited=delimited)
    if lead == S.RELEASE_LEAD:
        if end == 2 and buf[1] == 0x03:
            return ReleaseAll()          # RELEASE ALL (frmmainform 3c 03)
        if end == 5 and buf[1] == S.DEFINE_WINDOW_KW and buf[2] == S.SYM:
            # RELEASE WINDOW <name> (round-24 m6 byte-exact; corpus
            # mainmenur.scx::cdtj 'RELEASE WINDOW wbrowse'). This is the shape
            # the lvalue reader mis-charged as "lvalue opcode 0x2c".
            return ReleaseStmt(["WINDOW " + _sym(syms, S.u16(buf, 3))])
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
        t = 1
        all_scope = False
        if buf[t] == 0x03:
            if not (t + 2 < end and buf[t + 1] == 0x13 and buf[t + 2] == S.FC):
                raise Unsupported("LOCATE FOR unwrapped")
            all_scope = True
            t += 1
        if buf[t] != 0x13 or buf[t + 1] != S.FC:
            raise Unsupported("LOCATE FOR unwrapped")
        # Round-33 (locate_while lane): the FOR window stops at its own fd so a
        # trailing clause unit can follow it. A top-level fd never had an
        # expression arm — stock always raised 'expression opcode 0xfd' there —
        # so the stop byte cannot change the parse of any already-lifting
        # shape: with no fd in its window this decodes exactly as before.
        es, k = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
        if len(es) != 1:
            raise Unsupported("LOCATE FOR expression unresolved")
        while_cond = None
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
            ws, k2 = _dec_expr(buf, k + 2, end, syms,
                               stop_bytes=_IF_COND_STOP)
            if len(ws) != 1 or k2 != end:
                raise Unsupported("LOCATE WHILE unresolved")
            while_cond = ws[0]
            k = k2
        if k != end:
            raise Unsupported("LOCATE FOR expression unresolved")
        return LocateFor(es[0], all_scope=all_scope, while_cond=while_cond)
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
                    # utilityreportlistener; _keywords 'ALIAS "keywords"')
                    alias, j = _dec_str_arg(buf, j, end)
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
        if end >= 2 and buf[1] == 0xBE:
            # round-28 W4: EXTERNAL PROCEDURE <name>
            # (xfrxlib Xfrxcmd1 s0 stmt6 'EXTERNAL PROCEDURE
            # _XFPRINTERPROPERTIES' <-> 90 be fb<name>)
            t = 2
            if t + 3 > end or buf[t] not in (S.STR, S.STR2):
                raise Unsupported("statement lead 0x90")
            nm, t = _dec_str_arg(buf, t, end)
            if t != end:
                raise Unsupported("statement lead 0x90")
            return ExternalStmt("PROCEDURE", nm)
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
        # Round-17 oracle-measured forms ONLY (probes/oracle_harvest/
        # round17_streams.json): SCATTER TO <array> = 5e 28 f7 <sym> and
        # SCATTER MEMVAR MEMO = 5e 1b c2. The selector bytes stay contextual
        # BENEATH this lead — never global tokens — so strict shape checks fail
        # loudly on every other 5e spelling (bare MEMVAR/MEMO variants included).
        if end == 3 and buf[1] == S.SCATTER_MEMVAR_MARK \
                and buf[2] == S.SCATTER_MEMO_MARK:
            return ScatterStmt(memvar=True, memo=True)
        if end == 5 and buf[1] == S.TO_MARK and buf[2] == S.SYM:
            return ScatterStmt(target=_sym(syms, S.u16(buf, 3)))
        if end >= 2 and buf[1] == 0x4A:
            # round-28 W4: SCATTER NAME <operand>
            node, t = _name_operand(buf, 2, end, syms)
            if t != end:
                raise Unsupported(
                    "SCATTER variant outside measured round-17 forms")
            return ScatterStmt(name_obj=_emit(node))
        # round-42 I8 (probes/oracle_harvest/round42_scatter_streams.json):
        # SCATTER MEMO NAME <bare-sym> = 5e 1b 4a f7 <u16>, length 6.
        # 1b is MEMO under the NAME form (s0001 vs s0009 MEMVAR NAME).
        if end == 6 and buf[1] == 0x1B and buf[2] == 0x4A and buf[3] == S.SYM:
            return ScatterStmt(name_obj=_sym(syms, S.u16(buf, 4)), memo=True)
        # same lane: SCATTER MEMO BLANK NAME <bare-sym> = 5e 08 1b 4a f7 <u16>,
        # length 7. The round-28 W4 arm below still requires FIELDS LIKE plus
        # a path/m.x NAME operand; that spelling is unchanged.
        if end == 7 and buf[1:4] == bytes([0x08, 0x1B, 0x4A]) and buf[4] == S.SYM:
            return ScatterStmt(name_obj=_sym(syms, S.u16(buf, 5)),
                               memo_blank=True)
        if end >= 12 and buf[1:4] == bytes([0x08, 0x1B, 0x4A]):
            # round-28 W4 full form (_reportlistener s54[7]):
            # 'SCATTER MEMO BLANK NAME <path> FIELDS LIKE <skeleton>'
            node, t = _name_operand(buf, 4, end, syms)
            if t + 4 > end or buf[t] != 0x11 or buf[t + 1] != 0xBC \
                    or buf[t + 2] != S.STR:
                raise Unsupported(
                    "SCATTER variant outside measured round-17 forms")
            skeleton, t = _dec_str_arg(buf, t + 2, end)
            if t != end:
                raise Unsupported(
                    "SCATTER variant outside measured round-17 forms")
            return ScatterStmt(name_obj=_emit(node), memo_blank=True,
                               like_skeleton=skeleton)
        raise Unsupported("SCATTER variant outside measured round-17 forms")
    if lead == S.GATHER_LEAD:
        # Sole measured form (round-17 streams): GATHER FROM <array>
        # = 5f 15 f7 <sym>; 15 is contextual under this lead, never global.
        if end == 5 and buf[1] == S.GATHER_FROM_MARK and buf[2] == S.SYM:
            return GatherStmt(_sym(syms, S.u16(buf, 3)))
        if end >= 2 and buf[1] == 0x4A:
            # round-28 W4: GATHER NAME <m.x | path> (see SCATTER arm helper;
            # _reportlistener s54 stmt12 'GATHER NAME THIS.evaluateContentsValues')
            node, t = _name_operand(buf, 2, end, syms)
            if t != end:
                raise Unsupported(
                    "GATHER variant outside measured round-17 forms")
            return GatherStmt(name_obj=_emit(node))
        raise Unsupported("GATHER variant outside measured round-17 forms")
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
        if j < end and buf[j] == 0x03:
            scan_all = True
            j += 1
        if j < end and buf[j] in (0x13, 0x2B):
            is_while = buf[j] == 0x2B
            clause_while = is_while
            if is_while and scan_all:
                raise Unsupported("SCAN ALL WHILE unmeasured")
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
                        rel_target=rel_target)
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
        if end == 5 and buf[1] == S.GO_IN_CLAUSE and buf[2] == S.SYM:
            alias = _sym(syms, S.u16(buf, 3))
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
    if lead == S.APPEND_LEAD:
        if end == 1:
            return ("APPEND",)
        if end == 2 and buf[1] == 0x08:
            return ("APPEND BLANK",)   # BLANK=0x08 clause; aligned dashboard.scx etc.
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
            if j < end and buf[j] in (S.STR, S.STR2):
                nm, j = _dec_str_arg(buf, j, end)
                es = [Str(nm)]
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
            if j < end and buf[j] in (0xD4, 0xBE):
                if buf[j] == 0xD4:
                    j += 1
                if j + 2 >= end or buf[j] != 0xBE \
                        or buf[j + 1] != 0xD1 or buf[j + 2] != 0xBF:
                    raise Unsupported("APPEND trailing bytes (variants unforced)")
                j += 3
                if j < end and buf[j] == 0xC4:
                    delimited = ("TAB",)
                    j += 1
                elif j < end and buf[j] in (S.STR, S.STR2):
                    delim_char, j = _dec_str_arg(buf, j, end)
                    delimited = ("CHARACTER", delim_char)
                else:
                    raise Unsupported("APPEND trailing bytes (variants unforced)")
            if j != end:
                raise Unsupported("APPEND trailing bytes (variants unforced)")
            return AppendFromStmt(es[0], cond=cond, fields=fields,
                                  delimited=delimited)
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
            to_target = None
            if t < end and buf[t] == S.TO_MARK:
                to_target, t = _dec_lvalue(buf, t + 1, end, syms)
            args = []
            if t < end and buf[t] == S.REPLACE_WITH:
                t += 1
                while True:
                    if t >= end:
                        raise Unsupported("DO FORM argument unresolved")
                    if buf[t] == S.SYM:
                        if t + 3 > end:
                            raise Unsupported("DO FORM argument truncated")
                        args.append(Sym(_sym(syms, S.u16(buf, t + 1))))
                        t += 3
                    elif buf[t] in (S.MEMBER, S.WITHREF):
                        try:
                            node, k = _dec_path(buf, t, end, syms)
                        except Unsupported:
                            raise Unsupported("DO FORM argument unresolved")
                        args.append(node)
                        t = k
                    elif buf[t] == S.FC:
                        es, k = _dec_expr(buf, t + 1, end, syms,
                                          stop_bytes=_IF_COND_STOP)
                        if len(es) != 1:
                            raise Unsupported("DO FORM argument unresolved")
                        if k < end and buf[k] == S.FD:
                            k += 1
                        args.append(es[0])
                        t = k
                    else:
                        raise Unsupported("DO FORM argument form")
                    if t >= end:
                        break
                    if buf[t] != S.ARGJOIN:
                        raise Unsupported("DO FORM argument tail")
                    t += 1
            if t != end:
                raise Unsupported("DO FORM trailing bytes")
            return DoStmt(prog, args, form=True, to_target=to_target)
        prog = None
        t = 1
        if buf[1] in (S.STR, S.STR2):
            nm, j = _dec_str_arg(buf, 1, end)
            prog = nm
            t = j
            args = []
            return DoStmt(prog, args)
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
            elif k != end:
                raise Unsupported("DO program expression unresolved")
            args = []
            if k < end and buf[k] == S.REPLACE_WITH:
                k += 1
                while True:
                    if k + 3 <= end and buf[k] == S.SYM:
                        # round-33 measured argument spelling: bare symbol
                        # push ('DO (_GENHTML) WITH lcFile, ...',
                        # _reports.vcx::_output s16 stmt49)
                        args.append(Sym(_sym(syms, S.u16(buf, k + 1))))
                        k += 3
                    elif k < end and buf[k] == S.MEMBER:
                        # round-33 measured path argument: an f4-run with ONE
                        # terminal f7; an incomplete run keeps the stock
                        # rejection below
                        hops = []
                        while k + 3 <= end and buf[k] == S.MEMBER:
                            hops.append(_sym(syms, S.u16(buf, k + 1)))
                            k += 3
                        if k + 3 > end or buf[k] != S.SYM:
                            raise Unsupported("DO WITH argument unwrapped")
                        hops.append(_sym(syms, S.u16(buf, k + 1)))
                        k += 3
                        args.append(MemberPath(hops))
                    elif buf[k] != S.FC:
                        raise Unsupported("DO WITH argument unwrapped")
                    else:
                        aes, ak = _dec_expr(buf, k + 1, end, syms, stop_bytes=_IF_COND_STOP)
                        if len(aes) != 1:
                            raise Unsupported("DO WITH argument unresolved")
                        if ak >= end:
                            # MEASURED (_base.vcx::_checkbox.setobjectref: 'DO
                            # (this.cSetObjRefProgram) WITH (this),(tcName),
                            # (tvClass),(tvClassLibrary)'): the FINAL argument's
                            # closing fd is reader-stripped like an assignment RHS,
                            # so the last argument may run to end-of-statement.
                            args.append(aes[0])
                            break
                        if buf[ak] != S.FD:
                            raise Unsupported("DO WITH argument unresolved")
                        args.append(aes[0])
                        ak += 1
                        if ak == end:
                            break
                        if buf[ak] != S.ARGJOIN:
                            raise Unsupported("DO WITH argument tail")
                        k = ak + 1
                        continue
                    if k == end:
                        break
                    if buf[k] != S.ARGJOIN:
                        raise Unsupported("DO WITH argument tail")
                    k += 1
            elif k != end:
                raise Unsupported("DO trailing bytes")
            return DoStmt(es[0], args)
        if end >= 2 and buf[1] == S.SYM:
            # DO <program-name-by-symbol>: the payload is a SYMBOL PUSH, not a
            # jump word — ORACLE round-25 BOUND (d1 'DO someloc' -> 18 f7<sym>,
            # d2 local-procedure identical; corpus alignment
            # txtcollectqichachaclean.scx::frmtxtcollectclean s0 stmt[426]
            # 'DO ReduceMemory' = 18 f7 8800 with REDUCEMEMORY that section's
            # last symbol).
            # LOOP(2e)/EXIT(21) are standalone one-byte statements, NOT 18-led
            # (round-25 REFUTED the 18-led hypothesis).
            # Round-32: a trailing arm of EXACTLY `d1 f7<sym> (07 f7<sym>)*`
            # is the compiled WITH list of BARE SYMBOL arguments — no fc-group
            # wrapping, unlike the parenthesised arm above (which owns
            # tests/test_sql_dowith.py's DOWITH_REAL pins). Measured carriers:
            # 'DO GetReport WITH codeid' <-> 18 f77500 d1 f75300
            # (buyswwprint.scx::CdSend stmts[183]/[345]; identical bytes
            # weiwaiemail.scx::CdSend stmts[45]/[189]) and three args joined by
            # ARGJOIN <-> 18 f71000 d1 f70d00 07 f70e00 07 f70c00
            # (pisupply.scx::Command10 stmt[16], 'DO EVERYDAY WITH P_FILENAME,
            # P_ID, P_EDITMODE'). Anything else after the push stays
            # Unsupported: no-d1 tails, dangling joiners, non-f7 argument
            # spellings (member/fc-group), truncated pushes, bare d1, extra
            # tail — each costs one statement, never the module.
            t3 = 4
            eargs = []
            if t3 < end and buf[t3] == S.REPLACE_WITH:
                t3 += 1
                while True:
                    if t3 + 3 <= end and buf[t3] == S.SYM:
                        eargs.append(Sym(_sym(syms, S.u16(buf, t3 + 1))))
                        t3 += 3
                    elif t3 < end and buf[t3] == S.FC:
                        # round-33 measured fc-group argument ('DO RunCode
                        # WITH (tcCode)', _webview.vcx::_webbrowser3 s10
                        # stmt18 <-> 18 f70d00 d1 fcf70000 03 fd); the same
                        # final-fd-may-be-stripped rule as the parenthesised
                        # arm applies to the list's last group
                        try:
                            aes, ak = _dec_expr(buf, t3 + 1, end, syms,
                                                stop_bytes=_IF_COND_STOP)
                        except Unsupported:
                            raise Unsupported(
                                "unsupported 0x18 frame subtype")
                        if len(aes) != 1:
                            raise Unsupported("unsupported 0x18 frame subtype")
                        if ak >= end:
                            eargs.append(aes[0])
                            t3 = ak
                        elif buf[ak] == S.FD:
                            eargs.append(aes[0])
                            t3 = ak + 1
                        else:
                            raise Unsupported("unsupported 0x18 frame subtype")
                    else:
                        raise Unsupported("unsupported 0x18 frame subtype")
                    if t3 == end:
                        break
                    if buf[t3] != S.ARGJOIN:
                        raise Unsupported("unsupported 0x18 frame subtype")
                    t3 += 1
            elif end != 4:
                raise Unsupported("unsupported 0x18 frame subtype")
            return DoStmt(_sym(syms, S.u16(buf, 2)), eargs)
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
            # UNION-form SQL SELECT. MEASURED on the full pinned benchmark: 5
            # statements, 2 byte shapes, every stored source a two-arm UNION ALL
            # with arms emitted in REVERSE source order:
            #   6f c4 03e8 0c0000  15 t1 c7 15 t2 c7 c3 fc <n> fd 3c bc bd cur
            #     = 'SELECT * FROM tmpop2 UNION ALL SELECT * FROM tmpop1
            #        ORDER BY 3 DESC INTO CURSOR tmpop'  (buypricecheck/preorder/
            #        preorderrz/danzhengmake — star arms carry no column section)
            #   6f c4 03e8 140000  be 15 T fc MB018 fd be 15 T fc MB067 fd 51 CG
            #                      bc bd rmb1 d7
            #     = 'SELECT distinct MB067 AS CG FROM TMPINVMB1 UNION ALL
            #        SELECT distinct MB018 FROM TMPINVMB1 INTO CURSOR rmb1
            #        READWRITE'  (chgman)
            # Arm grammar: [be(DISTINCT, HARVEST 'be=DISTINCT')] 15 <table>
            # [fc <col> fd [51 <alias>]]*; consecutive arms either abut or join
            # via c7 when the next token opens another arm. The u24 after the
            # constant 03 e8 pair equals the summed lengths of the arms' table
            # names plus column aliases (cursor excluded) — verified below.
            # Plain UNION is not distinguishable in bytecode from these samples;
            # both measured junctions are UNION ALL and emit as such.
            j += 1
            if buf[j:j + 2] != bytes(S.SQL_UNION_CONST):
                raise Unsupported("SQL SELECT header mismatch")
            want_id_len = int.from_bytes(buf[j + 2:j + 5], "little")
            j += 5
            arms = []
            id_len = 0
            while True:
                distinct = False
                if j < end and buf[j] == S.SQL_DISTINCT_MARK:
                    distinct = True
                    j += 1
                if j >= end or buf[j] != 0x15:
                    raise Unsupported("SQL SELECT header mismatch")
                j += 1
                tbl_a, j = _dec_str_arg(buf, j, end)
                id_len += len(tbl_a)
                arm_cols = []
                while j < end and buf[j] == S.FC:
                    ces, ck = _dec_expr(buf, j + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(ces) != 1 or ck >= end or buf[ck] != S.FD:
                        raise Unsupported("SQL SELECT column unresolved")
                    ck += 1
                    alias = None
                    if ck + 4 <= end and buf[ck] == 0x51 and buf[ck + 1] == S.SYM:
                        # r37 P3 (C11): the alias unit is '51 f7 <u16>' — the
                        # marker plus a FULL u16 symbol reference, four bytes
                        # on the wire; consuming three left the index's high
                        # byte behind and desynced every following arm column.
                        alias = _sym(syms, S.u16(buf, ck + 2))
                        id_len += len(alias)
                        ck += 4
                    arm_cols.append((ces[0], alias))
                    j = ck
                arms.append((distinct, tbl_a, arm_cols))
                if j < end and buf[j] == 0xC7 and j + 1 < end \
                        and buf[j + 1] in (0x15, S.SQL_DISTINCT_MARK):
                    j += 1                      # arm joiner, more arms follow
                    continue
                if j < end and buf[j] in (0x15, S.SQL_DISTINCT_MARK):
                    continue                    # abutting next arm
                break
            if id_len != want_id_len:
                raise Unsupported("SQL SELECT union header mismatch")
            where_expr = None
            if j < end and buf[j] == 0xC7:
                j += 1
                if j < end and buf[j] == 0xC6:
                    j += 1
                    wes, wk = _dec_expr(buf, j, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(wes) != 1 or wk >= end or buf[wk] != S.FD:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    j = wk + 1
                elif j < end and buf[j] == S.C3_ORDER:
                    pass                      # bare c7: no WHERE, ORDER follows
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
            if cur is None:
                raise Unsupported("SQL INTO CURSOR section missing")
            readwrite = False
            if j < end:
                if buf[j] == 0xD7 and j + 1 == end:
                    readwrite = True
                else:
                    raise Unsupported("SQL SELECT trailing bytes")
            segs = []
            for distinct, tbl_a, arm_cols in reversed(arms):
                seg = "SELECT "
                if distinct:
                    seg += "DISTINCT "
                if arm_cols:
                    seg += ", ".join(_emit(e) + (" AS %s" % a if a else "")
                                     for e, a in arm_cols)
                else:
                    seg += "*"
                seg += " FROM " + tbl_a
                segs.append(seg)
            text = " UNION ALL ".join(segs)
            if where_expr is not None:
                text += " WHERE " + _emit(where_expr)
            if order_expr is not None:
                text += " ORDER BY " + _emit(order_expr) + (" DESC" if desc else "")
            text += " INTO CURSOR " + cur
            # r37 P3: d7 emitted once — see the unified-path return below.
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
        # d4 INNER (and bare JOIN), 58 LEFT, 59 RIGHT. ON expr uses QualField.
        _JOIN_KW = {
            S.SQLSEL_JOIN_INNER: "INNER JOIN",
            S.SQLSEL_JOIN_LEFT: "LEFT JOIN",
            S.SQLSEL_JOIN_RIGHT: "RIGHT JOIN",
        }
        while j + 1 < end and buf[j + 1] == S.SQLSEL_JOIN_MARK \
                and buf[j] in _JOIN_KW:
            kw = _JOIN_KW[buf[j]]
            j += 2
            jtbl, j = _dec_str_arg(buf, j, end)
            if j + 3 <= end and buf[j] == S.SQLSEL_FROM_ALIAS \
                    and buf[j + 1] == S.SYM:
                jtbl = jtbl + " " + _sym(syms, S.u16(buf, j + 2))
                j += 4
            if j >= end or buf[j] != S.SQLSEL_JOIN_ON:
                raise Unsupported("SQL JOIN ON missing")
            j += 1
            if j >= end or buf[j] != S.FC:
                raise Unsupported("SQL JOIN ON unwrapped")
            oes, ok = _dec_expr(buf, j + 1, end, syms,
                                stop_bytes=_IF_COND_STOP)
            if len(oes) != 1 or ok >= end or buf[ok] != S.FD:
                raise Unsupported("SQL JOIN ON unresolved")
            j = ok + 1
            tbl = "%s %s %s ON %s" % (tbl, kw, jtbl, _emit(oes[0]))
        # UNIFIED SQL SELECT grammar: 6f 15 <FROM-str> [columns] [c7 [c6 where]]
        #   [bf group] [c3 order] [29 top] bc bd <cursor-str> [d7]. Columns are
        #   fc-wrapped expressions optionally aliased via 51; both star-form
        #   (no columns) and column-list forms may carry WHERE/GROUP/ORDER.
        cols = []
        star_extra = False
        t2 = j
        while t2 < end and buf[t2] == S.FC:
            agg = _try_sql_agg(buf, t2 + 1, end, syms)
            if agg is not None:
                node, k = agg
                es = [node]
            else:
                try:
                    es, k = _dec_expr(buf, t2 + 1, end, syms,
                                      stop_bytes=_IF_COND_STOP)
                except Unsupported:
                    break
            if len(es) != 1:
                raise Unsupported("SQL SELECT column unresolved")
            if k < end and buf[k] == S.FD:
                k += 1
            elif distinct and k == end:
                # r42-seldistinct no-INTO: 6f be 15 … fc <col> with the
                # statement-final fd reader-stripped.
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
                    wnode, wk = _dec_sql_like_cond(buf, pos + 1, end, syms)
                    where_expr = wnode
                    pos = wk
                except Unsupported:
                    wes, wk = _dec_expr(buf, pos + 1, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(wes) != 1 or wk >= end or buf[wk] != S.FD:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    pos = wk + 1
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
                    wes, wk = _dec_expr(buf, pos + 2, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(wes) != 1 or wk >= end or buf[wk] != S.FD:
                        raise Unsupported("SQL WHERE unresolved")
                    where_expr = wes[0]
                    pos = wk + 1
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
            if len(ges) != 1 or gk >= end or buf[gk] != S.FD:
                raise Unsupported("SQL GROUP BY unresolved")
            pos = gk + 1
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
            if len(oes) != 1 or ok >= end or buf[ok] != S.FD:
                raise Unsupported("SQL ORDER unresolved")
            pos = ok + 1
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
        if into_txt is None:
            if distinct:
                into_txt = ""
            else:
                raise Unsupported("SQL INTO CURSOR section missing")
        if pos < end:
            if buf[pos] == 0xD7 and pos + 1 == end:
                readwrite = True
            elif buf[pos] == S.SQLSEL_NOFILTER_MARK and pos + 1 == end:
                nofilter = True
            else:
                raise Unsupported("SQL SELECT trailing bytes")
        # build result
        sel_kw = ["SELECT"]
        if distinct:
            sel_kw.append("DISTINCT")
        if top_n is not None:
            sel_kw.append("TOP %s" % _emit(top_n))
        top_txt = " ".join(sel_kw) + " "
        if cols:
            parts = [_emit(e) + (f" AS {a}" if a else "") for e, a in cols]
            # review F1: a mixed projection renders its additional star too
            head = top_txt + ", ".join(parts) \
                + (", *" if star_extra else "") + f" FROM {tbl}"
            text = head
            if where_expr is not None:
                text += " WHERE " + _emit(where_expr)
            if group_terms:
                text += " GROUP BY " + ", ".join(_emit(t) for t in group_terms)
            if order_terms:
                text += " ORDER BY " + ", ".join(
                    _emit(t) + (" DESC" if d else "") for t, d in order_terms)
            text += into_txt
            # r37 P3 (C13): the d7 tag is emitted ONCE, by _emit_line via
            # the readwrite flag — appending it here too doubled the tag on the
            # wire-visible text ('READWRITE READWRITE', rejected by VFP).
            return SqlSelectColumns(text, readwrite=readwrite,
                                    nofilter=nofilter)
        else:
            # star-form: no explicit columns means SELECT * FROM ...
            text = top_txt + ("* FROM %s" % tbl)
            if where_expr is not None:
                text += " WHERE " + _emit(where_expr)
            if group_terms:
                text += " GROUP BY " + ", ".join(_emit(t) for t in group_terms)
            if order_terms:
                text += " ORDER BY " + ", ".join(
                    _emit(t) + (" DESC" if d else "") for t, d in order_terms)
            text += into_txt
            return SqlSelectColumns(text, readwrite=readwrite,
                                    nofilter=nofilter)
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
            k += 1
            if k < end:
                raise Unsupported("SET trailing bytes")
            return SetDatasessionTo(es[0])
        # r36-sim V-F6: SET RELATION TO (<expr>) INTO <alias> [, ... ] —
        # single corpus carrier _reportlistener.vcx::xmllistener s26 stmt15
        # <-> stored L560 'SET RELATION TO the_alias INTO flds, the_alias
        # INTO rels' = 47 2d 28 fc f7<THE_ALIAS> fd bc f7<FLDS> 07
        # fc f7<THE_ALIAS> fd bc f7<RELS>. Envelope is the exact measured
        # spelling only: TO rides an fc..fd expression group, each INTO
        # target is a bare f7 symbol, pairs join on ARGJOIN 07; ANY other
        # byte keeps raising today's message unchanged.
        #
        # Round-40 lane G widens the envelope by exactly two MEASURED spellings,
        # both carried by xfrxlib.vcx::xfcont s66 (stored source quoted per arm):
        #   ADDITIVE rides a LEADING 01 between the id and the TO marker —
        #   '47 2d 01 28 …' <-> 'SET RELATION TO RECNO(This.linkAlias) INTO
        #   (This.LinkAliasEx) ADDITIVE' (stmt27);
        #   an INTO target may be a parenthesised expression group instead of a
        #   bare symbol — 'bc fc <expr> [fd]' in the same statement.
        if buf[1] == S.SET_RELATION_ID and end >= 8 \
                and buf[2] in (S.TO_MARK, S.SET_ADDITIVE_MARK):
            _pairs = []
            _t = 2
            additive = ""
            if buf[_t] == S.SET_ADDITIVE_MARK:
                additive = " ADDITIVE"
                _t += 1
            if _t >= end or buf[_t] != S.TO_MARK:
                raise Unsupported("SET variant outside forced subset")
            _t += 1
            while True:
                # every TO value rides its OWN fc..fd expression group
                if _t >= end or buf[_t] != S.FC:
                    raise Unsupported("SET variant outside forced subset")
                es, k = _dec_expr(buf, _t + 1, end, syms,
                                  stop_bytes=_IF_COND_STOP)
                if len(es) != 1 or k >= end or buf[k] != S.FD:
                    raise Unsupported("SET variant outside forced subset")
                _t = k + 1
                # INTO target: bc f7 <u16 sym>, or bc fc <expr> [fd] for the
                # parenthesised '(This.LinkAliasEx)' spelling
                if _t + 2 > end or buf[_t] != 0xBC:
                    raise Unsupported("SET variant outside forced subset")
                if buf[_t + 1] == S.SYM:
                    if _t + 4 > end:
                        raise Unsupported("SET variant outside forced subset")
                    alias = _sym(syms, S.u16(buf, _t + 2))
                    _t += 4
                elif buf[_t + 1] == S.FC:
                    aes, ak = _dec_expr(buf, _t + 2, end, syms,
                                        stop_bytes=_IF_COND_STOP)
                    if len(aes) != 1:
                        raise Unsupported("SET variant outside forced subset")
                    if ak < end and buf[ak] == S.FD:
                        ak += 1     # closer reader-stripped when statement-final
                    alias = _emit(aes[0])
                    _t = ak
                else:
                    raise Unsupported("SET variant outside forced subset")
                _pairs.append((es[0], alias))
                if _t == end:
                    break
                if buf[_t] == S.ARGJOIN:
                    _t += 1
                    continue
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET RELATION TO " + ", ".join(
                "%s INTO %s" % (_emit(e), a) for e, a in _pairs) + additive)
        # SET SKIP / SET MARK OF BAR <n> OF <popup> [TO] <lExpr> —
        # ORACLE-MEASURED skeleton (round-37 wave-2 w10 probes k01/k02/k03;
        # conclusions W01/W02/W03):
        #   'SET SKIP OF BAR 6 OF pp .T.' = 47 4e c3 06 fc f8 01 06 fd
        #                                   c3 f7 <u16 pp> fc 61
        #   '… .F.' swaps the value byte to 2d; 'SET MARK …' is 47 3a with the
        #   same skeleton. c3 = OF, 06 = BAR.
        # The bar number rides its own fc..fd group; the popup name is either a
        # bare f7 symbol or its OWN fc..fd group for the parenthesised
        # '(m.cShortcut)' spelling; the value group's fd is reader-stripped when
        # statement-final. The optional 28 in front of the value is the source's
        # own TO word and is measured on MARK only (SET SKIP … TO is not VFP):
        #   frxpreview.vcx::frxpreviewform s10 stmt43
        #     473ac306fcf8020afdc3fcf50df7060003fd28fc2d
        #     <-> stored L270 'set Mark of bar 10 of (m.cShortcut) to .F.'
        #   same section stmt49 474ec306fcf8020afdc3fcf50df7060003fdfc61
        #     <-> stored L285 'set Skip of bar 10 of (m.cShortCut) .T.' (no 28).
        # The OF-BAR clause pair is REQUIRED, so SET SKIP/MARK OF
        # MENU/PAD/POPUP and the date-separator 'SET MARK TO' keep raising the
        # message unchanged.
        if buf[1] in S.SET_OF_BAR_NAMES and end >= 6 \
                and buf[2] == S.SET_OF_MARK and buf[3] == S.SET_BAR_MARK:
            if buf[4] != S.FC:
                raise Unsupported("SET variant outside forced subset")
            bes, k = _dec_expr(buf, 5, end, syms, stop_bytes=_IF_COND_STOP)
            if len(bes) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("SET variant outside forced subset")
            k += 1
            if k + 2 > end or buf[k] != S.SET_OF_MARK:
                raise Unsupported("SET variant outside forced subset")
            if buf[k + 1] == S.SYM:
                if k + 4 > end:
                    raise Unsupported("SET variant outside forced subset")
                popup = _sym(syms, S.u16(buf, k + 2))
                k += 4
            elif buf[k + 1] == S.FC:
                pes, k = _dec_expr(buf, k + 2, end, syms,
                                   stop_bytes=_IF_COND_STOP)
                if len(pes) != 1 or k >= end or buf[k] != S.FD:
                    raise Unsupported("SET variant outside forced subset")
                popup = _emit(pes[0])
                k += 1
            else:
                raise Unsupported("SET variant outside forced subset")
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
            return SetStmt("SET %s OF BAR %s OF %s %s%s"
                           % (S.SET_OF_BAR_NAMES[buf[1]], _emit(bes[0]),
                              popup, to, _emit(ves[0])))
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
                name = _SET_MEASURED_ONOFF_IDS.get(buf[1])
            if name is None:
                raise Unsupported("SET variant outside forced subset")
            if buf[2] == 0x20:
                return SetStmt("SET %s ON" % name)
            if buf[2] == 0x1F:
                return SetStmt("SET %s OFF" % name)
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
        if buf[1] == S.SET_TEXTMERGE_ID and end >= 9 \
                and buf[2] == S.TO_MARK and buf[3] == S.SET_TEXTMERGE_MEMVAR_MARK:
            # exact measured shape: c2 then ONE m.<name> operand then optional ce
            if buf[4] != S.WORKAREA_REF or buf[5] != 0x0D or buf[6] != S.SYM:
                raise Unsupported("SET variant outside forced subset")
            nm = _sym(syms, S.u16(buf, 7))
            t = 9
            noshow = False
            if t < end and buf[t] == S.SET_NOSHOW_MARK:
                noshow = True
                t += 1
            if t != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET TEXTMERGE TO MEMVAR m.%s%s"
                           % (nm, " NOSHOW" if noshow else ""))
        # SET TEXTMERGE DELIMITERS TO — ORACLE-MEASURED round-42 I9:
        #   reset  47 60 be 07
        #   pair   47 60 be fc <left> [fd] 07 fc <right> [fd]
        # Unmeasured DELIMITERS tails (no 07, one operand, trailing bytes)
        # keep raising SET variant outside forced subset.
        if buf[1] == S.SET_TEXTMERGE_ID and end >= 4 \
                and buf[2] == S.SET_TEXTMERGE_DELIMITERS_MARK:
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
        if buf[1] == S.SET_REPORTBEHAVIOR_ID and end >= 4 and buf[2] == S.FC:
            es, k = _dec_expr(buf, 3, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SET variant outside forced subset")
            if k < end and buf[k] == S.FD:
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET REPORTBEHAVIOR %s" % _emit(es[0]))
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
            es, k = dec_set_value(buf, t + 1, end, syms)
            if k != end:
                raise Unsupported("SET trailing bytes")
            return SetStmt("SET ORDER TO %s IN %s" % (_emit_set_order_tag(es), alias))
        # SET FILTER TO IN <alias> — ORACLE-MEASURED round-42 I9:
        #   47 1a 28 16 f7 <u16>  <->  SET FILTER TO IN <alias>
        # 16 is the IN clause byte already used by SET ORDER ... IN.
        # Alias is a bare f7 symbol; grouped/string/expr+IN stay refused.
        if buf[1] == 0x1A and end == 7 and buf[2] == S.TO_MARK \
                and buf[3] == S.SET_ORDER_IN_MARK and buf[4] == S.SYM:
            alias = _sym(syms, S.u16(buf, 5))
            return SetStmt("SET FILTER TO IN %s" % alias)
        # Generic measured value form: '47 <id> 28 [fc <expr> [03] [fd]] |
        # fb <str>] [01]' — grouped spellings carry the PAREN postfix 03 inside
        # the group for '(m.x)' values, fd is reader-stripped when final, and
        # 01 = ADDITIVE on its measured ids only. Bare single string operands
        # are measured on ORDER/CLASSLIB/PROCEDURE/LIBRARY ('SET ORDER TO
        # Revert', 'SET CLASSLIB TO foxchartsBeta.vcx ADDITIVE').
        if buf[1] in S.SET_VALUE_TO_NAMES and buf[2] == S.TO_MARK and end > 3:
            name = S.SET_VALUE_TO_NAMES[buf[1]]
            es, k = dec_set_value(buf, 3, end, syms)
            additive = ""
            if k < end and buf[k] == S.SET_ADDITIVE_MARK:
                if buf[1] not in S.SET_ADDITIVE_IDS:
                    raise Unsupported("SET trailing bytes")
                additive = " ADDITIVE"
                k += 1
            if k != end:
                raise Unsupported("SET trailing bytes")
            if name == "ORDER":
                return SetStmt("SET ORDER TO %s%s" % (_emit_set_order_tag(es), additive))
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
        if end >= 2 and buf[end - 1] == 0x03:
            strip_all = True
            end -= 1
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
                return ReplaceStmt(pairs, all_scope=all_scope,
                                   in_spec=in_spec)
            # the FINAL pair's fd is consumed by the reader's fd-fe strip, so a clean
            # run-to-end is legal; mid-statement pairs keep their fd before 07/ALL
            if k < end and buf[k] == S.FD:
                k += 1
            elif k != end:
                raise Unsupported("REPLACE expression unresolved")
            pairs.append((lv, es[0]))
            if k == end:
                return ReplaceStmt(pairs,
                                   all_scope=all_scope or strip_all,
                                   in_spec=in_spec)
            if buf[k] == 0x03:
                # ALL scope: forced 9/9 against stored 'REPLACE ... ALL' sources;
                # round-28 W4: the byte may also PRECEDE a trailing FOR clause
                # ('REPLACE .. WITH .. ALL FOR id<>1', setpurtd.lhbbak
                # OpChgClass s0 stmts4/8)
                all_scope = True
                k += 1
                if k == end:
                    return ReplaceStmt(pairs, all_scope=True, in_spec=in_spec)
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
        if t < end and buf[t] == 0x03:
            if not is_count:
                raise Unsupported(shape)
            count_all = True
            t += 1
        if t + 1 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
            fes, k = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(fes) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported(shape.replace("shape", "FOR clause unresolved"))
            for_cond = fes[0]
            t = k + 1
        elif is_count and t < end and buf[t] == 0x2B:
            if count_all:
                raise Unsupported(shape)
            if t + 1 >= end or buf[t + 1] != S.FC:
                raise Unsupported("COUNT WHILE clause unwrapped")
            wes, k = _dec_expr(buf, t + 2, end, syms, stop_bytes=_IF_COND_STOP)
            if len(wes) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("COUNT WHILE clause unresolved")
            while_cond = wes[0]
            t = k + 1
        if count_all and for_cond is None:
            # hardening F2: `12 03` is measured ONLY with a FOR group
            # ('COUNT ALL FOR INLIST(…)' _reportlistener.vcx::xmllistener s50
            # stmt19). ALL straight to TO — and any ALL form without the measured
            # FOR clause — is an unmeasured shape and stays loudly Unsupported;
            # the no-ALL COUNT/SUM forms are untouched.
            raise Unsupported(shape)
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported(shape)
        targets, t = [], t + 1
        while True:
            tv, t = _dec_lvalue(buf, t, end, syms)
            targets.append(tv)
            # a COUNT stream ends directly after its target memvar
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        values = []
        while t < end:
            if buf[t] != S.FC:
                raise Unsupported("SUM expr unwrapped")
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1:
                raise Unsupported("SUM expression unresolved")
            k += 1 if k < end and buf[k] == S.FD else 0
            values.append(es[0])
            if k < end and buf[k] == S.ARGJOIN:
                t = k + 1
                continue
            t = k
            break
        if is_count:
            # measured COUNT carries exactly one target memvar and no expressions
            if values or t != end or len(targets) != 1:
                raise Unsupported(shape)
            return CountStmt(targets[0], for_cond=for_cond, while_cond=while_cond,
                             count_all=count_all)
        if len(values) != len(targets) or t != end:
            raise Unsupported(shape)
        return SumStmt(targets, values, for_cond=for_cond)
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
        if end == 2 and buf[1] == 0xD5:
            return ClearStmt("EVENTS")
        if end == 2 and buf[1] == 0xD4:
            # round-28 W4: 'CLEAR TYPEAHEAD' (_reports.vcx cmdGetReport s0[8])
            return ClearStmt("TYPEAHEAD")
        if end == 2 and buf[1] == S.DEFINE_WINDOW_KW:
            # r42-clear: CLEAR WINDOW / WINDOWS / WINDOW w1 / WINDOWS w1
            # are all 0e2c (AATest frstestharn s38[4]). Name and plural
            # are not on the wire. Bare CLEAR stays 0e.
            return ClearStmt("WINDOW")
        if end >= 3 and buf[1:3] == bytes([0x56, 0x02]):
            names = []
            t = 3
            while t < end:
                name, t = _dec_str_arg(buf, t, end)
                names.append(name)
                if t == end:
                    break
                if buf[t] != S.ARGJOIN:
                    raise Unsupported("CLEAR DLLS name-list tail")
                t += 1
            if not names:
                raise Unsupported("CLEAR DLLS name missing")
            return ClearStmt("DLLS", names)
        # round-28 W4: RESOURCES (bare or one grouped operand) and CLASS <sym>
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
        if buf[1] == 0x4F:
            t = 2
            if t + 3 != end or buf[t] != S.SYM:
                raise Unsupported("CLEAR trailing bytes")
            return ClearStmt("CLASS",
                             [_sym(syms, S.u16(buf, t + 1))])
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
        if end == 1:
            return ("DELETE",)
        t = 1
        all_scope = False
        if t < end and buf[t] == 0x03:
            all_scope = True
            t += 1
            if t == end:
                # scope-only form: 'Delete All' <-> 14 03 (org_chart s1
                # stmts16/49), same compiled ALL byte REPLACE carries finally
                return ("DELETE ALL",)
        if t + 2 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
            es, k = _dec_expr(buf, t + 2, end, syms)
            if len(es) != 1 or k != end:
                raise Unsupported("DELETE FOR condition unresolved")
            return DeleteFor(es[0], all_scope=all_scope)
        if not all_scope and t < end and buf[t] == S.COPY_FILE_MARK:
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
        if not all_scope and t < end and buf[t] == 0xC4:
            t += 1
            if t < end and buf[t] in (S.STR, S.STR2):
                name, t2 = _dec_str_arg(buf, t, end)
                if t2 != end:
                    raise Unsupported("DELETE trailing bytes")
                return DeleteScopeStmt("VIEW", name)
            raise Unsupported("DELETE trailing bytes")
        if not all_scope and t < end and buf[t] == 0x1E:
            try:
                count, t2 = _fc_group(buf, t + 1, end, syms)
            except Unsupported:
                raise Unsupported("DELETE NEXT count unresolved")
            if t2 != end:
                raise Unsupported("DELETE trailing bytes")
            return DeleteScopeStmt("NEXT", count)
        # Round-31: `16 f7 <sym>` = the compiled IN-work-area clause — the same
        # clause-first wire byte REPLACE carries under its own lead ('REPLACE ..
        # WITH True .. IN c_cells' -> `3e 16 f7 ..`, reader above). Every carrier
        # lives in VFPxWorkbookXLSX.vcx::vfpxworkbookxlsx and is aligned to its
        # own stored METHODS line (alignment table /tmp/foxlift-r31-delete-scope/
        # samples/ALIGNMENT.md): bare 'DELETE IN c_sheets' -> `14 16 f7 <alias>`,
        # and 'DELETE FOR workbook = tnWB IN c_cells' ->
        # `14 16 f7 <alias> 13 fc <cond>` — the compiler wires the IN clause
        # FIRST regardless of the authored FOR..IN order, then the condition runs
        # to stream end like the bare-FOR arm above. Only the symbol-operand
        # spelling is measured: string/fc-group aliases, any other byte between
        # alias and FOR, an unresolved condition, and the ALL+IN combination all
        # keep the unchanged trailing-bytes label.
        if not all_scope and t + 4 <= end and buf[t] == 0x16 \
                and buf[t + 1] == S.SYM:
            alias = _sym(syms, S.u16(buf, t + 2))
            t += 4
            if t == end:
                return DeleteScopeStmt("IN", alias)
            if t + 2 < end and buf[t] == 0x13 and buf[t + 1] == S.FC:
                es, k = _dec_expr(buf, t + 2, end, syms)
                if len(es) != 1 or k != end:
                    raise Unsupported("DELETE IN FOR condition unresolved")
                return DeleteScopeStmt("IN", alias, cond=es[0])
            raise Unsupported("DELETE trailing bytes")
        raise Unsupported("DELETE trailing bytes")
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
        # round-28 W4: bd as statement lead is THROW (n11; context-local vs ON
        # ESCAPE under lead 31). Expression runs to statement end, no closer:
        # 'bd fc f8020b' = THROW 11; 'bd fc f50df700..' = THROW (m.x).
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
                if t + 3 > end or buf[t] != S.SYM:
                    raise Unsupported("ON SELECTION BAR popup missing")
                popup = _sym(syms, S.u16(buf, t + 1))
                t += 3
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
            if t + 3 > end or buf[t] != S.SYM:
                raise Unsupported("ON BAR popup missing")
            popup = _sym(syms, S.u16(buf, t + 1))
            t += 3
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
            es, k = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(es) != 1 or k >= end or buf[k] != S.FD:
                raise Unsupported("DECLARE library unresolved")
            lib = _emit(es[0])
            t = k + 1
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
        return DeclareDllStmt(fname, lib, ret=ret, alias=alias, params=params)
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
        if t + 3 > end or buf[t] != S.SYM:
            raise Unsupported("ALTER TABLE column missing")
        col = _sym(syms, S.u16(buf, t + 1))
        t += 3
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
        if kind in ("COMMAND", "FILE"):
            while t < end:
                b = buf[t]
                if b == 0xC5 and not noedit and kind == "FILE":
                    noedit = True
                    t += 1
                    continue
                if b == 0xC7 and range_args is None and kind == "FILE":
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
                            if rk != end:
                                raise Unsupported(
                                    "MODIFY RANGE argument unresolved")
                            range_args.append(res_[0])
                            t = rk
                    continue
                if b == 0x3A and not nowait:
                    nowait = True
                    t += 1
                    continue
                raise Unsupported("MODIFY trailing bytes")
        elif t != end:
            raise Unsupported("MODIFY trailing bytes")
        return ModifyStmt(kind, target, noedit, range_args, nowait)
    if lead == 0x7D:
        # CALCULATE SUM(..)/MAX(..) TO <memvar>: CMD_SWEEP.md bound row
        # ('CALCULATE SUM(f1) TO clc1', item selector c2) + census gold pair
        # be=MAX (managecode.scx::CmdSave 'CALCULATE MAX(KEYID) TO X').
        if end < 2:
            raise Unsupported("statement lead 0x7d")
        t = 1
        if t >= end or buf[t] != S.TO_MARK:
            raise Unsupported("CALCULATE shape")
        targets, t = [], t + 1
        while True:
            tv, t = _dec_lvalue(buf, t, end, syms)
            targets.append(tv)
            if t < end and buf[t] == S.ARGJOIN:
                t += 1
                continue
            break
        items = []
        fn_names = {0xC2: "SUM", 0xBE: "MAX"}
        while t < end:
            fn = fn_names.get(buf[t])
            if fn is None:
                raise Unsupported(
                    "CALCULATE item selector 0x%02x unmeasured" % buf[t])
            t += 1
            if t >= end or buf[t] != 0x02:
                raise Unsupported("CALCULATE item group missing")
            t += 1
            if t >= end or buf[t] != S.FC:
                raise Unsupported("CALCULATE item expression unwrapped")
            ies, ik = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(ies) != 1:
                raise Unsupported("CALCULATE item expression unresolved")
            ik += 1 if ik < end and buf[ik] == S.FD else 0
            if ik >= end or buf[ik] != 0x03:
                raise Unsupported("CALCULATE item group unterminated")
            items.append((fn, ies[0]))
            t = ik + 1
        if not items or len(items) != len(targets):
            raise Unsupported("CALCULATE shape")
        return CalculateStmt(targets, items)
    if lead == 0x3F:
        # REPORT FORM <form>: CMD_SWEEP.md bound row ('REPORT FORM rpt1');
        # TO FILE (28+12), OBJECT TYPE (2e+d4), PREVIEW c1 / NOWAIT 3a bound
        # by the buyswwprint/pidocchk/foxchartsbeta gold pairs.
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
            fes, fk = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(fes) != 1 or fk >= end or buf[fk] != S.FD:
                raise Unsupported("REPORT FORM name unresolved")
            form = fes[0]
            t = fk + 1
        else:
            raise Unsupported("statement lead 0x3f")
        to_file = None
        objtype = None
        preview = False
        nowait = False
        if t < end and buf[t] == S.TO_MARK:
            t += 1
            if t >= end or buf[t] != 0x12:
                raise Unsupported("REPORT FORM TO clause missing FILE")
            t += 1
            if t >= end or buf[t] != S.FC:
                raise Unsupported("REPORT FORM TO FILE unwrapped")
            tes, tk = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(tes) != 1 or tk >= end or buf[tk] != S.FD:
                raise Unsupported("REPORT FORM TO FILE unresolved")
            to_file = tes[0]
            t = tk + 1
        if t < end and buf[t] == 0x2E:
            t += 1
            if t >= end or buf[t] != 0xD4:
                raise Unsupported("REPORT FORM OBJECT clause missing TYPE")
            t += 1
            if t >= end or buf[t] != S.FC:
                raise Unsupported("REPORT FORM OBJECT TYPE unwrapped")
            oes, ok = _dec_expr(buf, t + 1, end, syms, stop_bytes=_IF_COND_STOP)
            if len(oes) != 1:
                raise Unsupported("REPORT FORM OBJECT TYPE unresolved")
            # the closing fd rides at the statement tail, where the reader's
            # fd-fe strip consumed it (same convention as REPLACE/SUM)
            ok += 1 if ok < end and buf[ok] == S.FD else 0
            if ok != end:
                raise Unsupported("REPORT FORM OBJECT TYPE unresolved")
            objtype = oes[0]
            t = ok
        if t < end and buf[t] == 0xC1:
            preview = True
            t += 1
        if t < end and buf[t] == 0x3A:
            nowait = True
            t += 1
        if t != end:
            raise Unsupported("REPORT FORM trailing bytes")
        return ReportFormStmt(form, objtype, to_file, preview, nowait)
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
    if lead == S.PROTECTED_LEAD:
        # r43-class: PROTECTED n -> a1 f7 <sym>. Development compiled programs
        # carry only this 4-byte shape (12 statements). 07-joined lists and
        # HIDDEN 0x9f stay unmeasured here.
        if end == 4 and buf[1] == S.SYM:
            return ProtectedProp(_sym(syms, S.u16(buf, 2)))
        raise Unsupported("statement lead 0xa1")
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
    raise Unsupported(f"statement lead 0x{lead:02x}")


# ---------- section lift --------------------------------------------------------------------------
def statement_source(stream, syms):
    """Decode and emit ONE compiled statement to canonical source.

    Raises :class:`Unsupported` outside the slice — the per-statement building block
    lift_section is built from, exposed for tooling that must account for every blocking
    schema in a method individually (foxlift.impact) rather than stopping at the first.
    """
    return _emit_line(dec_statement(stream, syms))


def lift_section(sec, syms_override=None):
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
    global _MENU_SHIFTED_BLOCK, _PAYLOAD_CODEC
    outer = _MENU_SHIFTED_BLOCK
    prev_codec = _PAYLOAD_CODEC
    _MENU_SHIFTED_BLOCK = _menu_bar_shifted_section(sec.statements)
    _PAYLOAD_CODEC = getattr(sec, "codec", None) or "latin1"
    try:
        out, _ = _walk_block(sec.statements, 0, len(sec.statements), eff,
                             code_base=code_base)
    finally:
        _MENU_SHIFTED_BLOCK = outer
        _PAYLOAD_CODEC = prev_codec
    return out


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


def lift_program(mod):
    """Lift every section of a parsed module into one source.

    Class modules (r43-fxphdr post-section directory) emit DEFINE CLASS
    <name> AS <base> [OLEPUBLIC] around members. Procedure bodies become
    PROCEDURE <name> when the method directory in front of class-init
    supplies names; PROTECTED/HIDDEN follow the 0xa3/0x9e index. 0xa2/0xa3/0x9e
    class-init index statements have no source line.
    """
    span_end = mod.extent if mod.extent else len(mod.data)
    ids = class_identities(mod.data, mod.offset, span_end)
    if not ids:
        procs = procedure_names(mod.data, mod.offset, span_end)
        nonempty = [(i, sec) for i, sec in enumerate(mod.sections)
                    if not sec.is_empty]
        out = []
        if procs and len(procs) == len(nonempty):
            named = nonempty
            main = []
        elif procs and len(procs) == len(nonempty) - 1:
            main = [nonempty[0]]
            named = nonempty[1:]
        else:
            main = nonempty
            named = []
            procs = []
        for _, sec in main:
            out.extend(lift_section(sec))
        for (_, sec), name in zip(named, procs):
            out.append("PROCEDURE %s" % name)
            out.extend(ln for ln in lift_section(sec) if ln != "")
            out.append("ENDPROC")
        if not out:
            for si, sec in enumerate(mod.sections):
                out.append("* --- section %d%s ---" % (
                    si, " (empty)" if sec.is_empty else ""))
                out.extend(lift_section(sec))
        return out
    nclass = len(ids)
    secs = list(mod.sections)
    if not secs:
        out = []
        for ident in ids:
            out.append(_class_header_line(ident))
            out.append("ENDDEFINE")
        return out
    top, rest = [], secs
    if secs[0].statements and not _is_class_init_section(secs[0]):
        # mixed: top-level code then the class
        top = lift_section(secs[0])
        rest = secs[1:]
    elif secs[0].is_empty:
        rest = secs[1:]
    if len(rest) < nclass:
        inits, procs = rest, []
    else:
        inits = rest[-nclass:]
        procs = [s for s in rest[:-nclass] if not s.is_empty]
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
    for ci, ident in enumerate(ids):
        out.append(_class_header_line(ident))
        methods = list(ident.methods)
        vis = list(ident.method_vis)
        for pi, psec in enumerate(split_procs[ci] if ci < len(split_procs) else []):
            body = [ln for ln in lift_section(psec) if ln != ""]
            name = methods[pi] if pi < len(methods) else ("_m%d" % (pi + 1))
            prefix = (vis[pi] + " ") if pi < len(vis) and vis[pi] else ""
            out.append("%sPROCEDURE %s" % (prefix, name))
            out.extend(body)
            out.append("ENDPROC")
        init = inits[ci] if ci < len(inits) else None
        if init is not None:
            for ln in lift_section(init):
                if ln != "":
                    out.append(ln)
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
            body = [ln for ln in lift_section(psec) if ln != ""]
            name = extra_names[pi] if pi < len(extra_names) else (
                "_m%d" % (pi + 1))
            out.append("PROCEDURE %s" % name)
            out.extend(body)
            out.append("ENDPROC")
    return out


def _walk_block(stmts, i, stop, syms, stops=frozenset(), code_base=None):
    """Emit stmts[i:stop]. Stops BEFORE any statement whose lead is in ``stops`` (the
    caller consumes it) and fails if a required sentinel never appears."""
    out = []
    while i < stop:
        s = stmts[i]
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
            body, j = _walk_block(stmts, i + 1, stop, syms,
                                  stops={S.ELSE_LEAD, S.ENDIF_LEAD},
                                  code_base=code_base)
            want = stmts[j].offset - code_base
            if s.jump_rel != want:
                raise Unsupported(
                    "verbatim-if jump target %d != %s code-base distance %d"
                    % (s.jump_rel,
                       "ELSE" if stmts[j].stream[0] == S.ELSE_LEAD else "ENDIF",
                       want))
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
            out.extend(_emit_line(ast).split("\n"))
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
                        stops={S.ENDCASE_LEAD}, code_base=code_base)
                    want_oth = stmts[pos].offset - code_base
                    if oth.rel_target != want_oth:
                        raise Unsupported(f"otherwise jump target {oth.rel_target} "
                                          f"!= ENDCASE distance {want_oth}")
                    break
                if s2.text is not None or s2.stream[0] != S.CASE_CLAUSE:
                    # stray statement between clauses: unforced shape
                    raise Unsupported("unexpected statement inside DO CASE")
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
                                         code_base=code_base)
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
        # FOLDED constants are kept out by the 0xCC marker at the reader (they
        # arrive here with width None). These two are the value-preserving backstop
        # for any fold that might reach the wire unmarked: where the header's own
        # rendering does not fit its width, or does not round-trip to the very same
        # double, the incumbent repr() spelling stays — emitting a rounded '5.94'
        # for 5.9399999999999995 would change the program.
        if node.width is None:
            return node.spelling
        v = float(node.spelling)
        s = "%0*.*f" % (node.width, node.decimals, v)
        if len(s) == node.width and float(s) == v:
            return s
        return node.spelling
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
        return "%s.%s(%s).%s" % (node.obj, node.member, _emit(node.sub),
                                 node.prop)
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
        if node.tail:
            text += "." + ".".join(node.tail)
        return text
    if isinstance(node, Str):
        if node.dq:
            # double-quoted (d9); no in-scope literal embeds a double quote — doubling is
            # the assumed VFP escape and is UNMEASURED past that
            return '"' + node.text.replace('"', '""') + '"'
        return "'" + node.text.replace("'", "''") + "'"
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
        text = "%s.%s(%s)" % (".".join(node.recv), node.name,
                              ", ".join(_emit(a) for a in node.args))
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
        return "%s::%s" % (node.cls, node.member)
    if isinstance(node, ArrayElement):
        if node.method_receiver:
            raise Unsupported("array-element receiver without method callee")
        return "%s[%s]" % (_emit(node.base),
                           ", ".join(_emit(x) for x in node.subs))
    if isinstance(node, Mod):
        return "%s %% %s" % (_side(node.a, 6), _side(node.b, 7))
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


def _side(node, min_prec):
    """Render a child, parenthesizing when its own precedence is below what this slot demands.
    Explicit Paren nodes always render with their parens (they carry measured provenance)."""
    txt = _emit(node)
    if isinstance(node, Paren):
        return txt
    own = _own_prec(node)
    if own >= min_prec:
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
        lines += ["    " + b for b in ast.body]
        if ast.else_body or ast.else_target >= 0:
            lines.append("ELSE")
            lines += ["    " + b for b in ast.else_body]
        lines.append("ENDIF")
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
        if ast.style is not None:
            txt += " STYLE " + _emit(ast.style)
        if ast.message is not None:
            txt += " MESSAGE " + _emit(ast.message)
        if ast.key is not None:
            txt += " KEY " + ast.key[0]
            if ast.key[1] is not None:
                txt += ", " + _emit(ast.key[1])
        if ast.skip_for is not None:
            txt += " SKIP FOR " + _emit(ast.skip_for)
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
        if ast.window is None:
            if not ast.fields:
                return "BROWSE"
            head = "BROWSE"
        else:
            head = "BROWSE WINDOW %s" % ast.window
        txt = head
        if ast.fields:
            cols = []
            for fname, width, pic, heading in ast.fields:
                col = fname
                if width is not None:
                    col += ":%s" % width
                if pic is not None:
                    col += " :P = %s" % _emit(pic)
                if heading is not None:
                    # round-31: canonical ':H = ..' spelling; the corpus spells
                    # it both ':10 :H = ..' and ':h=..:10' (wire order follows
                    # source, emission is canonical)
                    col += " :H = %s" % _emit(heading)
                cols.append(col)
            txt += " FIELDS " + ", ".join(cols)
        if ast.title is not None:
            txt += " TITLE " + _emit(ast.title)
        if ast.timeout is not None:
            txt += " TIMEOUT " + _emit(ast.timeout)
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
        if ast.kind == "NEXT":
            return "DELETE NEXT %s" % _emit(ast.target)
        if ast.kind == "IN":
            # stored sources spell the scoped form FOR-first ('DELETE FOR
            # workbook = tnWB IN c_cells') even though the wire is IN-clause-
            # first; mirror that order like ReplaceStmt does
            if ast.cond is not None:
                return "DELETE FOR %s IN %s" % (_emit(ast.cond), ast.target)
            return "DELETE IN %s" % ast.target
    if isinstance(ast, Return):
        return "RETURN" if ast.expr is None else "RETURN %s" % _emit(ast.expr)
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
        lines += ["    " + b for b in ast.body]
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
            + (" NOFILTER" if ast.nofilter else "")
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
        return "PRIVATE ALL LIKE " + ast.skeleton
    if isinstance(ast, ClearStmt):
        if ast.clause == "EVENTS":
            return "CLEAR EVENTS"
        if ast.clause == "DLLS":
            return "CLEAR DLLS " + ", ".join(ast.names)
        if ast.clause == "TYPEAHEAD":
            return "CLEAR TYPEAHEAD"
        if ast.clause == "WINDOW":
            return "CLEAR WINDOW"
        if ast.clause == "RESOURCES":
            if ast.expr is not None:
                return "CLEAR RESOURCES %s" % _emit(ast.expr)
            return "CLEAR RESOURCES"
        if ast.clause == "CLASS":
            return "CLEAR CLASS %s" % ast.names[0]
        raise Unsupported("CLEAR clause unmeasured")
    if isinstance(ast, ThrowStmt):
        return "THROW %s" % _emit(ast.expr)
    if isinstance(ast, SumStmt):
        text = "SUM %s TO %s" % (
            ", ".join(_emit(e) for e in ast.expr),
            ", ".join(_emit(t) for t in ast.target))
        if getattr(ast, "for_cond", None) is not None:
            text += " FOR " + _emit(ast.for_cond)
        return text
    if isinstance(ast, CountStmt):
        # VFP doc clause order: scope/FOR precedes TO (both stored source orders
        # compile to the same frames); round-32 adds ALL and WHILE to the matrix
        head = "COUNT"
        if getattr(ast, "count_all", False):
            head += " ALL"
        if ast.for_cond is not None:
            head += " FOR %s" % _emit(ast.for_cond)
        if getattr(ast, "while_cond", None) is not None:
            head += " WHILE %s" % _emit(ast.while_cond)
        return "%s TO %s" % (head, _emit(ast.target))
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
        return "SET DATASESSION TO (%s)" % _emit(ast.expr)
    if isinstance(ast, NodefaultStmt):
        return "NODEFAULT"
    if isinstance(ast, ClassMethodIndex):
        return ""
    if isinstance(ast, ProtectedProp):
        return "PROTECTED " + ast.name
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
    if isinstance(ast, ScatterStmt):
        if ast.target is not None:
            return "SCATTER TO %s" % ast.target
        if ast.name_obj is not None:
            if ast.memo_blank:
                out = "SCATTER MEMO BLANK NAME %s" % ast.name_obj
            elif ast.memo:
                out = "SCATTER MEMO NAME %s" % ast.name_obj
            else:
                out = "SCATTER NAME %s" % ast.name_obj
            if ast.like_skeleton is not None:
                out += " FIELDS LIKE %s" % ast.like_skeleton
            return out
        return "SCATTER MEMVAR MEMO"
    if isinstance(ast, GatherStmt):
        if ast.name_obj is not None:
            return "GATHER NAME %s" % ast.name_obj
        return "GATHER FROM %s" % ast.source
    if isinstance(ast, ErrorStmt):
        return "ERROR " + ", ".join(_emit(a) for a in ast.args)
    if isinstance(ast, ReleaseAll):
        return "RELEASE ALL"
    if isinstance(ast, ReleaseStmt):
        return "RELEASE " + ", ".join(ast.names)
    if isinstance(ast, LocateFor):
        txt = ("LOCATE ALL FOR %s" if ast.all_scope else "LOCATE FOR %s") \
            % _emit(ast.cond)
        if ast.while_cond is not None:
            txt += " WHILE %s" % _emit(ast.while_cond)
        return txt
    if isinstance(ast, ForStmt):
        lines = ["FOR %s = %s TO %s" % (
            _emit(ast.var), _emit(ast.start), _emit(ast.end))]
        if ast.step is not None:
            lines[-1] += " STEP %s" % _emit(ast.step)
        lines += ["    " + b for b in ast.body]
        lines.append("ENDFOR")
        return "\n".join(lines)
    if isinstance(ast, ForEachStmt):
        head = "FOR EACH %s IN %s" % (_emit(ast.var), _emit(ast.collection))
        if ast.foxobject:
            head += " FOXOBJECT"
        lines = [head]
        lines += ["    " + b for b in ast.body]
        lines.append("ENDFOR")   # stored sources spell NEXT and ENDFOR alike
        return "\n".join(lines)
    if isinstance(ast, ScanStmt):
        head = "SCAN"
        if ast.scan_all:
            head += " ALL"
        if ast.cond is not None:
            head += " FOR " + _emit(ast.cond)
        if getattr(ast, "while_cond", None) is not None:
            head += " WHILE " + _emit(ast.while_cond)
        lines = [head]
        lines += ["    " + b for b in getattr(ast, "body", [])]
        lines.append("ENDSCAN")
        return "\n".join(lines)
    if isinstance(ast, TryStmt):
        lines = ["TRY"]
        lines += ["    " + b for b in ast.body]
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
            lines += ["    " + b for b in (ast.catch_body or [])]
        if ast.finally_body is not None:
            lines.append("FINALLY")
            lines += ["    " + b for b in ast.finally_body]
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
                # column NULL clause (round-29 d6); VFP field grammar places
                # it before AUTOINC, and no carrier carries both suffixes
                p += " NULL"
            if autoinc is not None:
                p += " AUTOINC NEXTVALUE %s" % autoinc
            parts.append(p)
        # round-33 CODEPAGE clause rides between name and field list exactly
        # as the stored sources spell it ('CREATE CURSOR c_strings
        # CODEPAGE = 620 (id I, ...)').
        out = "CREATE %s %s" % ("TABLE" if ast.table else "CURSOR", ast.name)
        if ast.codepage is not None:
            out += " CODEPAGE = %s" % ast.codepage
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
        if ast.values is None:
            return out + " FROM MEMVAR"
        return out + " VALUES (%s)" % ", ".join(_emit(v) for v in ast.values)
    if isinstance(ast, tuple) and len(ast) == 1 and (
            ast[0] in (
                "APPEND", "APPEND BLANK", "QUIT", "CLEAR", "DELETE", "ENDSCAN",
                "PUSH KEY", "POP KEY", "PACK", "ZAP", "CANCEL", "DOEVENTS",
                "CLOSE TABLES", "CLOSE DATABASES", "CLOSE DATABASES ALL",
                "CLOSE TABLES ALL", "CONTINUE", "LIST", "ENDTEXT", "ENDEACH",
                "DELETE ALL", "BROWSE", "PUSH KEY CLEAR", "LOCATE", "RECALL")
            or ast[0].startswith("PUSH MENU ")
            or ast[0].startswith("POP MENU ")
            or ast[0].startswith("ZAP IN ")):
        return ast[0]
    if isinstance(ast, BackslashLine):
        return "\\" + ast.text
    if isinstance(ast, HelpStmt):
        out = "HELP"
        if ast.id_expr is not None:
            out += " ID " + _emit(ast.id_expr)
        if ast.nowait:
            out += " NOWAIT"
        if ast.topic:
            out += " '" + ast.topic.replace("'", "''") + "'"
        return out
    if isinstance(ast, KeyboardStmt):
        out = "KEYBOARD " + _emit(ast.keys)
        return out + " PLAIN" if ast.plain else out
    if isinstance(ast, ShowWindowStmt):
        return ("SHOW WINDOW " + _emit(ast.name)
                + " IN WINDOW " + _emit(ast.in_window))
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
        return ("MOUSE AT %s, %s WINDOW %s PIXELS"
                % (_emit(ast.row), _emit(ast.col), _emit(ast.window)))
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
        out = "APPEND FROM " + _emit(ast.source)
        if ast.cond is not None:
            out += " FOR " + _emit(ast.cond)
        if ast.fields:
            out += " FIELDS " + ", ".join(ast.fields)
        if ast.delimited is not None:
            out += (" DELIMITED WITH TAB" if ast.delimited[0] == "TAB"
                    else " DELIMITED WITH CHARACTER '%s'" % ast.delimited[1])
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
        if ast.delimited is not None:
            if ast.delimited[0] == "TAB":
                out += " DELIMITED WITH TAB"
            else:
                out += " DELIMITED WITH CHARACTER '%s'" % ast.delimited[1]
        return out
    if isinstance(ast, LoopStmt):
        return "LOOP"
    if isinstance(ast, OtherwiseClause):
        return "OTHERWISE"
    if isinstance(ast, ExitStmt):
        return "EXIT"
    if isinstance(ast, DoWhile):
        lines = ["DO WHILE " + _emit(ast.cond)]
        lines += ["    " + b for b in ast.body]
        lines.append("ENDDO")
        return "\n".join(lines)
    if isinstance(ast, DoStmt):
        prog = _emit(ast.prog) if not isinstance(ast.prog, str) else ast.prog
        line = ("DO FORM %s" if ast.form else "DO %s") % prog
        if ast.args:
            line += " WITH " + ", ".join(_emit(a) for a in ast.args)
        if ast.to_target is not None:
            line += " TO " + _emit(ast.to_target)
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
            lines += ["    " + b for b in ast.body]
        else:
            for cl, _st in ast.clauses:
                lines.append("    CASE " + _emit(cl.cond))
                lines += ["        " + b for b in cl.body]
            if ast.otherwise_body is not None:
                lines.append("    OTHERWISE")
                lines += ["        " + b for b in ast.otherwise_body]
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
        lines += ["    " + b for b in ast.body]
        if ast.else_body or ast.else_target >= 0:
            lines.append("ELSE")
            lines += ["    " + b for b in ast.else_body]
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
        return text
    if isinstance(ast, CalculateStmt):
        return "CALCULATE %s TO %s" % (
            ", ".join("%s(%s)" % (fn, _emit(e)) for fn, e in ast.items),
            ", ".join(_emit(t) for t in ast.targets))
    if isinstance(ast, ReportFormStmt):
        form = ast.form if isinstance(ast.form, str) else _emit(ast.form)
        text = "REPORT FORM %s" % form
        if ast.objtype is not None:
            text += " OBJECT TYPE %s" % _emit(ast.objtype)
        if ast.to_file is not None:
            text += " TO FILE %s" % _emit(ast.to_file)
        if ast.preview:
            text += " PREVIEW"
        if ast.nowait:
            text += " NOWAIT"
        return text
    if isinstance(ast, RemoveTableStmt):
        return "REMOVE TABLE %s%s" % (ast.name, " DELETE" if ast.delete else "")
    raise Unsupported(f"emit statement {type(ast).__name__}")
