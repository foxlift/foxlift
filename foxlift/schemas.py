# ABOUTME: Measured instruction schema tables for the VFP thin slice — decoding and encoding.
# ABOUTME: Every entry cites its probe case under probes/schema_harvest/cases/. Extends per family.

import struct

from foxlift import registry as _reg

# ---- expression tokens (postfix RPN unless noted) ------------------------------------------
SYM = 0xF7        # f7 <u16> variable push                    (f4_300: index >255 is plain u16le)
NAME = 0xF6       # f6 <u16> array/function-name reference    (f8_arr, f7_cal)
MEMBER = 0xF4     # f4 <u16> member/name reference            (ctl32 witness THIS.Caption)
WITHREF = 0xE2    # e2 f7 <u16>  WITH-scoped .prop reference  (f8_wit)
INT8 = 0xF8       # f8 <digits> <u8>                          (f1_lit: digits = decimal length)
INT16 = 0xF9      # f9 <digits> <u16le>                       (f1_lit, negatives incl sign)
INT32 = 0xE9      # e9 <digits> <u32le>                       (f1_lit |v|>=32768)
FLOAT = 0xFA      # fa <w> <d> <double8>                      (f2_lit; w/d derive from spelling)
STR = 0xFB        # fb <u16len> <bytes>                       (f3_str; never folded past 255)
TRUE = 0x61       # .T.                                       (f2_lit)
FALSE = 0x2D      # .F.
NULL = 0xE4       # .NULL.
CURRENCY = 0xDE   # de <pfx> 04 <i64LE scaled x10^4>         (round-27 oracle-forced b13/b14)
DATE = 0xEE       # ee <8B LE double: JDN + frac-of-day>     (round-27 b8-b10; corpus-aligned)
DATETIME = 0xE6   # e6 <8B LE double: JDN + secs/86400>      (round-27 b12; corpus midnight)
BINARY = 0xFF     # ff <type=01> <u16 len LE> <raw payload>  (round-27 oracle-forced b1-b6)

# Hex integer literals are a member of the INT32 (e9) family whose digits byte counts
# the SOURCE TOKEN length including the '0x' prefix, not len(str(value)). Corpus
# alignment (bytecode matched against the stored source of the same pair):
# corpus carrier 61380f09ff08457f, method Init stmt2 — source '0x00080000'
# compiles to e9 0a 00 00 08 00: digits byte 10 == len("0x00080000"), u32 LE
# = 524288. Consistent with the decimal family rule already pinned by encode_int
# ("digits byte counts characters of the rendered number incl sign"). A digits byte
# that fits NEITHER reading stays the folded-zero-arg-builtin gap (FORMAT.md §6).
HEX_LITERAL_PREFIX_CHARS = 2   # len("0x")

# operators, applied postfix over operand stack
ADD = 0x06; SUB = 0x08; MUL = 0x04; DIV = 0x0C; POW = 0x05          # f5_bin (** == ^ alias 05)
EQ = 0x10; EQEQ = 0x14; NE = 0x0F; LT = 0x0D; GT = 0x11; LE = 0x0E; GE = 0x12   # f5_cmp
CONTAINS = 0x01                                                     # f5_log $
MOD_APPLY = 0x47                                                    # f5_bin % via 43-wrapper
AND_APPLY = 0x09; OR_APPLY = 0x0B                                   # f5_log/f5_lg2
NEG = 0x63                                                          # f6_una unary minus
NOT = 0x0A                                                          # f6_una NOT/!/!.NOT. alias
PAREN = 0x03                                                        # f9_par explicit paren node
# unary plus emits NOTHING (f6_una x=+y identical to bare push) — dropped by design

# short-circuit prefixes: <left> f0|f1 <u16 skip> <right> 09|0b ; skip = len(right)+1 (f5_lg2)
SC_AND = 0xF0
SC_OR = 0xF1

# 43 opens a wrapped operand group closed by the first top-level NAME/escape (call) or 47 (mod):
CALL_OPEN = 0x43                                                   # f7_cal, f5_bin %
ESCAPE = 0xEA                                                      # builtin function: ea <u8> (f2_lit CREATEOBJECT -> ea 4e)
X1A_ESCAPE = 0x1A                                                  # third builtin bank: 1a <u8>
EA_BYREF_ID = 0x19                                                  # ea 19 prefixes by-reference arguments
BARE_BYREF = 0xEB                                                   # bare-bank by-reference argument prefix

# ---- statement leads ------------------------------------------------------------------------
ASSIGN = 0x54      # 54 <lvalue> 10 <expr>                        (everywhere)
STORE = 0x4A       # 4a fc <expr> fd 28 <target> [07 <target>]*
PRINTQ = 0x02      # ?  : 02 <count-lit f8 03 N> <arg> [07 <arg>]*
PRINTEE = 0x03     # ?? — same shape                               (f7_qm2)
LOCAL = 0xAE       # ae <name> [07 <name>]*  ; typed adds 51 fb <len> <type>  (f8_typ)
LPARAMS = 0xAF     # af <name> [07 <name>]*                       (f7_cal FUNCTION F(a,b))
ERASE_LEAD = 0x20  # 20 fb <file> (CMD_SWEEP bound row: 'ERASE ers1.txt' -> 20fb0800657273312e747874)
PARAMETERS_LEAD = 0x34  # 34 f7 <sym> name-list (HARVEST.md round-3, oracle-measured; != LPARAMETERS af)

# ---- ON-family selectors, round-20 FORCED (probes/oracle_harvest/round20_*.json) ---------------
# Valid ONLY beneath statement lead 0x31. bd is CONTEXT-LOCAL REUSE: as a statement
# lead bd = THROW (round-20 n11); as a selector here bd = ON ESCAPE (n03). Never
# promote these into a global byte->token map.
ON_SELECTOR_ERROR = 0x10        # n01/n12
ON_SELECTOR_ESCAPE = 0xBD       # n03; collides with THROW only outside lead 31
ON_SELECTOR_SHUTDOWN = 0xCD     # n05
ON_SELECTOR_KEY_LABEL = 0x17    # n04; then the KEY LABEL marker:
ON_KEY_LABEL_MARK = 0x32        # label itself an fb string, then the handler string
ON_SELECTION_PREFIX = 0xD0      # SELECTION family opener (n08-n10)
ON_SELECTION_POPUP = 0xC6       # d0 c6 f7 <popup>
ON_SELECTION_MENU = 0x1C        # d0 1c f7 <popup>
ON_SELECTION_BAR = 0x06         # d0 06 fc<expr>fd c3 f7 <popup>; c3 = OF
ON_SELECTION_OF = 0xC3

# Bare/placeholder ON family under its OWN lead, kept SEPARATE from the 0x31 map
# above: round-13 HARVEST ('ON PAGE DO pgh' emits ONLY `7b be` — the handler
# string produces no bytecode) and ORACLE round-25 o1/o2 ('ON SHUTDOWN' ->
# 7b cd fb 00 00, bare 'ON ERROR' -> 7b 10 fb 00 00). Selector bytes are again
# CONTEXT-LOCAL UNDER THIS LEAD: cd doubles as ALEN in registry.BARE_IDS and as
# a selector under lead 0x31 — disjoint namespaces, never a global table.
ON_BARE_LEAD = 0x7B
ON_PAGE_SELECTOR = 0xBE     # value collides with ENDTRY_LEAD; context-local

# ORACLE round-25 forced_rules[0] (r1/r2; CMD_SWEEP RUN=43 row): lead 0x43 =
# RUN / `!` — the WHOLE command line verbatim as ONE fb string; casing is
# preserved ('/N7' in corpus txtcollectqichachaclean s0 stmt[173] vs authored
# '/n7' in r1).
RUN_LEAD = 0x43
# ORACLE round-25 forced_rules[3] (c1 = `53`; corpus cboHierarchy s1 stmt[7]):
# ZAP is a bare one-byte statement. r42-zapin: ZAP IN <alias> is
# 53 16 f7 <u16> (AATest frstestharn s5[0] 5316f70000). r54-inalias: the alias
# takes the same three spellings SET's 16 mark carries — bare symbol, work-area
# number, or its own fc..fd group with the 03 runtime-paren postfix.
ZAP_LEAD = 0x53
# ORACLE CMD_SWEEP.md row RECALL (probes/oracle_harvest/CMD_SWEEP.md line 141:
# authored source 'RECALL' compiled to bare `3a`); the round-30 followup carries
# the matching one-byte corpus form (_dialogs.vcx::_keywords s0 stmt[32],
# wire `04 00 3a fe`). Value collides with the NOWAIT clause byte — context-local
# under this lead only.
RECALL_LEAD = 0x3A
# ORACLE round-25 forced_rules[5] (c4/c5; corpus xfrxlib.vcx::cboHierarchy s1
# stmts[18]/[23]): APPEND FROM clause under lead 06. Value collides with DIM
# (0x15) and GATHER_FROM_MARK — context-local under this lead only.
APPEND_FROM_MARK = 0x15
# ORACLE round-25 forced_rules[4] (c2/c3; corpus cboHierarchy s1 stmts[25]/[27]):
# setting id 0d = DECIMALS under lead 47; a parenthesized TO-value group carries
# the runtime-paren marker 03 INSIDE its group before the closing fd.
SET_DECIMALS_ID = 0x0D

# ---- DECLARE-DLL statement (lead 0x7c), wave-2 lane lead-7c -------------------------------------
# Shape read from all 301 lead-7c statements in the frozen benchmark:
#   7c [<ret>] fb <u16-len> <func-name> 16 <lib> [51 fb <alias>] <type> (07 <type>)*
# Token meanings are pinned by the carriers' OWN stored METHODS sources:
#   d1 Integer  (cmd_sweep oracle row 'DECLARE INTEGER GetFocus' + oaremotionweb.rtx)
#   d2 Single   (_gdiplus.vcx::gppen 'single fWidth' / 'single @ fWidth')
#   d4 Long     (vfp_skins 'DECLARE LONG CombineRgn ... LONG,LONG,LONG,LONG')
#   d6 String   (oaremotionweb.rtx 'String szUrl' / 'String pCaller,...')
#   57 Short    (txtcollectshuidiqushu 'Short bVk,Short bScan'; ssfader 'SHORT bAlpha')
#   2e Object   (aatest 'integer, integer, string , object @')
#   18 suffix = '@' byref on the preceding type ('object @', 'Integer @nPen')
#   51+fb      = 'AS <alias>' between library and params (registry.vcx 'AS Find_Window')
#
# The <lib> slot has two shapes and the difference is the AUTHOR'S QUOTING, measured
# round-41 (probes/oracle_harvest/round41_declareparams_*, probes d1/d2/d3/d4/d6/d7):
#   16 fb <u16> <text>              IN gdi32           bare name, also registers the
#                                                      dotted parts as symbols
#   16 fc d9 <u16> <text> fd        IN "Shell32.dll"   double-quoted (STR2), registers
#                                                      no symbol for the library
#   16 fc fb <u16> <text> fd        IN 'Shell32.dll'   single-quoted
#   16 fc <expr> 03 fd              IN (THIS.cDllFile) parenthesised: 03 is the
#                                                      runtime-paren marker
# Both corpus carriers reproduce byte-for-byte from the quoted spelling and not from
# the bare one, so a bare rendering of an fc-wrapped library loses recorded text.
#
# Parameter NAMES are NOT in this shape at all — same round-41 batch, families a/c/e:
# named, nameless and renamed spellings collapse onto one stream while two negative
# controls separate. They are documentation the compiler discards; nothing recovers them.
DECLARE_IN_MARK = 0x16
DECLARE_AS_MARK = 0x51
DECLARE_TYPE_INTEGER = 0xD1
DECLARE_TYPE_SINGLE = 0xD2
DECLARE_TYPE_LONG = 0xD4
DECLARE_TYPE_STRING = 0xD6
DECLARE_TYPE_SHORT = 0x57
DECLARE_TYPE_OBJECT = 0x2E
DECLARE_PARAM_BYREF = 0x18

# ---- TEXT...ENDTEXT frame and WITH AS clause, round-23 FORCED -----------------------------------
# (probes/oracle_harvest/round23_*.json: every pre-run pin matched byte-exact on
# the first batch; corpus twins unicode.scx::Command1 and chartadjust.scx::Command3)
TEXT_LEAD = 0x4D             # bare '4d', else 4d 28 <target> [flags]; t1..t7
ENDTEXT_LEAD = 0x1F          # standalone frame sentinel closing a TEXT block
TEXT_FLAG_TEXTMERGE = 0x60   # wire-ordered BEFORE NOSHOW even when source says otherwise (t4/t6)
TEXT_FLAG_NOSHOW = 0xCE      # t3
TEXT_FLAG_ADDITIVE = 0x01    # wire-AFTER NOSHOW though sources spell it first (t5/t6)
TEXT_FLAG_PRETEXT = 0xC3     # round-37 C07/J1: in the fixed wire order 60 -> ce -> 01 ->
                             # c3 -> c4, carrying an fc-wrapped EXPRESSION argument closed
                             # by fd only when a clause follows and reader-stripped when
                             # statement-final. round-62 r62-texthead re-measured: the
                             # argument is any expression, not only a small int ('PRETEXT 2'
                             # = c3 fc f8 01 02, 'PRETEXT "z"' = c3 fc d9 01 00 7a,
                             # 'PRETEXT m.lnP' = c3 fc f5 0d f7..); corpus twins aatest.scx
                             # 'PRETEXT 14' = fc f8 02 0e, sstextbox.scx '{NOSHOW}
                             # PRETEXT 1' = fc f8 01 01, fxu.vcx 'NOSHOW PRETEXT 3 FLAGS 1'
                             # = ce c3 fc f8 01 03 fd c4 fc f8 01 01
TEXT_FLAG_FLAGS = 0xC4       # round-62 r62-texthead: the FLAGS nFlags clause, LAST in the
                             # wire order (behind PRETEXT), same fc-wrapped-expression shape
                             # ('FLAGS 1' = c4 fc f8 01 01)
# 0xFB inside a TEXT frame = one verbatim body line, fb <u16 len excluding newline>
# <bytes>; reuse of the STR literal token, context-local to the frame. Met at
# STATEMENT level (a section that failed to lift for another reason), it is the
# same verbatim line: dec_statement decodes it standalone (round-62 r62-textline).
AS_CLAUSE_MARK = 0x51        # WITH ... AS <class> (round-23 w3; class uppercased on the
                             # wire) AND typed-LOCAL '<name> AS <type>' (same byte; also
                             # SQL alias / DECLARE alias slots elsewhere)
LOCAL_OF_MARK = 0xC3         # typed-LOCAL 'AS <type> OF <library>' (chartadjust.scx::
                             # Command3 stmt0, OF "..\class\FoxCharts.Vcx"; corpus
                             # alignment -- round-23 logged it as corroboration only,
                             # confirmed against the pair's own bytes+source)
RETURN = 0x42      # 42 [[04] fc expr fd]                        (f7_cal)
RETURN_TO_MASTER_WORD = 0xBC  # r51-carriers: 'RETURN TO MASTER' is 42 28 bc —
                     # the universal 28 TO mark with a WORD behind it instead of a
                     # target. 'RETURN TO <prog>' puts an f7 symbol there instead.
RETURN_BYREF = 0x04  # r50-sysapp: 'RETURN @<expr>' puts an 04 in front of the
                     # group; no unmarked spelling produces one, so the two are
                     # wire-distinguishable and the '@' is recoverable.
DIM = 0x15         # 15 <name f6> fc <dim> fd [07 fc <dim> fd]* 03 (f8_arr/f8_ar2)
WITH = 0xA6        # a6 fc <expr> fd f9 05 <u16 slot-word>        (f8_wit; word stable across runs)
ENDWITH = 0xA7     # a7
EXPRSTMT = 0x86    # 86 fc <expr> fd                              (f7_cal "= F()")

ARGJOIN = 0x07     # separator between STORE targets / print args / dims / extra names

# ---- phase-4 cluster (probes/phase4_cluster/FINDINGS.md — forced from stored gold pairs;
# ---- N evidence counts stated there; nothing below is inferred-only) ------------------------
STR2 = 0xD9          # d9 <u16len> <bytes> DOUBLE-quoted literal; fb stays single-quoted
                     # (12/12 aligned examples carry the source's quote character)
EXPRSTMT_BARE = 0x99 # 99 fc <expr> …      bare call/reference line, NO "=" prefix
                     # 99 <path>           member invocation without parens
                     # (the trailing fd of the fc-form is consumed by the reader's fd-fe strip)
IF_LEAD = 0x25       # 25 fc <cond> fd f9 05 <u16 rel-target>; body; ENDIF
ENDIF_LEAD = 0x1E    # bare ENDIF statement
# NOTE 0x0C doubles as DIV inside expressions; context (statement lead) disambiguates.
DO_CASE_LEAD = 0x18  # 18 48 f9 05 <t1> f9 05 <t2>: DO CASE opener. FORCED 22/22:
                     # t1 = first CASE prefix - code_base, t2 = matching ENDCASE - code_base.
                     # (A second subtype 18 2b fc <cond> fd f9 05 <u16> = DO WHILE exists
                     # but its terminator set is unforced — left Unsupported this iteration.)
CASE_CLAUSE = 0x0C   # 0c fc <cond> fd f9 05 <u16>: CASE clause; u16 = next-clause-or-
                     # ENDCASE prefix - code_base (FORCED 84/87). Round-33 adds the
                     # LONG-jump width of the same landing: [fd] e9 00 <u32>, exact
                     # end-of-statement (oaremotion1.scx::rtx s14 clauses).
ENDCASE_LEAD = 0x1C
OTHERWISE_LEAD = 0x32   # 32 f9 05 <u16>: OTHERWISE clause; u16 = ENDCASE prefix -
                        # code_base (same anchor family), forced by _outputdialog.
                        # Round-42 adds the long-jump width 32 e9 00 <u32>, length
                        # exactly 7 (listener.vcx u32-framed methods; oracle
                        # sibling-forced and overflow-forced compiles).  # bare ENDCASE
WAIT_CLEAR = 0x52   # 52 2c fc <expr>: WAIT WINDOW <expr>; 52 0c: WAIT CLEAR.
                    # FORCED subset only — a variant with an extra 3a byte after WINDOW
                    # and AT-clause forms exist whose discriminator is UNMEASURED (same
                    # statement text appears with and without 3a across methods); they
                    # stay Unsupported. Probe needed (lane A): minimal WAIT programs
                    # varying NOWAIT/NOCLEAR/AT/TIMEOUT.
# SQL-SELECT ... INTO CURSOR (FORCED subset, dashboard.scx::Header1 x2 branches +
# setworkdtotal::Command1): 6f 15 <d9/fb FROM-string> c7 c3 fc <order-expr> fd
# [3c = DESC] bc bd <d9/fb CURSOR-string>. Column lists / WHERE / joins UNFORSED ->
# strict shape checks fail loudly on anything else.
# DO command family (lead 0x18, subtype byte second; Guineu: DO=0x18, ENDDO=0x1D):
DO_CASE_LEAD = 0x18
DO_CASE_FRAME_MARK = 0x48  # second-byte frame subtype under lead 0x18: 18 48 f9 05
                           # <t1> f9 05 <t2> = DO CASE opener (FORCED 22/22); round-33
                           # adds the long-jump width 18 48 e9 00 <u32 t1> e9 00 <u32
                           # t2> (length exactly 14; oaremotion1 rtx s14/s19,
                           # dashboardset Frmfood s1). Byte position disambiguates it
                           # from SKIP_LEAD, which is the same value as a statement
                           # LEAD — unrelated meanings.
DOWHILE_MARK = 0x2B  # 18 2b fc <cond> fd f9 05 <u16>: DO WHILE; u16 = matching ENDDO
                     # prefix - code_base (FORCED 19/19). Bare 1d = ENDDO.
ENDDO_LEAD = 0x1D
FOR_LEAD = 0x84      # 84 <lv> 10 fc <start> fd 28 fc <end> fd [c7 fc <step> fd]
                     #   [f9 05 <target>]; bare 85 = ENDFOR. Forced x3 sources
                     #   ('FOR lnCount = ... TO ... [STEP -1]'). Guineu: FOR=0x84,
                     #   ENDFOR=0x85, TO=0x28(clause), STEP=0xC7(clause), LOOP=0x2E,
                     #   EXIT=0x21.
ENDFOR_LEAD = 0x85
TO_MARK = 0x28
STEP_MARK = 0xC7
LOOP_LEAD = 0x2E     # bare LOOP
EXIT_LEAD = 0x21     # bare EXIT

# ---- DEFINE family (round-24 oracle batch, probes/oracle_harvest/round24_*.json;
#      HARVEST.md round-24; corpus-aligned on mainmenur.scx::cdtj and
#      workerchart.scx::Organizationchart1.onnodeclick) ----
DEFINE_LEAD = 0x73   # ONE construct: keyword byte selects the object.
DEFINE_WINDOW_KW = 0x2C   # DEFINE WINDOW ... (m1 replica byte-exact); also the
                          # WINDOW keyword under leads 09/3c below. NOT an lvalue.
                          # r42-clear: CLEAR WINDOW is 0e 2c (AATest frstestharn
                          # s38[4]). WINDOWS / WINDOW w1 collapse to the same.
DEFINE_POPUP_KW = 0xC6    # DEFINE POPUP / ACTIVATE POPUP object keyword
DEFINE_BAR_KW = 0x06      # DEFINE BAR <n> OF <popup> (g3/g4)

# CLEAR's operand bank under lead 0x0e — ONE keyword byte and nothing else,
# swept whole on the oracle (r54-clearbank: every keyword VFP9's CLEAR accepts,
# 25 programs). WINDOW and WINDOWS share 0x2c (r42-clear). CLEAR ECHO and a
# bare CLEAR CLASSLIB are not in the language: VFP9 refuses both. The operands
# that carry a payload keep their own arms and appear here for their BARE form
# only — DLLS 0x56, RESOURCES 0xcc; CLASS 0x4f and CLASSLIB 0x52 have no bare
# form at all and are absent.
CLEAR_KEYWORDS = {
    0x03: "ALL", 0x11: "FIELDS", 0x1A: "MACROS", 0x1B: "MEMORY",
    0x1C: "MENUS", 0x22: "PROMPT", 0x2C: "WINDOW", 0x4B: "PROGRAM",
    0x56: "DLLS", 0xC2: "GETS", 0xC6: "POPUPS", 0xC8: "READ",
    0xCA: "DEBUG", 0xCC: "RESOURCES", 0xD4: "TYPEAHEAD", 0xD5: "EVENTS",
}
CLEAR_READ = 0xC8         # CLEAR READ ALL is READ's byte then ALL's own 0x03
CLEAR_ALL = 0x03
CLEAR_CLASSLIB = 0x52     # CLEAR CLASSLIB <name>, the name an fb/d9 literal
DEFINE_PAD_KW = 0xBC      # DEFINE PAD <name> OF _MSYSMENU (r43-pad); 0xBC is
                          # FINALLY / ON PAD / ACTIVATE elsewhere — lead 0x73
                          # decides
PAD_BEFORE_MARK = 0xBE    # BEFORE <pad> = be f7<sym> (r43-pad); WINDOW CLOSE
                          # is the same byte under DEFINE WINDOW
PAD_MARK_CLAUSE = 0xC7    # MARK <expr> (r43-pad); STEP_MARK in FOR, position
                          # decides
PAD_NEGOTIATE_MARK = 0x54 # NEGOTIATE LEFT = 54 58 (r43-pad); assignment lead
                          # 0x54 elsewhere
PAD_NEGOTIATE_LEFT = 0x58
DEFINE_FROM_MARK = 0x15   # FROM-list intro (m1/g1)
DEFINE_BAR_OF = 0xC3      # BAR OF popup (c3 f7<sym>); byte collides with
                          # C3_ORDER (SQL namespace) — position decides
WIN_SCHEME_MARK = (0x0D, 0x4E)  # COLOR SCHEME n = 0d 4e fc<n>fd (m4); the group
                          # is WIRE-REORDERED ahead of grow/close regardless of
                          # source order. Pre-run guess 0d/4e=GROW/CLOSE refuted.
DEFINE_WIN_GROW = 0xC1    # GROW flag (m2 isolation; pre-run guess had 0d/4e)
DEFINE_WIN_CLOSE = 0xBE   # CLOSE flag (m3 isolation); collides with ENDTRY_LEAD
# ---- window family, round-40 lane H (oracle batch of 2026-08-26, ONE compile_dir
#      run recorded in probes/oracle_harvest/round40_windowreport_streams.json;
#      it re-measures the round-37 wave-2 w7b probes d01-d12/r07 and adds the
#      single-flag isolations those left open). Carrier for every shape below:
#      _reports.vcx::_output (pair 9d9e5428ee2c7bd2 section 3)
#      statements #15 / #92 / #110, whose replicas f19/f20/f21 compile
#      byte-identical modulo symbol indexes.
DEFINE_WIN_AT = 0x05      # AT <row> 07 <col> — the second position spelling
                          # (f19/d01); 0x15 FROM..0x28 TO is the first. Same byte
                          # as ACTIVATE POPUP's AT mark; lead context decides.
DEFINE_WIN_SIZE = 0xD3    # SIZE <height> 07 <width>, always paired with AT
DEFINE_WIN_NAME = 0x4A    # NAME <object-name> (f19 paren group; d02 bare string)
DEFINE_WIN_FONT = 0x40    # FONT <name> [07 <size>] (f19 one operand, d04 two)
DEFINE_WIN_TITLE = 0x27   # TITLE <expr> (f19/d05); BROWSE_TITLE_MARK's byte
DEFINE_WIN_IN = 0x16      # IN WINDOW <expr> (f19/d06); GO_IN_CLAUSE's byte, and
                          # the same IN-WINDOW mark leads 0x74/0x80 carry
# Attribute words: every id below is a SINGLE-FLAG oracle isolation from that
# batch (f01-f16 'DEFINE WINDOW w1 <word>' -> '732cf70000 <byte>'); GROW/CLOSE
# re-confirm round-24 m2/m3 independently. The wire order is CANONICAL and not
# the source order: 'SYSTEM FLOAT ZOOM' and 'ZOOM FLOAT SYSTEM' both compile to
# 'bf d5 d4' (f17 == f18), so the spelled order is NOT recoverable — emission
# renders wire order, as DEFINE WINDOW's COLOR SCHEME group already does.
# SYSTEM (d4) sits LAST on the wire, after the TITLE and IN-WINDOW groups (f19).
# Namespaces stay position-resolved: 0xBE is CLOSE here, MAX under the ZOOM
# WINDOW lead, and WONTOP as a bare group closer; 0xBF is FLOAT here, MIN under
# ZOOM WINDOW, and WOUTPUT in the bare bank.
DEFINE_WINDOW_ATTRS = {
    0x0F: "DOUBLE",     0xBD: "MINIMIZE",   0xBE: "CLOSE",  0xBF: "FLOAT",
    0xC1: "GROW",       0xC2: "HALFHEIGHT", 0xC3: "NOCLOSE", 0xC6: "NOFLOAT",
    0xC7: "MDI",        0xC8: "NOGROW",     0xCA: "NOMINIMIZE", 0xCB: "NONE",
    0xD0: "PANEL",      0xD1: "NOZOOM",     0xD4: "SYSTEM", 0xD5: "ZOOM",
}
ZOOM_WINDOW_LEAD = 0x8C   # 8c 2c <name> <mode> — ZOOM WINDOW (the lead-map
                          # correction recorded in round37 findings D5/C06-core)
ZOOM_WINDOW_MODES = {0xBE: "MAX", 0xBF: "MIN", 0xD6: "NORM"}   # f20/f22/f23 +
                          # round-37 D5; a fourth keyword does not exist — the
                          # oracle REJECTS 'ZOOM WINDOW w1 BOGUS' outright (f30)
ACTIVATE_WIN_SAME = 0xCF  # 74 2c cf <name> = ACTIVATE WINDOW <name> SAME (f21);
                          # siblings measured but not carried: TOP=29, BOTTOM=36
# APPEND FROM / COPY TO file types, one byte each and no WITH tail except
# DELIMITED's (r48-valsweep: `APPEND FROM t SDF` -> 0615fb010074d0,
# TYPE FOXPLUS -> …d4bd, TYPE XL5 -> …d4bb, TYPE XLS -> …d4c7,
# TYPE DELIMITED -> …d4be). The optional d4 records only that the source
# spelled the word TYPE (r47-typeword).
FILE_TYPE_WORDS = {0xD0: "SDF", 0xBE: "DELIMITED", 0xC7: "XLS",
                   0xBB: "XL5", 0xBD: "FOXPLUS"}
# SHOW WINDOW's own modifier bank, between the 2c and the name (r48-valsweep:
# `SHOW WINDOW w REFRESH` -> 802cc4f70000, TOP -> 802c29f70000, BOTTOM ->
# 802c36f70000, SAME -> 802ccff70000). HIDE WINDOW (0x87) takes none of them.
SHOW_WINDOW_MODIFIERS = {0xC4: "REFRESH", 0x29: "TOP", 0x36: "BOTTOM",
                         0xCF: "SAME"}
POPUP_SHORTCUT_MARK = 0x57  # SHORTCUT flag (g1 isolation — pre-run cc/57 guess REFUTED)
POPUP_RELATIVE_MARK = 0xCC  # RELATIVE flag (g2 isolation)
BAR_PROMPT_MARK = 0x22        # BAR PROMPT fc<str>fd (g3)
BAR_SKIPFOR_MARK = (0xC9, 0x13)  # BAR SKIP FOR fc<expr>fd (g4)
BAR_PICTURE_MARK = 0xC2       # BAR PICTURE fc<str>fd (g3/g4); collides with
                              # USE_SHARED_FLAG etc. — lead-0x73 context only
BAR_PICTRES_MARK = 0x5F       # BAR PICTRES fc ec <id> (r43-pictres); statement-
                              # final fd is reader-stripped. PICTURE is 0xc2
                              # and does not emit 0x5f.
ACTIVATE_POPUP_LEAD = 0x74    # 74 c6 f7<sym> = ACTIVATE POPUP (g5; CMD_SWEEP ACTIVATE=74)
ACTIVATE_SCREEN_KW = 0x26     # 74 26 = ACTIVATE SCREEN (audit-B order-4 corpus alignment,
                              # winsock.vcx::Olecontrol1 stmt[4] vs stored source line 10);
                              # byte is DBF()'s bare group-closer id in expression space —
                              # statement position under lead 0x74 decides
BROWSE_LEAD = 0x09            # 09 2c f7<w> ... = BROWSE WINDOW (m5); collides with
                              # AND_APPLY (expression namespace) — statement position decides
BROWSE_TITLE_MARK = 0x27      # 27 fc<TITLE>fd (m5)
BROWSE_TIMEOUT_MARK = 0xCE    # ce fc<TIMEOUT>fd (m5); cross-binds round-15's WAIT
                              # TIMEOUT byte (TEXT_FLAG_NOSHOW is another namespace)
BROWSE_FOR_MARK = 0x13        # 13 fc<FOR>fd (round-31 attendanceset frmWeixiu s1); the
                              # same FOR-marker byte SCAN FOR / LOCATE FOR carry
BROWSE_FIELDS_MARK = 0x11     # 11 <items joined by 07> (round-28 pricelistdetail
                              # Command1 s0); COPY_LEAD's byte, context-local under 09
BROWSE_WINDOW_MARK = 0x2C     # 2c f7<win> (m5); DEFINE_WINDOW_KW's byte

# BROWSE's clause list, in the ONE canonical order the wire stores it in.
# r53-browsehead measured the envelope over 45 authored programs: BROWSE has no
# mandatory head, and every permutation of a clause set compiles to the SAME
# frame — the source's order survives only in the section's symbol table, never
# in the statement. So the reader walks this table once, in this order, and a
# clause byte the table does not name keeps its refusal. The table holds only
# clauses a measured law admits; it grows one law at a time.
#
# Each entry is (byte, operand kind, source word, BrowseWindow field):
#   flag    = the byte alone, no operand
#   group1  = fc <expr> [fd] — exactly one operand
#   group2  = up to two operands, fc groups joined by ARGJOIN 07 (KEY's range)
#   group3  = up to three (FONT's face, size, style)
#   name    = f7 <u16>, or an fc <expr> 03 group when the source spelled ()
#   litname = a name, or an un-grouped d9 / fb string literal (PREFERENCE only)
#   valid   = VALID's own frame: [c6 = :F] fc <cond> [fd 10 fc <ERROR text>]
#   fields  = the 11 item list, with its own attribute grammar
# A groupN clause reads AT MOST n operands: r53-browseval authored every arity
# the language accepts for KEY and FONT, and a longer list is a shape no
# carrier shows, so it keeps its refusal.
# A clause with a field name is one of the five round 24/28/31 gave
# `BrowseWindow` an attribute for; the rest are carried in `clauses`, in this
# order, and emitted by the word recorded here. NOEDIT's `c5` is also
# NOMODIFY's: the wire records the clause, never which word was written
# (r53-browseflag), so the emitter writes one of them.
BROWSE_CLAUSES = (
    (0xC7, "flag", "NOFOLLOW", None),
    (0xC6, "flag", "NOCAPTIONS", None),
    (0xC2, "flag", "LAST", None),
    # PREFERENCE shares LAST's position: VFP9 refuses to write the pair, so no
    # frame ranks them and `_dec_browse` refuses a frame that carries both
    (0xD1, "litname", "PREFERENCE", None),
    (0x30, "flag", "NOOPTIMIZE", None),
    (BROWSE_FOR_MARK, "group1", "FOR", "for_cond"),
    (BROWSE_FIELDS_MARK, "fields", "FIELDS", "fields"),
    (0x40, "group3", "FONT", None),
    (0x19, "group1", "LOCK", None),
    (0xC0, "name", "FREEZE", None),
    (0xCA, "flag", "NOMENU", None),
    (0xC1, "flag", "NOAPPEND", None),
    (0xD4, "group1", "WIDTH", None),
    (0xC5, "flag", "NOEDIT", None),
    (0xC4, "flag", "NODELETE", None),
    (0xD0, "flag", "NOCLEAR", None),
    (0x14, "flag", "FORMAT", None),
    (BROWSE_WINDOW_MARK, "name", "WINDOW", "window"),
    (0x3A, "flag", "NOWAIT", None),
    (0x25, "flag", "SAVE", None),
    (0xD6, "flag", "NORMAL", None),
    (0x17, "group2", "KEY", None),
    (BROWSE_TITLE_MARK, "group1", "TITLE", "title"),
    (BROWSE_TIMEOUT_MARK, "group1", "TIMEOUT", "timeout"),
    (0x16, "name", "IN WINDOW", None),
    (0xBD, "flag", "NOLINK", None),
    (0x50, "flag", "NOLGRID", None),
    (0xCD, "flag", "NORGRID", None),
    (0xD5, "group1", "PARTITION", None),
    (0xD2, "group1", "WHEN", None),
    (0x2A, "valid", "VALID", None),
    (0xC3, "flag", "NOREFRESH", None),
)
PARAM_OF_MARK = 0xC3          # typed parameter 'As Class Of library': c3 fb<lib>
                              # verbatim (round-24 l1); byte collides with C3_ORDER /
                              # DEFINE_BAR_OF — position under lead af/34 decides

# ---- CREATE / INSERT family (round-26 oracle batch,
#      probes/oracle_harvest/round26_findings.json + round26_streams.json;
#      corpus-aligned on _reportlistener.vcx::_reportlistener::preparefrxswapcopy) ----
CREATE_LEAD = 0x13            # bare CREATE <name> = 13 fb<name> (CMD_SWEEP);
                              # byte doubles as the FOR clause under lead 7e
                              # (SCAN) — context decides. CURSOR owns 0x68.
CREATE_REPORT_KW = 0x33       # 33 under lead 0x13: CREATE REPORT (round-26 c3);
                              # byte is PACK's statement lead elsewhere — position decides
CREATE_CURSOR_LEAD = 0x68     # 68 {bd|31} fb<name> 02 <fields> 03 (round-26 c1/c2).
                              # 0xBD = CREATE CURSOR; 0x31 = CREATE TABLE (round-42
                              # clause batch). DISCOVERY: the NAME occupies SYMBOL
                              # SLOT 0 ahead of field names though carried as an fb string.
                              # r75-fromarray: FROM ARRAY is 15 04 <array> after the
                              # name (and after optional FREE c0 / CODEPAGE ba), with
                              # no field list.
CREATE_FROM_MARK = 0x15       # FROM under lead 0x68 (r75-fromarray). Same byte as
                              # the universal FROM_MARK; position under 68 decides.
CREATE_ARRAY_MARK = 0x04      # ARRAY after FROM under lead 0x68 (r75-fromarray).
                              # Same byte as CALC_TO_ARRAY_MARK / SQL INTO ARRAY.
INSERT_LEAD = 0x72            # 72 bc <target-group> 15 c2 =
                              # INSERT INTO (<expr>) FROM MEMVAR (round-26 i1)
SQL_INTOTABLE_MARK = (0xBC, 0x31)  # INTO TABLE (<expr>) vs INTO CURSOR bc bd
                                   # (round-26 s1/corpus stmt[45]); READWRITE=d7
SQL_LIKE_MARK = 0xCF     # comparison closer binding `43 <l> <r> cf` = LIKE
                         # (round-34 lane A: mhxpcontrol.vcx extwindow s0 stmt3 /
                         # text s6 stmt10 <-> stored '… WHERE EXTTYPE LIKE SQLTYPE …')
SQL_INTOARRAY_MARK = (0xBC, 0x04)  # INTO ARRAY <sym> tail `bc 04 f7 <u16>` beside the
                                   # INTO CURSOR bc bd spelling (round-34 lane A, same
                                   # two carriers; cf. COPY TO ARRAY '11 28 04 f7')
SKIP_PARAM_ON_FALSE = 0xF2   # IIF()/ICASE() parameter-navigation markers carrying
SKIP_PARAM_ON_TRUE = 0xF3    # a u16 skip; consume-and-ignore (Guineu reader semantics,
                             # confirmed: 11/16 blocked statements lift on strip-test)
SCOPE_OP = 0xDF      # df e3 <u16 class> f7 <u16 member>: CLASS::MEMBER scope ref
SCOPE_CLASS = 0xE3   # class-name reference token inside the scope form
ARRAY_ELEM_CALL = 0xE5 # e5 <u16 sym>: close array-element method receiver;
                     # pops the subscript pushed just before ('lao(1)')
ARRAY_MEMBER = 0xE0  # e0 <u16 sym>: WITH-scoped array element (.aChoices[i])
SET_LEAD = 0x47      # 47 <setting-id> [clauses]. FORCED subset only:
                     #   47 80 28 fc <expr> fd  = SET DATASESSION TO (expr)  (4+ methods)
                     #   47 15 20               = SET ESCAPE ON   (aligned 'SET ESCAPE ON')
                     #   47 1a 28               = SET FILTER TO    (empty filter form)
                     #   47 2b 28               = SET PROCEDURE TO
                     # Setting ids are yet another per-command namespace; unforced
                     # variants stay Unsupported until aligned (probe queued).
PUBLIC_LEAD = 0x37   # 37 <name-list> mirrors LOCAL grammar (ARGJOIN names)
# r50-leadsweep — the file-verb bank, one construct per program, frames read
# off the compile. Each verb's clause bytes are the estate-wide ones: 28 TO,
# 15 FROM, 03 the ALL scope, 18 LIKE / bc EXCEPT.
TYPE_LEAD = 0x4F         # TYPE [TO PRINTER] <file>
COMPILE_LEAD = 0x83      # COMPILE [DATABASE] <name>
RUNSCRIPT_LEAD = 0x92    # RUNSCRIPT <file>
LOAD_LEAD = 0x2C         # LOAD <module>
CALL_LEAD = 0x0A         # CALL <module>
PLAY_LEAD = 0x81         # PLAY MACRO <name>
BUILD_LEAD = 0x8F        # BUILD <kind> <name> FROM <source>
SAVE_LEAD = 0x44         # SAVE [kind] TO <file> [ALL LIKE|EXCEPT <skel>]
RESTORE_LEAD = 0x40      # RESTORE [kind] FROM <file> [ADDITIVE]
GETEXPR_LEAD = 0x82      # GETEXPR [<prompt>] TO <var> [TYPE <c>] [DEFAULT <e>]
PRINTER_KW = 0x21        # the PRINTER word REPORT FORM's own TO clause carries
DATABASE_KW = 0xC2       # COMPILE DATABASE; the same c2 CLOSE DATABASES spends
MACROS_KW = 0x1A         # SAVE/RESTORE/PLAY MACROS
FROM_MARK = 0x15         # the universal FROM clause (APPEND FROM, RESTORE FROM)
RESTORE_ADDITIVE = 0x01  # RESTORE FROM <f> ADDITIVE
GETEXPR_TYPE_MARK = 0xD4
GETEXPR_DEFAULT_MARK = 0x0E
# r51-carriers: DLL and MTDLL join the bank; both carry the EXE frame byte
# for byte, and RECOMPILE appends BUILD_RECOMPILE_WORD to any of them.
BUILD_KINDS = {0xC5: "PROJECT", 0xBD: "APP", 0xBE: "EXE",
               0xC6: "DLL", 0xC8: "MTDLL"}
BUILD_RECOMPILE_WORD = 0xCB
SAVE_RESTORE_KINDS = {0x1A: "MACROS", 0x26: "SCREEN", 0x2C: "WINDOW"}
ALL_QUALIFIERS = {0x18: "LIKE", 0xBC: "EXCEPT"}

UPDATE_SQL_LEAD = 0x70   # r50-leadsweep: UPDATE <t> [FROM <s>] SET <c> = <e> …
SQL_DELETE_LEAD = 0x71   # r52-sqldelete: DELETE FROM <target> [WHERE <cond>].
                         # The target is a bare fb name or its own fc..fd
                         # group with the 03 runtime-paren postfix; the
                         # condition rides one group behind the c6 WHERE mark.
                         # The xbase DELETE is lead 0x14, a different verb.

# The xbase DELETE's record-scope bank — ORACLE-MEASURED r54-inalias (41
# programs). The wire order under lead 0x14 is
#   14 [16 <alias>] [30] [<scope>] [13 fc <for>] [2b fc <while>]
# and the source spells it the other way round:
#   DELETE [<scope>] [FOR <c>] [WHILE <c>] [IN <alias>] [NOOPTIMIZE]
# NEXT and RECORD carry their count in an fc-group; ALL and REST are bare. The
# scope byte for ALL is the same 03 REPLACE spends, and NEXT's 1e and FOR's 13
# are the estate-wide clause bytes.
DELETE_SCOPE_WORDS = {0x03: "ALL", 0x24: "REST", 0x1E: "NEXT",
                      0x23: "RECORD"}
DELETE_SCOPE_COUNTED = {"NEXT", "RECORD"}
DELETE_WHILE_MARK = 0x2B      # WHILE <cond>, its own fc-group
DELETE_NOOPTIMIZE = 0x30      # NOOPTIMIZE, wired in FRONT of the scope word

DROP_LEAD = 0x6A         # DROP TABLE 31 / DROP VIEW c4
SQL_SET_MARK = 0xCA      # the SET mark; the same ca INDEX TAG spends
SQL_WHERE_MARK = 0xC6    # the WHERE mark SELECT-SQL's own WHERE carries
DROP_KINDS = {0x31: "TABLE", 0xC4: "VIEW"}

# r50-leadsweep — the data-command bank. Each verb's clause bytes are the
# estate-wide ones: 28 TO, 15 FROM, 20 ON, 13 FOR, d1 WITH, 11 FIELDS, 14 FORM,
# 2c WINDOW, 06 BAR, d4 TYPE.
EXPORT_LEAD = 0x56       # EXPORT TO <file> [FIELDS <list>] TYPE <word>
# EXPORT's own type bank: the shared APPEND FROM / COPY TO words this
# compiler also accepts here, plus DIF, which r50-leadsweep measured on
# EXPORT alone. It is kept separate from FILE_TYPE_WORDS so no reading can
# hand APPEND FROM a word only EXPORT was measured with — and so the SDF
# row, which VFP9 refuses on EXPORT, cannot leak in from the shared bank.
EXPORT_TYPE_WORDS = {0xC7: "XLS", 0xBB: "XL5", 0xBD: "FOXPLUS",
                     0xBE: "DELIMITED", 0xBF: "DIF"}
DOCK_LEAD = 0xBF         # DOCK WINDOW <w> POSITION <n>
DOCK_POSITION_KW = 0x64  # the POSITION word; the bare-number and AT
                         # forms are refused by this VFP9
ACCEPT_LEAD = 0x05       # ACCEPT ["prompt"] TO <var>
INPUT_LEAD = 0x27        # INPUT  ["prompt"] TO <var>
FIND_LEAD = 0x22         # FIND <literal text>
LABEL_LEAD = 0x2A        # LABEL FORM <name>
IMPORT_LEAD = 0x57       # IMPORT FROM <file> TYPE <word>
JOIN_LEAD = 0x29         # JOIN WITH <alias> TO <file> FOR <cond>
SORT_LEAD = 0x49         # SORT [FIELDS <list>] ON <key>[ /D] TO <file>
TOTAL_LEAD = 0x4E        # TOTAL ON <key> TO <file>
MENU_LEAD = 0x5D         # MENU BAR <array>, <n>
SCROLL_LEAD = 0x60       # SCROLL <r1>, <c1>, <r2>, <c2>, <n>
SIZE_LEAD = 0x89         # SIZE WINDOW <w> TO <rows>, <cols>
PRINTEEE = 0x79          # ??? <expr> — the raw-output sibling of ? and ??
BACKSLASH2_LEAD = 0x8E   # '\\ <text>' — the no-line-feed sibling of 0x8d
FIELDS_MARK = 0x11       # the FIELDS list mark COPY TO and SCATTER carry
ON_MARK = 0x20           # the ON mark INDEX ON / SORT ON / TOTAL ON share
FOR_MARK = 0x13          # the FOR mark LOCATE and SCAN spend
FORM_MARK = 0x14         # the FORM mark REPORT FORM and DO FORM carry
BAR_MARK = 0x06          # the BAR mark DEFINE BAR spends
TYPE_WORD_MARK = 0xD4    # the optional TYPE keyword (r47-typeword)
# REPORT FORM clause bank — ORACLE-MEASURED r69-bank. Flag clauses are a
# bare mark; RANGE / FOR / WHILE / HEADING / NEXT / RECORD / TO FILE /
# OBJECT / NAME carry an operand. ASCII (c3) rides AHEAD of the 28 TO
# mark. PREVIEW immediately followed by TO is a VFP9 syntax error; the
# corpus PREVIEW-then-TO wire is the compiler moving PREVIEW in front of
# a source TO. IN is 16 (PREVIEW IN w and PREVIEW IN WINDOW w share one
# frame); WINDOW without IN is 2c.
REPORT_FILE_KW = 0x12
REPORT_PROMPT_KW = 0x22
REPORT_OBJECT_KW = 0x2E
REPORT_PLAIN = 0x3B
REPORT_NOWAIT = 0x3A
REPORT_NOCONSOLE = 0x39
REPORT_NAME_KW = 0x4A
REPORT_NODIALOG = 0x65
REPORT_OFF = 0x1F
REPORT_PREVIEW = 0xC1
REPORT_ASCII = 0xC3
REPORT_NOEJECT = 0xC4
REPORT_RANGE = 0xC7
REPORT_SUMMARY = 0xCE
REPORT_PDSETUP = 0xD0
REPORT_NOPAGEEJECT = 0xD5
REPORT_NORESET = 0xD6
REPORT_ENVIRONMENT = 0xBD
REPORT_HEADING = 0xBF
REPORT_FLAG_CLAUSES = {
    0xBD: "ENVIRONMENT", 0xC4: "NOEJECT", 0x30: "NOOPTIMIZE",
    0xD0: "PDSETUP", 0x3B: "PLAIN", 0xC1: "PREVIEW", 0x3A: "NOWAIT",
    0xC3: "ASCII", 0x39: "NOCONSOLE", 0xD6: "NORESET",
    0xD5: "NOPAGEEJECT", 0xCE: "SUMMARY", 0x65: "NODIALOG",
    0x1F: "OFF",
}
REPORT_SCOPE_WORDS = {0x03: "ALL", 0x24: "REST", 0x1E: "NEXT",
                      0x23: "RECORD"}
REPORT_SCOPE_COUNTED = {"NEXT", "RECORD"}

TRANSACTION_KW = 0xBD    # r50-leadsweep: the keyword byte BEGIN/END TRANSACTION
                         # spend; VFP has no bare BEGIN or END statement.
PRINTJOB_LEAD = 0x76     # r50-leadsweep: PRINTJOB f9 05 <u16> … ENDPRINTJOB 77
ENDPRINTJOB_LEAD = 0x77
HIDDEN_LEAD = 0x9F   # r50-leadsweep: HIDDEN <prop>[, ...] in class-init —
                     # the same frame PROTECTED's 0xa1 carries.
IMPLEMENTS_LEAD = 0xB9  # r50-leadsweep: IMPLEMENTS <iface> IN <library>,
                     # the library behind the same 0x16 IN mark FOR EACH uses.
# SET's ON/OFF id bank — ORACLE-MEASURED r52-setonoff, one program per SET
# command name across the whole VFP9 namespace, each carrying that name's ON
# line and its OFF line and nothing else. 111 names compiled: 61 produce the
# toggle shape `47 <id> 20` / `47 <id> 1f`, 47 have no ON/OFF form in this
# language at all (VFP9 refuses them, so no artifact can carry one), and three
# — DATE, ENGINEBEHAVIOR, REPORTBEHAVIOR — compile ON and OFF into their own
# value slots instead and are NOT toggles.
#
# The bank is injective across every name, and every id the table already held
# from the landed sweep and the corpus alignments lands on the same byte, which
# is what makes the sweep a bank rather than a list.
#
# COVERAGE 86 and NULLDISPLAY 88 are carried from the landed HARVEST sweep:
# this VFP9 refuses their ON/OFF spelling, so r52-setonoff could not reach
# them, and narrowing an envelope on a form this matrix cannot address would
# be a regression rather than a measurement.
SET_ONOFF_NAMES = {
    0x01: "ALTERNATE", 0x02: "BELL", 0x03: "CARRY", 0x05: "CENTURY",
    0x06: "CLEAR", 0x07: "COLOR", 0x09: "CONFIRM", 0x0A: "CONSOLE",
    0x0C: "DEBUG", 0x0F: "DELETED", 0x10: "DELIMITERS", 0x12: "DOHISTORY",
    0x13: "ECHO", 0x15: "ESCAPE", 0x16: "EXACT", 0x17: "EXCLUSIVE",
    0x18: "FIELDS", 0x1B: "FIXED", 0x1E: "HEADINGS", 0x1F: "HELP",
    0x22: "INTENSITY", 0x26: "MESSAGE", 0x2A: "PRINTER", 0x2E: "SAFETY",
    0x30: "STATUS", 0x31: "STEP", 0x32: "TALK", 0x36: "UNIQUE",
    0x37: "VIEW", 0x3E: "CLOCK", 0x40: "SPACE", 0x41: "COMPATIBLE",
    0x42: "AUTOSAVE", 0x45: "DEVELOPMENT", 0x46: "NEAR", 0x49: "LOCK",
    0x51: "FULLPATH", 0x53: "MOUSE", 0x54: "RESOURCE", 0x57: "LOGERRORS",
    0x58: "STICKY", 0x59: "SYSMENU", 0x5A: "NOTIFY", 0x5B: "BRSTATUS",
    0x5D: "CURSOR", 0x5E: "UDFPARMS", 0x5F: "MULTILOCKS",
    0x60: "TEXTMERGE", 0x61: "OPTIMIZE", 0x64: "ANSI", 0x65: "TRBETWEEN",
    0x68: "KEYCOMP", 0x69: "PALETTE", 0x77: "NULL", 0x7B: "CPDIALOG",
    0x7D: "SECONDS", 0x83: "SYSFORMATS", 0x84: "OLEOBJECT",
    0x85: "ASSERTS", 0x87: "EVENTTRACKING", 0x8F: "AUTOINCERROR",
    0x86: "COVERAGE",                       # landed HARVEST sweep (see above)
    0x88: "NULLDISPLAY",                    # landed HARVEST sweep (see above)
}
# Bare-TO settings: '47 <id> 28' with no operand — ORACLE-MEASURED
# r52-setvalue, one program per SET command name spelling `SET <name> TO` and
# nothing else. 49 names compile to exactly three bytes; the rest either have
# no TO form at all or spend an operand even when the source writes none
# (PATH and TOPIC store an EMPTY fb name, `47 29 28 fb 0000`).
SET_BARE_TO_NAMES = {
    0x01: "ALTERNATE", 0x02: "BELL", 0x03: "CARRY", 0x05: "CENTURY",
    0x07: "COLOR", 0x0D: "DECIMALS", 0x0E: "DEFAULT", 0x12: "DOHISTORY",
    0x18: "FIELDS", 0x1A: "FILTER", 0x1C: "FORMAT", 0x1F: "HELP",
    0x21: "INDEX", 0x26: "MESSAGE", 0x27: "ODOMETER", 0x28: "ORDER",
    0x2A: "PRINTER", 0x2B: "PROCEDURE", 0x2D: "RELATION", 0x38: "CURRENCY",
    0x39: "HOURS", 0x3A: "MARK", 0x3B: "POINT", 0x3C: "SEPARATOR",
    0x3D: "BORDER", 0x3E: "CLOCK", 0x4E: "SKIP", 0x53: "MOUSE",
    0x54: "RESOURCE", 0x59: "SYSMENU", 0x5C: "MACKEY", 0x60: "TEXTMERGE",
    0x62: "LIBRARY", 0x63: "HELPFILTER", 0x66: "PDSETUP",
    0x6D: "NOCPTRANS", 0x79: "KEY", 0x7C: "CPCOMPILE", 0x7E: "CLASSLIB",
    0x7F: "DATABASE", 0x80: "DATASESSION", 0x81: "FDOW", 0x82: "FWEEK",
    0x86: "COVERAGE", 0x87: "EVENTTRACKING", 0x88: "NULLDISPLAY",
    0x89: "EVENTLIST", 0x8A: "DEBUGOUT", 0x91: "TABLEVALIDATE",
}

# ---- SET's value-TO id bank — ORACLE-MEASURED r52-setvalue ------------------
# One program per SET command name for each of three operand spellings: the
# bare `TO`, the `TO zz` unquoted name, and the `TO (m.a)` group. 60 names
# carry a value behind the `28` TO mark, the id space is injective, and every
# name that also has an ON/OFF form lands on the SAME byte in both sweeps —
# the agreement between the two halves is what makes this a bank.
#
# Wire: '47 <id> 28 <operand> [01]' where the operand is one of the three
# spellings dec_set_value reads — an fc..fd group (the 03 runtime-paren
# postfix rides INSIDE it for '(m.x)' values, and fd is reader-stripped when
# statement-final), a BARE fb name, or a bare f7 symbol on the five ids the
# sweep measured it on — and a trailing 01 is ADDITIVE.
#
# Which spelling a name takes is a property of the SETTING: 22 name-valued
# settings store `TO zz` as a bare fb name, 32 expression-valued ones compile
# it to a group, and CARRY / EVENTLIST / FIELDS / NOCPTRANS / SKIP take a bare
# symbol. RELATION is absent on purpose — this VFP9 refuses `SET RELATION TO
# zz` outright (the INTO clause is required), so only its bare TO and its own
# INTO-bearing arm exist. Ids with a dedicated arm earlier in the chain
# (FILTER's IN tail, ORDER's, SYSMENU's pad list, PRINTER's keywords,
# TEXTMERGE's, DATE's word, DATASESSION's) reach this table only for the
# shapes those arms do not claim.
SET_VALUE_TO_NAMES = {
    0x01: "ALTERNATE", 0x02: "BELL", 0x03: "CARRY", 0x05: "CENTURY",
    0x07: "COLOR", 0x0B: "DATE", 0x0D: "DECIMALS", 0x0E: "DEFAULT",
    0x10: "DELIMITERS", 0x12: "DOHISTORY", 0x18: "FIELDS", 0x1A: "FILTER",
    0x1C: "FORMAT", 0x1F: "HELP", 0x21: "INDEX", 0x23: "MARGIN",
    0x24: "MEMOWIDTH", 0x26: "MESSAGE", 0x27: "ODOMETER", 0x28: "ORDER",
    0x29: "PATH", 0x2A: "PRINTER", 0x2B: "PROCEDURE", 0x35: "TYPEAHEAD",
    0x37: "VIEW", 0x38: "CURRENCY", 0x39: "HOURS", 0x3A: "MARK",
    0x3B: "POINT", 0x3C: "SEPARATOR", 0x3D: "BORDER", 0x3E: "CLOCK",
    0x43: "BLOCKSIZE", 0x48: "REFRESH", 0x4D: "REPROCESS", 0x4E: "SKIP",
    0x53: "MOUSE", 0x54: "RESOURCE", 0x55: "TOPIC", 0x59: "SYSMENU",
    0x5C: "MACKEY", 0x60: "TEXTMERGE", 0x62: "LIBRARY", 0x63: "HELPFILTER",
    0x66: "PDSETUP", 0x6B: "COLLATE", 0x6D: "NOCPTRANS", 0x79: "KEY",
    0x7C: "CPCOMPILE", 0x7E: "CLASSLIB", 0x7F: "DATABASE",
    0x80: "DATASESSION", 0x81: "FDOW", 0x82: "FWEEK", 0x86: "COVERAGE",
    0x87: "EVENTTRACKING", 0x88: "NULLDISPLAY", 0x89: "EVENTLIST",
    0x8A: "DEBUGOUT", 0x91: "TABLEVALIDATE",
}
# The five ids whose `TO <name>` operand is a BARE f7 symbol rather than a
# group or an fb name (r52-setvalue). A bare symbol behind any other id was
# never produced by this compiler and stays refused.
SET_SYMBOL_VALUE_IDS = {0x03: "CARRY", 0x18: "FIELDS", 0x4E: "SKIP",
                        0x6D: "NOCPTRANS", 0x89: "EVENTLIST"}

# The 22 ids whose `TO <name>` operand is a BARE fb name (r52-setvalue). For
# every other id in the bank this compiler groups an unquoted operand, so a
# bare fb behind one of them was never produced and stays refused.
SET_NAME_VALUE_IDS = {
    0x01: "ALTERNATE", 0x0B: "DATE", 0x0E: "DEFAULT", 0x12: "DOHISTORY",
    0x1C: "FORMAT", 0x1F: "HELP", 0x21: "INDEX", 0x28: "ORDER",
    0x29: "PATH", 0x2A: "PRINTER", 0x2B: "PROCEDURE", 0x37: "VIEW",
    0x54: "RESOURCE", 0x55: "TOPIC", 0x5C: "MACKEY", 0x60: "TEXTMERGE",
    0x62: "LIBRARY", 0x7E: "CLASSLIB", 0x7F: "DATABASE", 0x86: "COVERAGE",
    0x87: "EVENTTRACKING", 0x8A: "DEBUGOUT",
}

# MACKEY's operand is a macro KEY LABEL, not a value: `SET MACKEY TO (m.a)`
# compiles to '47 5c 28 fc 43 00 …', a chain that is not an expression group,
# and reading it as one emits a line VFP9 recompiles differently. The bare
# name spelling round-trips, so the id keeps its place in the bank and only
# its GROUPED operand stays refused (r52-setvalue, referee-verified).
SET_NAME_ONLY_IDS = frozenset({0x5C})
# ADDITIVE (trailing 01) on PATH/PROCEDURE/LIBRARY/CLASSLIB (r52) and on
# ALTERNATE/PRINTER/COVERAGE (r71-additive). TEXTMERGE TO-file and TO MEMVAR
# also spend it. A trailing 01 behind any other id stays Unsupported.
SET_ADDITIVE_IDS = frozenset({0x01, 0x29, 0x2A, 0x2B, 0x62, 0x7E, 0x86})
SET_ADDITIVE_MARK = 0x01   # clause byte 'ADDITIVE' (CMD_SWEEP: same byte as
                           # RESTORE FROM ADDITIVE)
# SET CLASSLIB clause marks — ORACLE-MEASURED r71-classlib. After the TO
# value(s): 02 is ALIAS (bare symbol or grouped), 16 is IN (bare fb name or
# grouped), 07 joins extra libraries, 01 is ADDITIVE last. Source order is
# IN then ALIAS then ADDITIVE; the wire stores ALIAS ahead of IN.
SET_CLASSLIB_ALIAS_MARK = 0x02
SET_NOSHOW_MARK = 0xCE     # TEXTMERGE ON NOSHOW tail ('47 60 20 ce' x9)

# SET TEXTMERGE (corpus alignment _reportlistener.vcx::htmllistener s0):
#   '47 60 20'          <-> 'SET TEXTMERGE ON'      / 1f OFF
#   '47 60 20 ce'       <-> 'SET TEXTMERGE ON NOSHOW'
#   '47 60 28'          <-> 'SET TEXTMERGE TO'      (bare, closes output)
#   '47 60 28 c2 f5 0d f7 <u16> ce'
#                       <-> 'SET TEXTMERGE TO MEMVAR m.lcResult NOSHOW'
# (c2 = TO-MEMVAR target marker; one carrier, exact byte sequence pinned.)
SET_TEXTMERGE_ID = 0x60
SET_TEXTMERGE_MEMVAR_MARK = 0xC2
# SET TEXTMERGE DELIMITERS TO — ORACLE-MEASURED round-42 I9 (vmlock r42-set):
#   'SET TEXTMERGE DELIMITERS TO'                         -> 47 60 be 07
#   'SET TEXTMERGE DELIMITERS TO m.leftDelim, m.rightDelim'
#       -> 47 60 be fc f5 0d f7 <left> fd 07 fc f5 0d f7 <right>
# be = DELIMITERS in the TEXTMERGE slot (other slots reuse be as DELIMITED/
# LINKED). 07 is ARGJOIN; the reset form is ARGJOIN with no operands. The
# TO word is not on the wire (REPORTBEHAVIOR precedent).
SET_TEXTMERGE_DELIMITERS_MARK = 0xBE

# SET ORDER with work-area clause (foxcharts.vcx::foxcharts s59 stmt46 /
# xfrxlib.vcx s48 stmt15): '47 28 16 f7 <alias> 28 fb "0"' <->
# 'SET ORDER TO 0 IN FRX'; alias slot may be an fc-group. Emission puts the
# value before ' IN <alias>' per the stored spelling.
SET_ORDER_IN_MARK = 0x16
# SET ORDER direction — ORACLE-MEASURED r71-order. A leftover byte behind a
# finished TO-value: 3c is DESCENDING, bd is ASCENDING. Same byte values as
# SEPARATOR's setting id and NOTIFY CURSOR's mark, different slot. TAG is a
# source word that leaves no mark (TO t1 and TO TAG t1 are one frame).
SET_ORDER_DESCENDING_MARK = 0x3C
SET_ORDER_ASCENDING_MARK = 0xBD

# SET's `IN <alias>` tail — ORACLE-MEASURED r52-setin (30 programs). The `16`
# IN mark carries the work area FIRST, before the setting's own value, and the
# alias is a bare f7 symbol, a bare numeric literal, or its own fc..fd group
# taking the 03 runtime-paren postfix exactly when the source parenthesises it.
# What differs per setting is where the 28 TO mark sits:
#   FILTER / KEY spend it in FRONT of the IN mark
#     '47 1a 28 16 f7 <tt>'                 <-> SET FILTER TO IN tt
#     '47 1a 28 16 fc f5 0d f7 <a> 03'      <-> SET FILTER TO IN (m.a)
#     '47 1a 28 16 f9 01 0100'              <-> SET FILTER TO IN 1
#     '47 1a 28 16 f7 <tt> fc <expr>'       <-> SET FILTER TO <expr> IN tt
#     '47 79 28 16 f7 <tt> fc f8 0101'      <-> SET KEY TO 1 IN tt
#   ORDER / RELATION spend it BEHIND the alias
#     '47 28 16 f7 <tt> 28 fb "0"'          <-> SET ORDER TO 0 IN tt
#     '47 2d 16 f7 <tt> 28 fc <e> fd bc f7 <tt>'
#                                    <-> SET RELATION TO <e> INTO tt IN tt
#     '47 2d 16 f7 <tt> 1f bc f7 <tt>'
#                                    <-> SET RELATION OFF INTO tt IN tt
#     '47 2d 01 16 f7 <tt> 28 fc <e> fd bc f7 <tt>'
#                                    <-> SET RELATION TO <e> INTO tt ADDITIVE
#                                       IN tt  (r71-relation: ADDITIVE's 01
#                                       sits ahead of IN; source order of
#                                       ADDITIVE vs IN is one frame)
# The value group's closer is reader-stripped at statement end. INDEX, FIELDS
# and SKIP were measured in the same matrix and this compiler drops their IN
# clause without a trace, so no 16 can reach them.
SET_IN_TAIL_TO_FIRST = {0x1A: "FILTER", 0x79: "KEY"}

# SET PRINTER (excelxml.vcx s10, 3/3 alignment): '47 2a 28 0e' <->
# 'SET PRINTER TO DEFAULT'; '47 2a 28 4a fc <expr>' <-> 'SET PRINTER TO NAME
# (<expr>)'. 0e/4a here are inline keyword markers in the PRINTER slot.
SET_PRINTER_ID = 0x2A
SET_PRINTER_DEFAULT_MARK = 0x0E
SET_PRINTER_NAME_MARK = 0x4A
# r71-small: SET PRINTER ON PROMPT / OFF PROMPT appends DEVICE's PROMPT
# mark 22 behind the ON/OFF toggle (`47 2a 20 22` / `47 2a 1f 22`).
SET_REPROCESS_ID = 0x4D
# r71-small: SET REPROCESS TO AUTOMATIC is `47 4d 28 bc`. SECONDS is a
# trailing d1 behind a numeric TO-value (`47 4d 28 fc <n> fd d1`). AUTOMATIC
# plus SECONDS is the same frame as AUTOMATIC alone.
SET_REPROCESS_AUTOMATIC_MARK = 0xBC
SET_REPROCESS_SECONDS_MARK = 0xD1

# SET REPORTBEHAVIOR (corpus alignment foxchartsbeta/scx carriers + oaasstant,
# 19 stmts): '47 93 fc <expr>' <-> 'SET REPORTBEHAVIOR 80|90' — NO TO marker;
# the value group follows the id directly. r52-setword measured ENGINEBEHAVIOR
# on the same frame under id 90, byte for byte behind the id.
SET_REPORTBEHAVIOR_ID = 0x93
SET_NO_TO_VALUE_IDS = {0x90: "ENGINEBEHAVIOR", 0x93: "REPORTBEHAVIOR"}

# NOTIFY CURSOR sub-keyword (fxmemberdatascript.vcx s22/s23): '47 5a bd 20|1f'
# <-> 'SET NOTIFY CURSOR ON|OFF'; plain NOTIFY ON/OFF keeps the generic path.
SET_NOTIFY_CURSOR_MARK = 0xBD

# SET SYSMENU (r43-sysmenu / r37 E09): setting-id 0x59. Measured forms:
#   47 59 28       SET SYSMENU TO
#   47 59 28 0e    SET SYSMENU TO DEFAULT   (0e is the same DEFAULT keyword as
#                                           SET PRINTER TO DEFAULT)
#   47 59 bc       SET SYSMENU AUTOMATIC
#   47 59 20 / 1f  SET SYSMENU ON / OFF
#   47 59 25       SET SYSMENU SAVE
#   47 59 cd       SET SYSMENU NOSAVE
# TO <pad> / TO <pad>, <pad> is 47 59 28 fc ec <id> [fd 07 fc ec <id> …]
# (r43-sysmenu extra: _MFILE = 0x23, _MEDIT = 0x39). Pad ids are a
# different namespace from MENU_BAR_IDS (0x39 there is _MED_UNDO).
# r49-valsweep: the `@ <row>, <col> …` command. SAY's clause byte and its
# PICTURE byte are the same two BROWSE's :H/:P field attributes use.
# r49-menusweep: the system-menu POPUP ids, compiled one per program under
# `DEFINE BAR n OF <name>`. A name the compiler knows rides `c3 ec <id>`; one
# it does not know (_MFORMAT, _MHELP on this VFP9) stays an ordinary symbol
# operand, which is the control that keeps this table honest. Same `ec` marker
# the DEFINE BAR system-menu BAR ids use, in a different slot and namespace.
MENU_POPUP_IDS = {0x02: "_MSYSMENU", 0x23: "_MFILE", 0x39: "_MEDIT",
                  0x70: "_MPROG", 0x7D: "_MWINDOW", 0x8E: "_MVIEW",
                  0x90: "_MTOOLS"}

# r49-valsweep: EXTERNAL's kind bank, compiled in one matrix. ARRAY (04) and
# CLASS (4f) keep their own arms — an ARRAY names symbols, a CLASS a raw
# payload — and these five share one name operand. LABEL, MENU and QUERY exist
# in the language, are not measured here, and stay refused.
EXTERNAL_NAME_KINDS = {0x12: "FILE", 0x14: "FORM", 0x26: "SCREEN",
                       0x33: "REPORT", 0xBE: "PROCEDURE"}

AT_LEAD = 0x04
AT_SAY_MARK = 0xC4
AT_PICTURE_MARK = 0xC2

SET_SYSMENU_ID = 0x59
SET_SYSMENU_AUTOMATIC_MARK = 0xBC
SET_SYSMENU_SAVE_MARK = 0x25
SET_SYSMENU_NOSAVE_MARK = 0xCD
SET_SYSMENU_PAD_IDS = {
    0x23: "_MFILE",
    0x39: "_MEDIT",
}

# SET's word-valued settings — ORACLE-MEASURED r52-setword. Five settings
# store a WORD where the rest of the namespace stores a toggle or a value:
#   DATE   '47 0b fb <word>'      SET DATE ANSI      (no TO mark at all; a
#                                                     second word leaves no
#                                                     trace, as in ANSI LONG)
#   DEVICE '47 11 28 <kw>'        SET DEVICE TO SCREEN | PRINTER [PROMPT]
#          '47 11 28 12 <name>'   SET DEVICE TO FILE <name>
#   ENGINEBEHAVIOR '47 90 fc <v>' the frame REPORTBEHAVIOR's 93 already carries
#   STATUS '47 30'                SET STATUS TO      (the TO mark is dropped)
#          '47 30 06 20 | 1f'     SET STATUS BAR ON | OFF (06 is the BAR mark)
#   TEXTMERGE DELIMITERS with no TO is the delimiters mark alone, '47 60 be'.
SET_DEVICE_ID = 0x11
SET_DEVICE_WORDS = {0x12: "FILE", 0x21: "PRINTER", 0x26: "SCREEN"}
SET_DEVICE_PROMPT_MARK = 0x22
SET_STATUS_ID = 0x30
SET_STATUS_BAR_MARK = 0x06

# SET DATE setting id: '47 0b 28 fb <str>' <-> stored source
# 'SET DATE TO ANSI LONG' (oaremotionweb.scx::rtx Init). The compiler keeps only the
# first value word as an fb string literal — the trailing LONG leaves NO bytecode trace,
# so canonical emission is 'SET DATE TO <str>' (GO TOP/GOTO TOP precedent).
SET_DATE_ID = 0x0B

# SET SKIP / SET MARK OF BAR — ORACLE-MEASURED (round-37 wave-2 stage w10,
# probes k01/k02/k03 in probes/oracle_harvest/round37_wave2_streams.json,
# conclusions W01/W02/W03):
#   'DEFINE POPUP pp' + 'SET SKIP OF BAR 6 OF pp .T.'
#       -> 47 4e c3 06 fc f8 01 06 fd c3 f7 00 00 fc 61
#   'DEFINE POPUP pp' + 'SET SKIP OF BAR 6 OF pp .F.'
#       -> 47 4e c3 06 fc f8 01 06 fd c3 f7 00 00 fc 2d
#   'DEFINE POPUP pp' + 'SET MARK OF BAR 6 OF pp .T.'
#       -> 47 3a c3 06 fc f8 01 06 fd c3 f7 00 00 fc 61
# c3 = OF, 06 = BAR. The bar number rides its OWN fc..fd expression group, the
# popup name is a bare f7 symbol behind the SECOND OF, and the value rides a
# final fc group whose fd is reader-stripped. The ids are NOT shared with the
# value-TO family: 'SET ORDER TO 1' renders 47 28 28 fb 01 00 31 (probe k04),
# so 4e/3a never reach the SET_VALUE_TO_NAMES path.
SET_OF_BAR_NAMES = {0x4E: "SKIP", 0x3A: "MARK"}
SET_OF_MARK = 0xC3    # 'OF' keyword byte inside the SKIP/MARK clause chain
SET_BAR_MARK = 0x06   # 'BAR' keyword byte behind the first OF
# The four objects the OF chain names — ORACLE-MEASURED r52-setof. BAR names
# its bar with its own fc..fd group and takes an owner behind a second `c3`;
# PAD does the same with a bare symbol; MENU and POPUP take one operand and no
# owner. A system menu rides `ec <id>` in either slot.
SET_OF_OBJECT_WORDS = {0x06: "BAR", 0x1C: "MENU", 0xBC: "PAD", 0xC6: "POPUP"}
# The value slot may carry the source's own TO word as a 28 in front of its
# group — measured on MARK only, both directions, in the SAME method:
#   frxpreview.vcx::frxpreviewform s10 stmt43 '…03 fd 28 fc 2d'
#     <-> stored L270 'set Mark of bar 10 of (m.cShortcut) to .F.'
#   frxpreview.vcx::frxpreviewform s10 stmt49 '…03 fd fc 61'
#     <-> stored L285 'set Skip of bar 10 of (m.cShortCut) .T.'
# 'SET SKIP … TO' is not VFP syntax and occurs zero times corpus-wide, so a 28
# behind id 4e stays refused.
SET_OF_BAR_TO_IDS = frozenset({0x3A})

# SET RELATION ADDITIVE rides a LEADING flag byte between the setting id and
# the TO marker — '47 2d 01 28 …' <-> stored source
# 'SET RELATION TO RECNO(This.linkAlias) INTO (This.LinkAliasEx) ADDITIVE'
# (xfrxlib.vcx::xfcont s66 stmt27). Same byte value as SET_ADDITIVE_MARK but a
# DIFFERENT slot from the value-TO family's trailing 01, so SET_ADDITIVE_IDS
# deliberately does not gain 0x2D.
SET_RELATION_ID = 0x2D
SCAN_LEAD = 0x7E    # 7e [03|13 fc <cond> fd] [f9 05 <u16>] : SCAN [ALL|FOR cond]
                    #   03 = ALL scope ('SCAN ALL' aligned xfrxlib); 13 = FOR clause
ENDSCAN_LEAD = 0x7F # bare ENDSCAN
EMPTY_ARG = 0xDB    # ONE byte per OMITTED call-argument slot inside a 43 group,
                    # position-independent (round-22 oracle-forced, probes/
                    # oracle_harvest/round22_streams.json d2 leading-pair /
                    # d3 middle / d4 trailing vs d1 no-empty control; reproduces
                    # the corpus This.Nodes.Add(,,...) shape while the same
                    # record's four-argument Add carries none). Direct variable
                    # arguments keep their ByVal 00 prefixes around it. Bound
                    # ONLY at 43-group argument positions -- db elsewhere stays
                    # Unsupported (unmeasured context).
TRY_LEAD = 0xBA      # ba f9 05 <u16>: TRY; target = NEXT clause mark - code_base
                     #   (the CATCH prefix when one follows, else the FINALLY
                     #    prefix -- round-35, measured pimutilselect cmdPrint /
                     #    forest FrmSmartSystem -- else the ENDTRY prefix)
CATCH_LEAD = 0xBB    # bb f9 05 <u16>: CATCH; target = next clause mark - code_base
                     #   (FINALLY prefix when one follows, else ENDTRY — measured
                     #    on _reportlistener). Forms: bare | d2 WHEN | 28 TO <var>
                     #    (f7 sym 'CATCH TO err' / f5 0d f7 'CATCH TO m.oError')
ENDTRY_LEAD = 0xBE   # bare ENDTRY
FINALLY_LEAD = 0xBC  # bc f9 05 <u16>: FINALLY clause; target = matching ENDTRY
                     #   prefix - code_base (measured _reportlistener:
                     #   FINALLY@1276 -> ENDTRY@1349)
APPEND_LEAD = 0x06   # 06 <body>: APPEND command (Guineu APPEND=0x06); context
                     # disambiguates from ADD(0x06) operator via statement position.
NODEFAULT_LEAD = 0xAC   # bare NODEFAULT statement (Guineu NODEFAULT=0xAC)
CLASS_INIT_METHOD = 0xA2  # a2 e9 00 <u32le index>: class-init PUBLIC
                          # method registration (r43-class / r43-a3).
CLASS_INIT_PROTECTED = 0xA3  # PROTECTED PROCEDURE/FUNCTION (r43-a3)
CLASS_INIT_HIDDEN = 0x9E     # HIDDEN PROCEDURE/FUNCTION (r43-a3)
                          # Same e9 00 <u32le> envelope as 0xa2. Not a
                          # source line — the member body is its own section.
PROTECTED_LEAD = 0xA1     # a1 f7 <u16>: PROTECTED <prop> in class-init
                          # (r43-class). Assignment is a following 54.

# EXTERNAL command (Guineu CommandTokens EXTERNAL=0x90). Corpus-measured clause
# bytes under this lead, each forced by its own stored source line:
EXTERNAL_LEAD = 0x90
EXTERNAL_CLASS_CLAUSE = 0x4F   # '90 4f fb "…"' <-> 'EXTERNAL CLASS _GDIPLUS.VCX'
                               # (_reportlistener.vcx::fxlistener s0, 1/1).
                               # Also measured but NOT admitted here: 04=ARRAY
                               # (f7-sym list, 5 methods) and be=PROCEDURE (fb name,
                               # 3 methods) — outside this task's four targets.

# OPEN DATABASE (lead 0x95), forced on 7/7 corpus alignments:
#   95 c2 fb <name> [c2]  <->  OPEN DATABASE <name> [SHARED]
# Leading c2 marks the db-name string literal; the TRAILING c2 is present exactly
# when the stored source spells SHARED (MainPara/boxcolor/managecode with it all
# read SHARED; attendanceforcheck/checkmatinput/chartbillprint/temp without it do not).
OPEN_DATABASE_LEAD = 0x95
ODB_NAME_MARK = 0xC2
ODB_SHARED_FLAG = 0xC2

# USE clause bytes (contextual UNDER lead 0x51 — never global tokens):
USE_SHARED_FLAG = 0xC2    # mode-flag slot BEFORE the table name ('USE (e) SHARED …',
                          # _reportlistener.vcx::_reportlistener s36 stmts 25/43)
USE_NOUPDATE_FLAG = 0xBE  # follows SHARED in that slot ('… SHARED NOUPDATE …', same
                          # alignments); byte value is ENDTRY_LEAD elsewhere
USE_ALIAS_MARK = 0x02     # ALIAS clause marker AFTER the name; measured operand is an
                          # f7 symbol ('ALIAS FRX', _reportlistener.vcx::fxlistener s38).
                          # Expression aliases ('ALIAS (JUSTSTEM(…))') exist in the corpus
                          # but are NOT admitted.
# NOTE: bc before the name stays EXCLUSIVE (iter. 36) and the SAME byte after the name
# reads AGAIN — each reading forced by its own stored source line (fxlistener s38:
# 'USE (THIS.CommandClauses.File) AGAIN SHARED NOUPDATE ALIAS FRX').
CALC_LEAD = 0x7D     # 7d 28 <targets> (<sel> 02 [<fc expr fd> [07 …]] 03)*:
                     # CALCULATE <fn>(e)[, …] TO v[, …]. Items and TO targets
                     # both joined by ARGJOIN 07 (round59_calcitems oracle sweep).
CALC_ITEM_GROUP_OPEN = 0x02   # opens one CALCULATE item's argument group
CALC_ITEM_GROUP_CLOSE = 0x03  # closes it; a no-argument item (CNT) is 02 03
# The aggregate-function selector byte under lead 7d, one per function, a
# contiguous bc..c3 block in ALPHABETICAL name order (round59_calcitems sweep:
# every documented CALCULATE function compiled, one item each). CONTEXT-LOCAL to
# lead 7d — bf/c2/c3 carry other meanings under 3c/5e/1b and must never be
# promoted into a global byte map.
CALC_ITEM_FN = {0xBC: "AVG", 0xBD: "CNT", 0xBE: "MAX", 0xBF: "MIN",
                0xC0: "NPV", 0xC1: "STD", 0xC2: "SUM", 0xC3: "VAR"}
# Every CALCULATE clause rides AHEAD of the 28 TO mark, in one fixed frame order
# whatever order the source spelled it (round59_calcclause oracle sweep):
#   16 <operand>   IN            30      NOOPTIMIZE
#   <scope word>   03 ALL / 24 REST bare; 1e NEXT / 23 RECORD + fc <count> fd
#   13 fc <cond> fd   FOR         2b fc <cond> fd   WHILE
# then 28, and `28 04 <lvalue>` is TO ARRAY. CONTEXT-LOCAL to lead 7d: 13/2b/16
# are the FOR/WHILE/IN marks other leads spend, 03/04/24/23/1e/30 are not tokens.
CALC_SCOPE_WORDS = {0x03: "ALL", 0x24: "REST"}          # bare, no operand
CALC_SCOPE_COUNTED = {0x1E: "NEXT", 0x23: "RECORD"}     # word + fc <count> fd
CALC_FOR_MARK = 0x13
CALC_WHILE_MARK = 0x2B
CALC_TO_ARRAY_MARK = 0x04   # 28 04 <lvalue>: TO ARRAY <name>
CALC_NOOPTIMIZE = 0x30
CALC_IN_MARK = 0x16
SUM_LEAD = 0x4B      # 4b 28 <lv> fc <expr>: SUM <field> TO <memvar>
                     # forced by mainmenu1::GrdList 'SUM totalquan TO a'
COUNT_LEAD = 0x12    # 12 28 f7 <sym>: COUNT TO var (TOKEN_REFERENCE §leads);
                     # FOR-clause extension carried by picost::Command5 and
                     # mainmenu20131117::Command8 residuals (lifter SUM handler)
RELEASE_LEAD = 0x3C  # 3c (<lvalue> [07 <lvalue>])*: RELEASE name[, name...] —
                     # forced via certificate.scx multi-name form
# ---- RELEASE clause words (round-33 lane R33-3, corpus-forced on 4 carriers) ---------------------
# CONTEXT-LOCAL to lead RELEASE_LEAD ONLY — bf doubles as a bare group-closer id
# elsewhere (registry BARE_IDS WOUTPUT) and 52 is WAIT_CLEAR as a statement lead;
# never promote these into a global byte->token map. Measured shapes:
#   3c 2c f7 <sym>           RELEASE WINDOW <name>      (stock round-24 m6 arm)
#   3c {2c|bf|52} fc <expr> 03 [fd]
#                            RELEASE WINDOW/LIBRARY/CLASSLIB (<expr>) — the
#                            trailing 03 PAREN postfix rides INSIDE the decoded
#                            group exactly like the SET-value/STORE-name framing.
# Carriers: _webview.vcx::_webbrowser4/_webbrowser3 s0 'RELEASE WINDOW
# (lcFileName2)' <-> 3c2cfcf7010003fd; _webbrowser3 s34 'RELEASE LIBRARY
# (lcFileName)' <-> 3cbffcf7030003fd; xfrxlib.vcx::xfcont s48 'RELEASE CLASSLIB
# (This.XPath+"xfrxlib_"+lcLang+".vcx")' <-> 3c52fcf40100f70700…0603fd.
# DEFINE_WINDOW_KW above already names 2c ("also the WINDOW keyword under leads
# 09/3c"); the other two words land here with their own provenance.
RELEASE_LIBRARY_KW = 0xBF   # LIBRARY clause word under lead 3c only
RELEASE_CLASSLIB_KW = 0x52  # CLASSLIB clause word under lead 3c only
LOCATE_LEAD = 0x2D   # 2d 13 fc <rpn-to-end>: LOCATE FOR <cond> — no closing fd;
                     # RPN runs to stream end (forced across 12 aligned methods).
                     # Variants whose RPN ends mid-operator stay Unsupported.
USE_LEAD = 0x51     # bare USE statement (forced: source 'USE' after TABLEREVERT
                    # sequences); operand forms unforced
SCATTER_LEAD = 0x5E # SCATTER's destination bank, oracle-measured across rounds
                    # 17/28/42/58 (round58_destbank_streams.json). Wire grammar:
                    # 5e [08=BLANK] [1b=MEMO] <destination>, the two modifiers in
                    # a fixed 08-then-1b order that does NOT depend on source
                    # spelling. Destinations: c2 = MEMVAR (SCATTER MEMVAR = 5e c2),
                    # 28 f7 <arr> = TO <array>, 4a <operand> = NAME <object>. So
                    # 5e 1b c2 is MEMO(1b) then MEMVAR(c2) = SCATTER MEMVAR MEMO,
                    # and MEMO/BLANK never stand without a destination (VFP9 rejects
                    # SCATTER MEMO / SCATTER BLANK). Selector bytes are CONTEXTUAL
                    # beneath this lead, never global tokens (bare-67=VAL /
                    # ea-67=SQLDISCONNECT class; HARVEST.md round-17). The TO
                    # selector is the pre-existing TO_MARK — ONE name per byte.
SCATTER_MEMVAR_MARK = 0xC2  # MEMVAR destination under leads 5e/5f (r58-destbank:
                            # SCATTER MEMVAR = 5e c2, GATHER MEMVAR = 5f c2). The
                            # byte collides with USE SHARED / PUTFILE closer /
                            # OPEN-DATABASE marker elsewhere — contextual.
SCATTER_MEMO_MARK = 0x1B    # MEMO modifier under leads 5e/5f, stored BEFORE the
                            # destination (r58-destbank: 5e 1b c2 = SCATTER MEMVAR
                            # MEMO). Collides with ELSE_LEAD / ALIAS closer.
SCATTER_BLANK_MARK = 0x08   # BLANK modifier under lead 5e only, stored before MEMO
                            # (r58-destbank: 5e 08 c2 = SCATTER BLANK MEMVAR).
                            # GATHER rejects BLANK.
SCATTER_NAME_MARK = 0x4A    # NAME <object> destination under leads 5e/5f, the
                            # operand read by _name_operand (round-28 W4)
SCATTER_ADDITIVE_MARK = 0x01  # ADDITIVE on SCATTER's NAME destination and that
                            # destination ONLY (r58-additive: VFP9 rejects it on
                            # TO, on MEMVAR, on both GATHER destinations and with
                            # no destination). It sits directly after the NAME
                            # operand and BEFORE any FIELDS clause:
                            # 5e 4a f7<o> 01 [11 <fields>].
SCATTER_FIELDS_LIKE = 0x18  # LIKE qualifier after the 11 FIELDS mark
                            # (r49-menusweep, re-measured r58-fieldlist)
SCATTER_FIELDS_EXCEPT = 0xBC  # EXCEPT qualifier after the 11 FIELDS mark. Both
                            # qualifiers may appear, LIKE first then EXCEPT:
                            # r58-fieldlist measured 5e c2 11 18 <str> bc <str>
                            # for 'SCATTER FIELDS LIKE a EXCEPT b MEMVAR'.
GATHER_LEAD = 0x5F   # GATHER's destination bank (round17/28/58): 5f [1b=MEMO]
                     # <destination>, destination one of c2 = MEMVAR (GATHER
                     # MEMVAR = 5f c2), 15 f7 <arr> = FROM <array>, 4a <operand>
                     # = NAME <object>. BLANK is a SCATTER-only modifier and does
                     # not compile here.
GATHER_FROM_MARK = 0x15     # FROM clause under lead 5f only (collides with DIM
                            # lead and SQL FROM — contextual, not global)
ERROR_LEAD = 0xA8    # a8 fc <expr> [fd 07 fc <expr>]* : ERROR <expr>[, ...] —
                     # round-18 oracle-measured (probes/oracle_harvest/
                     # round18_streams.json). Every argument but the LAST closes
                     # with fd before the 07 joiner; the final expression runs
                     # UNCLOSED to end of statement (e04/e06). Bare ERROR cannot
                     # compile (e03, compiler rejection). A statement LEAD
                     # identity like 52=WAIT — no selector-level context.
SKIP_LEAD = 0x48     # bare SKIP (71 occurrences, all shape-less)
PUSH_KEY_LEAD = 0x8A # 8a 17 = PUSH KEY — ORACLE-measured (CMD_SWEEP.md row PUSH,
                     # snippet 'PUSH KEY'); CORPUS-ALIGNED at
                     # _reports.vcx::_outputdialog sec24 (ON-KEY save branch).
POP_KEY_LEAD = 0x8B  # 8b 17 = POP KEY — same oracle row pair (snippet 'POP KEY'),
                     # corpus-aligned at the ELSE branch of the same method.
# r42-zapin: PUSH/POP MENU _MSYSMENU = 8a/8b 1c ec 02; _MFILE = 8a 1c ec 23.
# Byte 1c is the MENU keyword under lead 8a/8b (same value as ON_SELECTION_MENU).
PUSH_POP_MENU_IDS = {
    0x02: "_MSYSMENU",
    0x23: "_MFILE",
}
PACK_LEAD = 0x33     # bare PACK — ORACLE-measured (CMD_SWEEP.md row PACK, snippet
                     # 'PACK'); corpus-aligned at systeminfo.scx::frmSysinfo.
COPY_LEAD = 0x11     # 11 [12 <from-str>] 28 <to-str>: COPY [FILE <from>] TO <to>.
                     # Full two-clause form ORACLE-measured (CMD_SWEEP.md row COPY,
                     # snippet 'COPY FILE cpf1.txt TO cpf2.txt'); the TO-only form
                     # is CORPUS-ALIGNED at frmSysinfo ('1128fb03004c5533' ==
                     # stored source 'COPY TO LU3', line 75). Each lead occurs
                     # exactly once in the scored universe — samples of one.
COPY_FILE_MARK = 0x12  # FILE-from clause under lead 11 only (doubles as the GE
                       # comparison in expression space — contextual, not global)
FOR_EACH_LEAD = 0xB5 # b5 <loopvar> 16 <collection> [c2] (f9 05 <u16> |
                     # e9 00 <u32>) = FOR EACH <var> IN <collection>
                     # [FOXOBJECT]. Corpus-forced from the scored pairs
                     # (fxlistener sec2 x2 + _outputdialog sec28) plus the
                     # u32-framed listener.vcx long-jump spelling (round-42 I5).
                     # Tail word == matching ENDEACH prefix - code_base at ALL
                     # occurrences. Loop-var forms: f5 0d f7 <sym> and bare
                     # f7 <sym>; collection is an f4-run path with terminal f7.
ENDEACH_LEAD = 0xB6  # bare ENDEACH sentinel pairing 0xb5; stored sources spell the
                     # loop end both NEXT (fxlistener:63) and ENDFOR
                     # (_outputdialog:310) — identical bytecode.
FOREACH_IN_MARK = 0x16       # IN clause under lead b5 only (the byte doubles as
                             # index operator / USE-IN elsewhere — contextual)
FOREACH_FOXOBJECT_MARK = 0xC2  # FOXOBJECT clause under lead b5 only
SQL_SELECT_LEAD = 0x6F
SQLSEL_ORDER_MARK = (0xC7, 0xC3)
SQLSEL_DESC_MARK = 0x3C
SQLSEL_TOP_MARK = 0x29  # SELECT TOP n: 29 fc <n> [fd] before INTO (r42-seltop).
                        # Collides with GO TOP 0x29; SQL-local.
INSERT_FROM_NAME = 0x4A  # INSERT INTO <t> FROM NAME <obj>: 15 4a <name>
                         # beside the c2 MEMVAR selector (r47-insertforms)
INSERT_BLANK_LEAD = 0x28  # INSERT BLANK is 28 08; BEFORE appends be
INSERT_BLANK_MARK = 0x08
INSERT_BEFORE_MARK = 0xBE
SUSPEND_LEAD = 0x4C      # one-byte SUSPEND (r47-suspend; r42 cmd sweep)
SQLSEL_GROUP_MARK = 0xBF  # SELECT GROUP BY: bf fc <n> fd [07 fc <n> fd]*
SQLSEL_HAVING_MARK = 0xC0  # SELECT HAVING: c0 fc <cond> fd, after GROUP BY
                           # and before ORDER BY (r47-having). The byte is
                           # context-local: under CREATE TABLE it is FREE.
                          # after WHERE, before ORDER BY (r42-selgroup).
                          # Collides with WINDOW()/FLOAT elsewhere; SQL-local.
SQLSEL_AGG_STAR = 0x04    # COUNT(*) operand inside a 43-group (r42-tiera3).
                          # Collides with MUL 0x04; SQL-aggregate-local.
SQLSEL_AGG_DISTINCT = 0xFF  # COUNT(DISTINCT x): ea ff before the operand.
SQLSEL_AGG = {            # ea <id> closer of a SQL aggregate 43-group
    0xFA: "SUM", 0xFB: "AVG", 0xFC: "COUNT", 0xFD: "MIN", 0xFE: "MAX",
}
SQLSEL_JOIN_MARK = 0xD2   # JOIN table follows this byte (r42-tiera3).
SQLSEL_JOIN_INNER = 0xD4  # INNER JOIN and bare JOIN are this byte; LEFT 58, RIGHT 59.
SQLSEL_JOIN_LEFT = 0x58
SQLSEL_JOIN_RIGHT = 0x59
SQLSEL_JOIN_FULL = 0xD3   # FULL JOIN / FULL OUTER JOIN (r74-join). OUTER is not on the wire.
SQLSEL_JOIN_ON = 0x20     # ON <expr> after the joined table/alias, or after a nested JOIN chain.
SQLSEL_FROM_ALIAS = 0x51  # FROM t alias uses the same 51 f7 <u16> as column AS.
SQLSEL_INTOCURSOR_MARK = (0xBC, 0xBD)
SQLSEL_NOFILTER_MARK = 0xCD  # trailing NOFILTER tag, the slot READWRITE (d7) also
                             # occupies; VFP spells them as alternatives on one
                             # INTO CURSOR. Round-40 lane F, oracle-measured and
                             # carried by two stored-source corpus pairs
# The whole trailing tail bank behind a SQL SELECT — ORACLE-MEASURED
# r54-selnointo. NOCONSOLE is 39 and NOWAIT 3a, and the compiler normalises the
# SOURCE order to the wire order NOWAIT-then-NOCONSOLE, so both spellings of
# the pair are ONE frame. The words ride a destination-bearing statement and a
# destination-less one alike. Combinations with READWRITE or NOFILTER have no
# oracle row and are not admitted: the tail is matched whole.
SQLSEL_TAILS = {
    (): (),
    (0xD7,): ("READWRITE",),
    (0xCD,): ("NOFILTER",),
    (0x39,): ("NOCONSOLE",),
    (0x3A,): ("NOWAIT",),
    (0x3A, 0x39): ("NOWAIT", "NOCONSOLE"),
}
# The SQL SUBQUERY operand — ORACLE-MEASURED r54-subquery (20 programs). The
# opcode carries the block's own byte LENGTH, so a reader knows where it ends
# without parsing it: `e8 <u16 n> <n bytes>`. The n bytes are `00` and then a
# SELECT BODY with no 6f lead of its own — the 15 FROM mark, its table in
# either the bare-name or the grouped spelling, and a projection that is c7 for
# the star or the ordinary fc <col> fd column units. Inside the block every
# group closes, because the block's own length ends it rather than the
# statement. What APPLIES the block is an ordinary expression operator behind
# it: an `ea` pair for the SQL-only ones, or a plain comparison byte.
SQL_SUBQUERY = 0xE8
SQL_SUBQUERY_LEAD_BYTE = 0x00   # the block's first byte, fixed in every row
SQL_SUBQUERY_OPS = {0xF8: "IN", 0xF9: "EXISTS"}
# r63-sqlop: ANY/SOME share f6, ALL is f7. They wrap the subquery and a
# comparison byte follows (`id = ANY (SELECT …)` is `e8 … ea f6 10`).
SQL_SUBQUERY_QUANT = {0xF6: "ANY", 0xF7: "ALL"}
C3_ORDER = 0xC3       # ORDER-BY section marker in SQL-SELECT (Guineu-clause consistent)
SQL_UNION_SUBLEAD = 0xC4  # second byte of the UNION-form SQL SELECT (6f c4 …)
SQL_UNION_ALL_MARK = 0x03  # optional ALL after c4; absent is plain UNION (r74-union)
SQL_UNION_LEN_MARK = 0xE8  # then a u24; not a sum-of-names gate (r74-union)
SQL_UNION_CONST = (0x03, 0xE8)  # ALL + length marker; ALL is optional (r74-union)
SQL_DISTINCT_MARK = 0xBE  # SELECT DISTINCT: 6f be 15 … [bc bd INTO]
                          # (r42-seldistinct). Per-arm DISTINCT under UNION
                          # (6f c4) is the same mark. No-INTO DISTINCT is
                          # 6f be 15 … with no bc bd.
REPLACE_LEAD = 0x3E # 3e <lvalue> d1 fc <expr> fd [07 <lvalue> d1 fc <expr> fd]* =
                    # REPLACE f WITH e [,f2 WITH e2...] — forced by aligned sources
                    # (supplycapacity/scx::Text1 'REPLACE DAYQUAN WITH QUAN*RAND*WEEKQUAN'
                    # exercises MUL inside the expr; d1 is the compiled WITH keyword).
                    # A trailing bare 03 after the final pair = ALL clause
                    # (FORCED 9/9 against stored 'REPLACE ... ALL' sources).
REPLACE_WITH = 0xD1
GO_TOP = (0x23, 0x29)   # bare two-byte statement after SELECT — FORCED 27/27
                        # (sources say 'GO TOP' or 'GOTO TOP'; identical bytecode)
GO_BOTTOM_MARK = 0x36   # 23 36 = GO BOTTOM — TOKEN_REFERENCE:73 '23 29/36 GO/GOTO
                        # TOP/BOTTOM'; population alignment: 16/16 paired sources
                        # spell BOTTOM (lane pop-go, 42 carriers order-paired).
GO_IN_CLAUSE = 0x16     # second byte under lead 23 only: GO [TOP|BOTTOM|<expr>]
                        # IN <target>. Context-local reuse — the same byte is an
                        # lvalue opcode in its own namespace. Measured target :=
                        # bare f7 operand | fc <expr> fd; wire order is
                        # [16 <target> [<rec-expr>] [29|36]].
SELECT_WA = 0x46    # 46 f7 <u16 sym>: SELECT <workarea> — forced 198/198 source-aligned;
                    # every dev-sample occurrence is exactly this shape
ELSE_LEAD = 0x1B     # 1b f9 05 <u16>: ELSE frame; u16 = offset(matching ENDIF prefix)
                     #   - (section.offset + 3), i.e. anchored to the post-prologue code
                     #   base — FORCED 139/142; outliers fail verification loudly.
                     # With an ELSE present, the IF's own u16 switches anchors too:
                     #   it points at the ELSE from the SAME code base (103/136; the 32
                     #   counter-cases are IFs that open their section, where both anchors
                     #   coincide). Without an ELSE the IF target stays statement-relative
                     #   (endif.prefix - if.prefix), verified across all cluster conversions.

# Oracle-measured builtin names. These namespaces collide freely and therefore
# remain separate from parsing through emission.
BUILTIN_BARE = {b: n for b, n in _reg.BARE_IDS.items() if isinstance(n, str)}
BUILTIN_ESCAPES = {b: n for b, n in _reg.EA_IDS.items() if isinstance(n, str)}
BUILTIN_X1A = {b: n for b, n in _reg.X1A_IDS.items() if isinstance(n, str)}

# ---- round-22 expr-tail lane (expression layer) ------------------------------------------------
# e1 <id> = system-OBJECT reference opener; intermediate member hops follow as
# f4 <u16> and ONE terminal property read as f7 <u16>.
# Oracle round-21 BOUND (probes/oracle_harvest/round21_findings.json,
# forced_rules[1]): 39=_SCREEN pinned twice (streams e1/e4), 43=_VFP (e2 IF
# frame); corpus 2808efd6bd99b0f1:11 carries e139 f7<caption> inside its
# MESSAGEBOX group. Multi-hop shapes are CORPUS ALIGNMENTS, not oracle rows:
# one hop 'WITH _SCREEN.SYSTEM.Drawing' (foxchartsbeta.vcx::DeltaLegend s1)
# and four hops '_SCREEN.SYSTEM.Drawing.Imaging.ImageFormat.Bmp'
# (chartadjust.scx::CmdSave s0, five aligned statements). Bare sysvar reads
# are NOT e1-encoded (_cliptext -> ed 1d, round-21 REFUTED), so an e1 whose id
# is absent here stays Unsupported rather than guessed. NOTE the namespace is
# disjoint from the generated function registries: registry.BARE_IDS 0x39 =
# ISALPHA, EA_IDS 0x39 = CPCONVERT / 0x43 = COS — no _SCREEN/_VFP identity
# exists there to hand-copy.
SYSTEM_OBJECT_REFS = {0x39: "_SCREEN", 0x43: "_VFP"}
# Bare-bank group closers whose IDENTITY is oracle-measured and already
# generated into registry.BARE_IDS (probes/oracle_harvest/function_ids.json:
# "mdy" -> {"id_kind":"bare","id":"6b"}; neighbour "dmy" -> bare 6a), but whose
# oracle arity sample is empty ("?" there). This table carries ONLY the
# argument-count gate, corpus-mined from 101 statements across 4 records --
# every sighting single-argument -- e.g. 65b24571eb819290:0
# 'CDATE=MDY(m装货日期)' <-> 54f7010010fc43f700006b and its CASE guards
# subst(MDY(..),n,len) = ..43..6bf801..f801..5c. The NAME is read from
# registry.BARE_IDS at point of use, never re-typed here: hand-transcribing
# generated tables is what produced the ALEN defect (tools/gen_registry.py),
# and function_ids.json even holds a SECOND 0x6b ("sqlmoreresults", ea bank).
# Deliberately NOT folded into CORPUS_ALIGNED_BARE_CLOSERS: that set closes
# unconditionally by design, while this one exists to enforce a measured count.
# Round-29 extends the same pattern to the bare ids whose generated ARITY is
# "?" (empty oracle sample) yet whose group-closer use the corpus forces: the
# NAME stays a generated-registry property (read at emission through
# BUILTIN_BARE), the ARGUMENT COUNT below is mined from EVERY sighting across
# the pinned benchmark population (VM-free census over its 293,985 statements;
# per-id stack-depth histograms quoted inline, stored-source alignments cited).
# Namespaces stay explicit: several ids double as statement leads or selectors
# (81 PLAY MACRO / 82 GETEXPR / 90 EXTERNAL ARRAY / b3 DEBUG / bd THROW + ON-
# ESCAPE selector / 1f ENDTEXT) -- ONLY the 43-group closer position changes.
#   0x1F CDOW   9x1      cc1b5d84dd28b6fd:0:2 'lcDay = LOWER(CDOW(m.ldDate))'
#   0x6D KEY    13x1     3010da46f89b39f3:26:38
#   0x81 MLINE  11x2     00ace13ea9056ff4:2:3 'cLine = mline(m.tcEXPR,m.i)'
#   0x82 ORDER  2x1      656ed4d8375e851a:1:16 'm.lcOrder = ORDER("OutputConfig")'
#   0x90 FOPEN  7x1+2x2  3efdcdbd64691fc7:0:6 'mFhn=Fopen(mFile)'; 2-arg edge
#                        94d3be857650beef:1:6
#   0xB3 FSIZE  3x1+1x2  b78003936e7e7b9d:0 stmts 73/75 carry BOTH arities
#   0xBD WEXIST 7x1      2eb7241a95e590b0:27:0 IF WEXIST(JUSTSTEM(...))
# Like MDY above, deliberately NOT folded into CORPUS_ALIGNED_BARE_CLOSERS:
# that set closes unconditionally by design, these enforce a measured count.
# Round-35 extends the pattern to one further registry-named id whose group-
# closer use the corpus forces (r35-impl-lastkey census, evidence lane
# /tmp/foxlift-r35-impl-closers/: VM-free two-pass sweep over ALL 24,394 parsed
# OBJCODE records / 440,531 statements of the public corpus through
# dbf.objcode_records; per-id ARGUMENT-COUNT histograms over every decoder-
# reached closer position, zero losses/drifts/message-shifts/leaks):
#   0x7C LASTKEY  6x0      'IF LASTKEY() != 27' 25fc437cf8021b0ffdf9055b01
#                          (_webview.vcx::_webbrowser4 s1 stmt25,
#                          byte-identical twin _webbrowser3 s1 stmt25);
#                          'IF LASTKEY() = 13' 25fc437cf8020d10fdf9055c00
#                          (_reports.vcx::cmdGetReport s0 stmt3);
#                          'IF LASTKEY() = 27' 25fc437cf8021b10fdf9051400 /
#                          ...f9051700 (ARoMal Combo2 s0; frxpanels objExpr +
#                          edtExpr s0). EVERY sighting zero-argument -> gate
#                          (0,0). WONTOP/RELATION stay OUT of this table: their
#                          lanes produced no dev-population gains and are not
#                          landing here.
# Namespace stays position-resolved exactly as round-29 required: 7C doubles as
# the DECLARE-DLL statement lead (301/301 frozen-benchmark shapes unchanged) and
# its EA-escape twin is SQLROLLBACK -- ONLY the 43-group closer position consults
# this table, and no statement-position path reads it.
# id -> (min args, max args).
MEASURED_LOCAL_GROUP_CLOSERS = {
    0x6B: (1, 1),
    0x53: (0, 2),   # RLOCK — r63-rlock: RLOCK() / RLOCK(alias) /
                    # RLOCK(alias, n) compile (`43 53`, `43 STR 53`,
                    # `43 STR f8 53`); 3 args too-many. NOT RLOCK() is
                    # the 0x0a postfix on the same closer. Registry arity
                    # stays "?"; name from BARE_IDS.
    0x2C: (0, 0),   # ERROR — r73-error: ERROR() compiles (`43 2c`);
                    # ERROR(n) is too-many. ERROR() = n is the 0x10
                    # comparison behind the same closer (`43 2c f8 02 18
                    # 10`, `43 2c f9 04 80 04 10`). Registry arity stays
                    # "?"; name from BARE_IDS.
    0x73: (0, 1),   # POPUPS — r73-popups: POPUPS() / POPUPS(name) compile
                    # (`43 73`, `43 STR 73`); 2 args too-many. NOT POPUPS()
                    # is the 0x0a postfix. Registry arity stays "?"; name
                    # from BARE_IDS.
    0x22: (0, 0),   # COL — r73-col: COL() compiles (`43 22`); COL(n)
                    # too-many. Registry arity stays "?"; name from BARE_IDS.
    0x4C: (0, 0),   # PROW — r73-tail: PROW() compiles (`43 4c`); PROW(n)
                    # too-many. Corpus `43 4c f8 01 01 06` is PROW() + 1.
    0x4B: (0, 0),   # PCOL — r73-tail: PCOL() compiles (`43 4b`); PCOL(n)
                    # too-many. Unmasked when PROW closed.
    0x84: (0, 0),   # PRINTSTATUS — r73-tail: PRINTSTATUS() compiles (`43 84`).
    0x3F: (0, 2),   # LOCK — r73-tail: LOCK() / LOCK(alias) / LOCK(alias, n).
    0x28: (0, 2),   # DISKSPACE — r73-tail: DISKSPACE() / DISKSPACE(vol) /
                    # DISKSPACE(vol, n).
    0x87: (0, 0),   # VARREAD — r73-tail: VARREAD() compiles (`43 87`).
    0x42: (0, 1),   # LUPDATE — r73-tail: LUPDATE() / LUPDATE(alias);
                    # 2 args too-many.
    0x1F: (1, 1),
    0x6D: (0, 3),   # KEY — r63-arity: KEY() / KEY(n) / KEY(n, alias) /
                    # KEY(n, alias, n) compile; 4 args unmeasured.
    0x81: (2, 3),   # MLINE — r63-arity: MLINE(s) too-few; MLINE(s, n) and
                    # MLINE(s, n, start) compile; 4 args too-many.
    0x82: (0, 2),   # ORDER — r63-arity: ORDER() / ORDER(alias) /
                    # ORDER(alias, n) compile; 3 args too-many. The corpus
                    # 0-arg form is ORDER() with an empty 43-group.
    0x90: (1, 2),
    0xB3: (1, 2),
    0xBD: (1, 1),
    0x7C: (0, 0),   # LASTKEY  (round-35 census: 6x zero-arg)
    0xBE: (0, 1),   # WONTOP — the round-35 note above withheld this id for want
                    # of a gain; round-40 lane H measures BOTH arities directly
                    # on the oracle: 'qq = WONTOP()' -> 54f7000010fc43be (f27,
                    # raw-equal to _reports.vcx::_output #10 modulo symbol index)
                    # and 'qq = WONTOP("w1")' -> 54f7000010fc43d902007731be (f28).
                    # Name read from the generated registry at point of use.
    # r49-valsweep: the window-metric quartet, compiled side by side —
    # 'x = WLROW("w")' -> 43 d9…w c9, and WLCOL c8, WROWS b7, WCOLS b6. WLROW
    # and WCOLS already had gates; these two are their neighbours, and only the
    # one-argument spelling is measured.
    0xC8: (1, 1),   # WLCOL
    0xB7: (1, 1),   # WROWS
    0xC0: (0, 1),   # WVISIBLE — r43-class: 'x = WVISIBLE()' -> 43 c0;
                    # 'x = WVISIBLE('trace')' -> 43 fb… c0. Two args unmeasured.
    0x85: (0, 1),   # PROMPT — r43-prompt: 'x = PROMPT()' -> 43 85;
                    # 'x = PROMPT(1)' -> 43 f8 1 85. Statement lead 0x85 is
                    # ENDFOR; expression closer is PROMPT. Two args unmeasured.
    0x9F: (1, 2),   # RELATION — r36 mined (1,1); r63-arity widens: RELATION()
                    # too-few, RELATION(n) and RELATION(n, alias) compile,
                    # 3 args too-many. Name from the generated registry.
    0x9B: (1, 26),  # ALLTRIM — r44-arity compile_dir (vmlock r44-arity):
                    # ALLTRIM() too-few; ALLTRIM(c) through 26 args compile;
                    # 27 args too-many. function_ids.json arity stays "?".
}
if not set(MEASURED_LOCAL_GROUP_CLOSERS) <= BUILTIN_BARE.keys():
    raise AssertionError("local-arity bare closer missing from measured registry")

# Round-42 I4: MESSAGEBOX (ea 0x78) argument count is on the wire.
# Oracle r42-msgbox (probes/oracle_harvest/round42_msgbox_{streams,findings}.json,
# vmlock label "r42-msgbox"):
#   MESSAGEBOX("a")            -> 1 operand before ea78
#   MESSAGEBOX("a", 0)         -> 2
#   MESSAGEBOX("a", 0, "t")    -> 3
#   MESSAGEBOX("a", 0, "t", 5) -> 4  (timeout)
# Discriminator: MESSAGEBOX("a", 0+48+0) is TWO operands (the sum folds to
# f8 04 30, no ADD on the wire) and is NOT MESSAGEBOX("a", 0, "t"). Do not
# invent a type+title concatenation and do not drop an operand the wire has.
# 0+47+1 / 0+48+0 / 0048 as the 3-arg TYPE compile to one integer (f8 04 30);
# emitting the sum would be fabrication. 48 (f8 02 30) is a different spelling.
# id -> (min args, max args). Name stays a generated-registry property.
MEASURED_EA_GROUP_CLOSERS = {
    0x78: (1, 4),
    0x11: (2, 6),  # ASCAN — r44-arity: ASCAN() / ASCAN(a) too-few;
                   # ASCAN(a, e) through six args compile; seven too-many.
                   # function_ids.json arity stays "?".
    0xEC: (1, 2),  # QUARTER — r73-tail: QUARTER(date) / QUARTER(date, n);
                   # QUARTER() too-few. `ea ec`. Bare opcode 0xec is a
                   # different class.
}
if not set(MEASURED_EA_GROUP_CLOSERS) <= BUILTIN_ESCAPES.keys():
    raise AssertionError("ea-arity closer missing from measured registry")

# ---- bare system-variable reads (SYSVAR_READ <u8 id>) ---------------------------------------
# Family shape ORACLE-measured: round 21 emitted '_cliptext' as the two raw bytes
# 'ed 1d' with no e1 prefix (probes/oracle_harvest/round21_streams.json stream e3 =
# '54f7000010fced1d'; rule recorded in round21_findings.json: bare sysvar reads are
# NOT e1-encoded). That round flagged the other ids as an open id space; the first
# corpus answer:
#   0x1D _CLIPTEXT — the round-21 oracle measurement above.
#   0x05 _PAGENO   — corpus alignment: _reportlistener.vcx::
#                    _reportlistener method adjustreportpagesinfo, stmt 8 stores
#                    through '54 f4<THIS> f6<REPORTPAGES> fc m.tiReportIndex fd
#                    07 fc 1 fd 16 10' with value bytes 'ed 05' where the stored
#                    source line reads '... = _PAGENO'.
#   0x20 _TALLY    — corpus alignment, round-30 census: 13 of the 19 carrier
#                    methods mention _TALLY in their full stored sources; unique
#                    carriers mhxpcontrol.vcx combo/extwindow/text hold only
#                    _TALLY. boxcolorbak.scx::CdQuery
#                    stmt#151 '25 fc ed20 f80101 0d fd f905 d616' stores through
#                    stored line 'IF _TALLY<1'; mhxpcontrol text stmt#11
#                    '25fced20f8010010fdf9055301' <-> stored 'IF _TALLY=0'.
#   0x47 _GENHTML  — corpus alignment: single-unbound-token carriers
#                    _internet.vcx::_frx2html/_scx2html/_dbf2html (the
#                    GENHTML.PRG ecosystem variable); all five ed-0x47 carriers
#                    mention GENHTML in their stored source.
#   0x57 _REPORTOUTPUT — corpus alignment: _reportlistener.vcx::gfxoutputclip
#                    stmt#20 '54 f40100 f70300 10 fc ed57' aligns exactly to the
#                    stored line 'THIS.gdiPlusLib = _REPORTOUTPUT'.
# Every other id stays Unsupported until an aligned carrier or a fresh probe names
# it — never guessed from frequency. Round-35 OVERTURNS the r30 withholding of
# 0x32/0x33/0x34 ("candidate spellings ambiguous"): decoder-accurate twin mining
# pinned all three ids simultaneously on stored pairs, zero conflicts population-
# wide (/tmp/foxlift-r35-census/ranking.json sysvar_exclusion_overturn):
#   0x32 _DOS, 0x34 _UNIX, 0x33 _MAC — registry.vcx::registry s13
#                    stmt5 '0c fc ed32 f10300 ed340b f10300 ed330b fd f9059900'
#                    <-> stored line 'CASE _DOS OR _UNIX OR _MAC' (L403): one OR
#                    chain over three reads fixes the id order; 0x33 has no second
#                    spelling to be ambiguous about.
#   corroboration x3: _webview.vcx::_webbrowser3 s3/s4/s5 stmts
#                    '54 f7<lcFileName> 10 fc 43 ed32 …ed340b …' <-> stored L148/
#                    L169/L189 'lcFileName=IIF(_dos OR _unix,UPPER(..),LOWER(..))'.
# Measured effect: converts exactly four blocked methods (65c0636668bf5d53:13 +
# c249ced60e160bd8:3/4/5); whole-population replay of all 10,241 authority keys
# twice with LOST=LEAK=DRIFT=message-shifts=0 (receipt under
# /tmp/foxlift-r35-impl-sysvars/). No other id is claimed by this evidence.
SYSVAR_READ = 0xED
#   0x39 _SCREEN — oracle round-27 s8 (round27_streams.json): 'qq = _SCREEN'
#                  compiles to 'ed 39' — the bare system-OBJECT identity rides the
#                  sysvar-read opcode, disjoint from its e1 path-opener use. The
#                  value must never mirror registry namespaces in the same byte
#                  (BARE_IDS[0x39]=ISALPHA, EA_IDS[0x39]=CPCONVERT; pinned in
#                  tests/test_round27_sysobj.py).
#   0x3E _ASCIICOLS, 0x3F _ASCIIROWS — round-40 lane H oracle probe f29
#   ('_ASCIICOLS = 80' / '_ASCIIROWS = 63' -> 54ed3e10fcf80250 / 54ed3f10fcf8023f),
#   both rows RAW-EQUAL to _reports.vcx::_output #85/#86.
#   0x42 _COVERAGE — round-42 E1 oracle `qq = _COVERAGE`; AATest
#   b3a24153c66ca99a sections 0/1/2 carry the same id.
# r54-sysvars IS the fresh probe those rounds were waiting for. Every documented
# VFP9 system-variable name was compiled as `q = <name>`, 81 programs, none
# refused: 78 names ride `ed <id>` and the ids below are exactly what the oracle
# spelled, every previously-mapped id confirmed unchanged and none contradicted.
# `_MERGE` and `_PDPARMS` compile as ordinary memory-variable reads — VFP9 has no
# such system variables — which is what makes the sweep self-verifying: no row of
# it rests on a compile that failed. The gaps (0x2c-0x2e, 0x4a-0x4c, 0x4f-0x51,
# 0x53) are ids no name in the language reaches and they stay unmapped.
SYSTEM_VARS = {
    0x00: "_ALIGNMENT", 0x01: "_BOX", 0x02: "_INDENT", 0x03: "_LMARGIN",
    0x04: "_PADVANCE", 0x05: "_PAGENO", 0x06: "_PBPAGE", 0x07: "_PCOLNO",
    0x08: "_PCOPIES", 0x09: "_PDRIVER", 0x0A: "_PECODE", 0x0B: "_PEJECT",
    0x0C: "_PEPAGE", 0x0D: "_PFORM", 0x0E: "_PLENGTH", 0x0F: "_PLINENO",
    0x10: "_PLOFFSET", 0x11: "_PPITCH", 0x12: "_PQUALITY", 0x13: "_PSCODE",
    0x14: "_PSPACING", 0x15: "_PWAIT", 0x16: "_RMARGIN", 0x17: "_TABS",
    0x18: "_WRAP", 0x19: "_DBLCLICK", 0x1A: "_CALCVALUE", 0x1B: "_CALCMEM",
    0x1C: "_DIARYDATE", 0x1D: "_CLIPTEXT", 0x1E: "_TEXT", 0x1F: "_PRETEXT",
    0x20: "_TALLY", 0x21: "_CUROBJ", 0x22: "_MLINE", 0x23: "_THROTTLE",
    0x24: "_GENMENU", 0x25: "_GENSCRN", 0x26: "_GENGRAPH", 0x27: "_GENPD",
    0x28: "_PDSETUP", 0x29: "_GENXTAB", 0x2A: "_FOXDOC", 0x2B: "_FOXGRAPH",
    0x2F: "_STARTUP", 0x30: "_TRANSPORT", 0x31: "_BEAUTIFY", 0x32: "_DOS",
    0x33: "_MAC", 0x34: "_UNIX", 0x35: "_WINDOWS", 0x36: "_SPELLCHK",
    0x37: "_SHELL", 0x38: "_ASSIST", 0x39: "_SCREEN", 0x3A: "_BUILDER",
    0x3B: "_CONVERTER", 0x3C: "_WIZARD", 0x3D: "_TRIGGERLEVEL",
    0x3E: "_ASCIICOLS", 0x3F: "_ASCIIROWS", 0x40: "_BROWSER",
    0x41: "_SCCTEXT", 0x42: "_COVERAGE", 0x43: "_VFP", 0x44: "_GALLERY",
    0x45: "_GETEXPR", 0x46: "_INCLUDE", 0x47: "_GENHTML",
    0x48: "_RUNACTIVEDOC", 0x49: "_SAMPLES", 0x4D: "_FOXCODE",
    0x4E: "_FOXTASK", 0x52: "_FOXREF", 0x54: "_TASKPANE",
    0x55: "_REPORTBUILDER", 0x56: "_REPORTPREVIEW", 0x57: "_REPORTOUTPUT",
}
WORKAREA_REF = 0xF5 # f5 <id>: 0D = memory-variable reference (m.<name>, next token MUST
                     # be f7 <sym>; forced 235/235 against stored sources); 01-0A = the
                     # A-J workarea aliases (rare; emitted as the alias letter). Other
                     # ids stay Unsupported.
# Bare ids with corpus-aligned closing behavior. Their oracle arity samples are not complete
# enough to reject calls by argument count, so parser policy remains a set separate from names.
# VAL (0x67) left this set in r44-arity: registry arity "1" is the measured envelope
# (VAL() too-few, VAL(c) compiles, VAL(c, n) too-many). ALLTRIM (0x9B) left for
# MEASURED_LOCAL_GROUP_CLOSERS (1, 26). UPPER (0x66) left: registry arity "1";
# 2-arg stock was ALLTRIM(UPPER(i, arr)) which VFP rejects (r44-g3g4 _reportlistener).
CORPUS_ALIGNED_BARE_CLOSERS = frozenset({
    0x19, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x21, 0x23, 0x24, 0x25, 0x27, 0x29,
    0x2A, 0x2B, 0x2E, 0x2F, 0x30, 0x34, 0x35, 0x36, 0x38, 0x39, 0x3B, 0x3C,
    0x3D, 0x3E, 0x40, 0x44, 0x46, 0x48, 0x4A, 0x4E, 0x4F, 0x51, 0x52, 0x54,
    0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x68,
    0x69, 0x74, 0x75, 0x76, 0x77, 0x7A, 0x7B, 0x83, 0x86, 0x89, 0x8A, 0x8B,
    0x8D, 0x8E, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    0x9D, 0x9E, 0xA1, 0xA2, 0xA5, 0xA7, 0xA8, 0xAA, 0xAB, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB8, 0xBA, 0xBB, 0xC1, 0xC2, 0xC4, 0xCB, 0xCE, 0xD1,
    0xD2,
})
if not CORPUS_ALIGNED_BARE_CLOSERS <= BUILTIN_BARE.keys():
    raise AssertionError("corpus-aligned bare closer missing from measured registry")
def u16(buf, i):
    return struct.unpack_from("<H", buf, i)[0]

def encode_u16(v):
    return struct.pack("<H", v)

# numeric literal encoders — digits byte counts characters of the rendered number incl sign
def encode_int(v):
    s = str(v)
    n = len(s)
    if 0 <= v <= 255:
        return bytes([INT8, n]) + struct.pack("<B", v)
    if -32767 <= v <= 32767:
        # measured negatives stop at -129 on f9; -32768 itself arrived as e9/i32 (f1_lit).
        # The gap -328..-32768-exclusive is UNMEASURED; f9 chosen, roundtrip will police it.
        return bytes([INT16, n]) + struct.pack("<h", v)
    return bytes([INT32, n]) + struct.pack("<i", v)


ARITY = _reg.ARITY


def parse_arity(spec):
    """'M1-2'/'1-3'/'2' -> (lo, hi); None for '?' / missing. The M prefix marks
    that the oracle snippet bound the args through memory-variables; it does not
    change the count constraint."""
    if not spec or spec == "?":
        return None
    s = spec[1:] if spec[:1] == "M" else spec
    if "-" in s:
        lo, hi = s.split("-", 1)
        return int(lo), int(hi)
    v = int(s)
    return v, v


# Bare ids the decoder may act on as group closers: unique measured name AND a
# parseable arity. Ambiguous slots (registry emits lists, e.g. bare 0x19 =
# ABS|ISPEN) stay out -- an unresolved id must surface as Unsupported rather
# than decode as a guessed name (docs/PROCEDURE.md).
DECODER_ENABLED_BARE = frozenset(
    b for b, n in _reg.BARE_IDS.items()
    if isinstance(n, str) and parse_arity(_reg.ARITY.get(("bare", b)))
)
# A later oracle arity measurement for an id already corpus-gated in
# MEASURED_LOCAL_GROUP_CLOSERS must be reconciled explicitly -- never silently
# shadowed by whichever table the closer ladder happens to consult first
# (ALEN-defect class).
if set(MEASURED_LOCAL_GROUP_CLOSERS) & DECODER_ENABLED_BARE:
    raise AssertionError(
        "bare id carries BOTH a registry arity and a local corpus gate: "
        "reconcile MEASURED_LOCAL_GROUP_CLOSERS")
DECODER_ENABLED_EA = frozenset(
    b for b, n in _reg.EA_IDS.items()
    if isinstance(n, str) and parse_arity(_reg.ARITY.get(("ea", b)))
)
if set(MEASURED_EA_GROUP_CLOSERS) & DECODER_ENABLED_EA:
    raise AssertionError(
        "ea id carries BOTH a registry arity and a local corpus gate: "
        "reconcile MEASURED_EA_GROUP_CLOSERS")
DECODER_ENABLED_X1A = frozenset(
    b for b, n in _reg.X1A_IDS.items()
    if isinstance(n, str)
)


# ---- round-40 lane E: popup/menu clause words and the system-menu bar table ----------------------
# Provenance: ORACLE batch `r40-popupmenu e-batch` (probes/oracle_harvest/
# round40_popupmenu_streams.json, 10 programs, one compile_dir under vmlock) plus the
# already-recorded round-37 popup probes (round37_streams.json D1/D4/D5/D6,
# round37_gap_streams.json w_b07-w_b09/w_m01-w_m05/w_r05/v1 d01-d03).
# Every byte below is CONTEXT-LOCAL to its lead — never promote into a global map.
#
# DEFINE POPUP <name> [0d4e COLOR SCHEME <n>] [cf SHADOW] [c8 MARGIN] [16 IN <name>]
#                     [15 FROM <list>] [cc RELATIVE] [57 SHORTCUT]
#   e01 `DEFINE POPUP pq MARGIN IN SCREEN RELATIVE SHORTCUT` -> 73c6f70000c816f70100cc57
#   e09 `DEFINE POPUP pq COLOR SCHEME 4 SHADOW RELATIVE SHORTCUT`
#                                                 -> 73c6f700000d4efcf80104fdcfcc57
#   e10 `DEFINE POPUP pr MARGIN RELATIVE SHORTCUT` -> 73c6f70000c8cc57
#   The FROM list is OPTIONAL (all three above carry none); round-37 D4 pins the full
#   clause set in one statement, and D4 vs e09 together force cf=SHADOW / c8=MARGIN.
POPUP_SHADOW_MARK = 0xCF     # SHADOW flag (D4 + e09; e0adf1d2ad645255:0#0 carrier)
POPUP_MARGIN_MARK = 0xC8     # MARGIN flag (D4 + e01/e10)
POPUP_IN_MARK = 0x16         # IN <name>: 16 f7 <u16>. Byte doubles as GO_IN_CLAUSE
                             # under lead 23 and as ACTIVATE WINDOW's IN under lead
                             # 74 — position under DEFINE_LEAD decides.
#
# DEFINE BAR <n> OF <popup> [22 PROMPT] [41 STYLE] [1d MESSAGE] [17 KEY] [c913 SKIP FOR]
#                           [c2 PICTURE]
#   e02 `… PROMPT "p" MESSAGES "m" STYLE "B"` and e03 `… PROMPT "p" STYLE "B" MESSAGES "m"`
#   compile to the SAME stream (…22 fc"p"fd 41 fc"B"fd 1d fc"m"), so the wire order is
#   canonical and independent of the source order; e04/e05 isolate each clause alone;
#   e11 pins the full order 22 -> 41 -> 1d -> c913 -> c2; e07 shows the KEY text after
#   the comma is OPTIONAL (`KEY CTRL+A` -> 17 fb<key>, no 07 group).
BAR_STYLE_MARK = 0x41        # STYLE fc<expr>fd (e02/e03/e04/e11)
BAR_MESSAGE_MARK = 0x1D      # MESSAGE fc<expr>fd (e05/e11; round-37 w_b09 `MESS ""`)

# DEFINE POPUP's clause list, in the ONE canonical order the wire stores it in
# (r53-popuphead: every permutation of a clause set is the same frame). Round
# 40 read the order off carriers that spelled COLOR SCHEME, SHADOW and MARGIN
# with no FROM list and placed those three in FRONT of one; the wire stores
# them behind it. Each entry is (byte, operand kind, source word):
#   flag   = the byte alone
#   group  = fc <expr> [fd]
#   pair   = two fc groups joined by ARGJOIN (FROM's and TO's coordinates)
#   prompt = 22 <sub-op>: 11 FIELD <expr>, 12 FILES, cc STRUCTURE
#   name   = f7 <u16>, or an fc <expr> 03 paren group
#   scheme = the two-byte WIN_SCHEME_MARK then its group
# KEY `17` is measured (an un-grouped fb literal, somewhere between SHADOW and
# SHORTCUT) but the span could not rank it, so it is deliberately absent.
DEFINE_POPUP_CLAUSES = (
    (DEFINE_FROM_MARK, "pair", "FROM"),
    (0x28, "pair", "TO"),
    (BAR_PROMPT_MARK, "prompt", "PROMPT"),
    (BAR_MESSAGE_MARK, "group", "MESSAGE"),
    (DEFINE_WIN_TITLE, "group", "TITLE"),
    (WIN_SCHEME_MARK[0], "scheme", "COLOR SCHEME"),
    (POPUP_SHADOW_MARK, "flag", "SHADOW"),
    (POPUP_MARGIN_MARK, "flag", "MARGIN"),
    (POPUP_IN_MARK, "name", "IN"),
    (POPUP_RELATIVE_MARK, "flag", "RELATIVE"),
    (0xD5, "flag", "MULTISELECT"),
    (0xC0, "group", "FOOTER"),
    (0xCE, "flag", "SCROLL"),
    (0xBD, "flag", "MOVER"),
    (POPUP_SHORTCUT_MARK, "flag", "SHORTCUT"),
)
BAR_KEY_MARK = 0x17          # KEY fb<key-text> [07 fc<label>fd] (round-37 D6, e07).
                             # Byte doubles as ON_SELECTOR_KEY_LABEL under lead 31.
#
# Popup verbs that ride their own statement leads (round-37 D5 measured the paren-name
# spellings; e06 adds the bare-name ones that the corpus carries).
DEACTIVATE_POPUP_LEAD = 0x75  # 75 c6 f7<sym> (e06; c79070eeff459e07:25#126)
MOVE_POPUP_LEAD = 0x7A        # 7a c6 f7<sym> 28 fc<row>fd 07 fc<col> (e06; …:25#121)
#
# `DEFINE BAR <system-menu constant>` puts the constant in the bar-NUMBER slot as
# `fc ec <id> fd` instead of a numeric literal. The table below is the CURRENT
# (VFP9 SP2) oracle mapping, derived one-to-one from probe source lines and their
# statement streams — see tests/test_round40_popupmenu.py and
# tests/test_round41_waitwin_barids.py, which re-derive it from the recorded JSON so a
# hand-transcription slip cannot survive (ALEN-defect class).
# Names that compiled to ordinary symbol references on this oracle (_MFI_SAVEAS,
# _MFI_PREVIEW, _MFI_PGSETUP, _MFI_PARAFO, _MWI_ARRANGE, _MWI_CYCLE, _MWI_HIDEALL,
# _MWI_MAX) are deliberately absent.
#
# The Edit-menu block was completed in round 41 (probe round41_waitwin_barids_batch.py,
# findings round41_waitwin_barids_findings.json). Round 37 had swept it with
# `_MED_PREFS` and `_MED_REPLACE`, which VFP does not know — its own shipped source
# spells them `_MED_PREF` and `_MED_REPL` — so those two rows measured a misspelling
# compiling to a symbol reference, not the constant, and eleven Edit ids were left
# looking free when they are bound. Candidate names come from a grep of the VFP 9
# install tree for `_M[A-Z][A-Z]_[A-Z0-9]+`, never from memory. No id measured in
# round 41 contradicts a round-37 row; the table only grew.
#
# Round 49 finished it. Rounds 37/40/41/43 each swept whichever menu block that
# round happened to need; round49_barnames_batch.py sweeps all 258 `_Mxx_*` names
# the install-tree grep finds, in the three slots that take one — the bar-NUMBER
# slot, BEFORE/AFTER's neighbour slot and PICTRES — in a single compile. 223 bind;
# a bound name takes the same id in all three slots and distinct names take
# distinct ids. The other 30 are foxpro.h constants and menu PAD names that ride
# along (_MAX_WIDTH, _MSG_ERROR, _MSM_HELP) and compile to ordinary symbol
# operands: the fall-back control that keeps every row a name VFP9 itself binds.
# No id contradicts a round-37/40/41/43 row, and 0x39 — the anchor the historical
# shifted reading below depends on — is still unbound.
MENU_BAR_ID_MARK = 0xEC
MENU_BAR_IDS = {
    0x03: "_MSM_SYSTM",
    0x04: "_MSM_FILE",
    0x05: "_MSM_EDIT",
    0x06: "_MSM_DATA",
    0x07: "_MSM_RECRD",
    0x08: "_MSM_PROG",
    0x09: "_MSM_WINDO",
    0x0A: "_MSM_VIEW",
    0x0B: "_MSM_TOOLS",
    0x0C: "_MSM_FORMAT",
    0x0E: "_MST_OFFICE",
    0x0F: "_MST_HELP",
    0x10: "_MST_HPSCH",
    0x11: "_MST_HPHOW",
    0x12: "_MST_MACRO",
    0x13: "_MST_SP100",
    0x14: "_MST_FILER",
    0x15: "_MST_CALCU",
    0x16: "_MST_DIARY",
    0x17: "_MST_SPECL",
    0x18: "_MST_ASCII",
    0x19: "_MST_CAPTR",
    0x1A: "_MST_PUZZL",
    0x1B: "_MST_SP200",
    0x1C: "_MST_DBASE",
    0x1D: "_MST_SP300",
    0x1E: "_MST_TECHS",
    0x1F: "_MST_ABOUT",
    0x20: "_MST_DOCUM",
    0x21: "_MST_SAMP",
    0x22: "_MST_VFPWEB",
    0x24: "_MFI_NEW",
    0x25: "_MFI_OPEN",
    0x26: "_MFI_CLOSE",
    0x27: "_MFI_CLALL",
    0x28: "_MFI_SP100",
    0x29: "_MFI_SAVE",
    0x2A: "_MFI_SAVAS",
    0x2B: "_MFI_REVRT",
    0x2C: "_MFI_SP200",
    0x2D: "_MFI_SETUP",
    0x2E: "_MFI_PRINT",
    0x2F: "_MFI_SYSPRINT",
    0x30: "_MFI_PRINTONECOPY",
    0x31: "_MFI_SP300",
    0x32: "_MFI_QUIT",
    0x33: "_MFI_PREVU",
    0x34: "_MFI_PGSET",
    0x35: "_MFI_IMPORT",
    0x36: "_MFI_EXPORT",
    0x37: "_MFI_SP400",
    0x38: "_MFI_SEND",
    0x3A: "_MED_UNDO",
    0x3B: "_MED_REDO",
    0x3C: "_MED_SP100",
    0x3D: "_MED_CUT",
    0x3E: "_MED_COPY",
    0x3F: "_MED_PASTE",
    0x40: "_MED_PSTLK",
    0x41: "_MED_CLEAR",
    0x42: "_MED_SP200",
    0x43: "_MED_INSOB",
    0x44: "_MED_OBJ",
    0x45: "_MED_LINK",
    0x46: "_MED_CVTST",
    0x47: "_MED_SP300",
    0x48: "_MED_SLCTA",
    0x49: "_MED_SP400",
    0x4A: "_MED_GOTO",
    0x4B: "_MED_FIND",
    0x4C: "_MED_FINDA",
    0x4D: "_MED_REPL",
    0x4E: "_MED_REPLA",
    0x4F: "_MED_SP500",
    0x50: "_MED_BEAUT",
    0x51: "_MED_PREF",
    0x53: "_MDA_SETUP",
    0x54: "_MDA_BROW",
    0x55: "_MDA_SP100",
    0x56: "_MDA_APPND",
    0x57: "_MDA_COPY",
    0x58: "_MDA_SORT",
    0x59: "_MDA_TOTAL",
    0x5A: "_MDA_SP200",
    0x5B: "_MDA_AVG",
    0x5C: "_MDA_COUNT",
    0x5D: "_MDA_SUM",
    0x5E: "_MDA_CALC",
    0x5F: "_MDA_REPRT",
    0x60: "_MDA_LABEL",
    0x61: "_MDA_SP300",
    0x62: "_MDA_PACK",
    0x63: "_MDA_RINDX",
    0x65: "_MRC_APPND",
    0x66: "_MRC_CHNGE",
    0x67: "_MRC_SP100",
    0x68: "_MRC_GOTO",
    0x69: "_MRC_LOCAT",
    0x6A: "_MRC_CONT",
    0x6B: "_MRC_SEEK",
    0x6C: "_MRC_SP200",
    0x6D: "_MRC_REPL",
    0x6E: "_MRC_DELET",
    0x6F: "_MRC_RECAL",
    0x71: "_MPR_DO",
    0x72: "_MPR_SP100",
    0x73: "_MPR_CANCL",
    0x74: "_MPR_RESUM",
    0x75: "_MPR_SP200",
    0x76: "_MPR_COMPL",
    0x77: "_MPR_GENER",
    0x78: "_MPR_SP300",
    0x79: "_MPR_BEAUT",
    0x7A: "_MPR_DOCUM",
    0x7B: "_MPR_GRAPH",
    0x7C: "_MPR_SUSPEND",
    0x7E: "_MWI_ARRAN",
    0x7F: "_MWI_HIDE",
    0x80: "_MWI_HIDEA",
    0x81: "_MWI_SHOWA",
    0x82: "_MWI_CLEAR",
    0x83: "_MWI_SP100",
    0x84: "_MWI_MOVE",
    0x85: "_MWI_SIZE",
    0x86: "_MWI_ZOOM",
    0x87: "_MWI_MIN",
    0x88: "_MWI_ROTAT",
    0x89: "_MWI_COLOR",
    0x8A: "_MWI_SP200",
    0x8B: "_MWI_CMD",
    0x8C: "_MWI_VIEW",
    0x8D: "_MVI_TOOLB",
    0x91: "_MTL_WZRDS",
    0x92: "_MTL_SP100",
    0x93: "_MTL_SP200",
    0x94: "_MTL_SP300",
    0x95: "_MTL_SP400",
    0x96: "_MTL_OPTNS",
    0x97: "_MTL_BROWSER",
    0x98: "_MTI_FOXCODE",
    0x99: "_MTL_DEBUGGER",
    0x9A: "_MTI_TRACE",
    0x9B: "_MWI_TRACE",
    0x9C: "_MTI_WATCH",
    0x9D: "_MWI_DEBUG",
    0x9E: "_MTI_LOCALS",
    0x9F: "_MTI_DBGOUT",
    0xA0: "_MTI_CALLSTACK",
    0xA4: "_MBR_MODE",
    0xA5: "_MBR_GRID",
    0xA6: "_MBR_LINK",
    0xA7: "_MBR_CPART",
    0xA8: "_MBR_SP100",
    0xA9: "_MBR_FONT",
    0xAA: "_MBR_SZFLD",
    0xAB: "_MBR_MVFLD",
    0xAC: "_MBR_MVPRT",
    0xAD: "_MBR_SP200",
    0xAE: "_MBR_GOTO",
    0xAF: "_MBR_SEEK",
    0xB0: "_MBR_DELET",
    0xB1: "_MBR_APPND",
    0xB7: "_MMB_GOPTS",
    0xB8: "_MMB_MOPTS",
    0xB9: "_MMB_SP100",
    0xBA: "_MMB_PREVU",
    0xBB: "_MMB_SP200",
    0xBC: "_MMB_INSRT",
    0xBD: "_MMB_INSBR",
    0xBE: "_MMB_DELET",
    0xBF: "_MMB_SP300",
    0xC0: "_MMB_QUICK",
    0xC1: "_MMB_GENER",
    0xC4: "_MSM_TEXT",
    0xC6: "_MWZ_TABLE",
    0xC7: "_MWZ_QUERY",
    0xC8: "_MWZ_FORM",
    0xC9: "_MWZ_REPRT",
    0xCA: "_MWZ_LABEL",
    0xCB: "_MWZ_MAIL",
    0xCC: "_MWZ_PIVOT",
    0xCD: "_MWZ_IMPORT",
    0xCE: "_MWZ_FOXDOC",
    0xCF: "_MWZ_UPSIZING",
    0xD0: "_MWZ_ALL",
    0xD2: "_MTB_PROPS",
    0xD3: "_MTB_SP100",
    0xD4: "_MTB_GOTO",
    0xD5: "_MTB_APPND",
    0xD6: "_MTB_DELRC",
    0xD7: "_MTB_SP200",
    0xD8: "_MTB_DELET",
    0xD9: "_MTB_RECAL",
    0xDA: "_MTB_SZFLD",
    0xDB: "_MTB_MVFLD",
    0xDC: "_MTB_MVPRT",
    0xDD: "_MTB_SP300",
    0xDE: "_MTB_LINK",
    0xDF: "_MTB_CPART",
    0xE0: "_MTB_SP400",
    0xE2: "_MFI_SAVEASHTML",
    0xE4: "_MST_MSDNC",
    0xE5: "_MST_MSDNI",
    0xE6: "_MST_MSDNS",
    0xE8: "_MWZ_APPLICATION",
    0xE9: "_MWZ_DATABASE",
    0xEA: "_MWZ_WEBPUBLISHING",
    0xEB: "_MWZ_WEBSERVICES",
    0xED: "_MTL_GALLERY",
    0xEE: "_MTL_COVERAGE",
    0xEF: "_MTI_TASKLIST",
    0xF0: "_MTI_OBJECTBROWSER",
    0xF1: "_MTI_DOCVIEW",
    0xF2: "_MTI_BREAKPOINT",
    0xF4: "_MED_LISTMEMBERS",
    0xF5: "_MED_QUICKINFO",
    0xF6: "_MED_BKMKS",
    0xF8: "_MBK_TOGTASK",
    0xF9: "_MBK_TOGBKMK",
    0xFA: "_MBK_BKMKNEXT",
    0xFB: "_MBK_BKMKPREV",
    0xFD: "_MWI_CASCADE",
    0xFE: "_MWI_DOCKABLE",
}

# Five VFP9-era bars sit in a SECOND bank behind an 0xff escape: the id group is
# `fc ec ff <id> fd` instead of `fc ec <id> fd`. Whether 0xff is an escape byte
# or the high half of a wider field is not measured — only five names ride it,
# and every one of them spells `ec ff <low>`. Kept as its own table so no reading
# can merge the banks and hand a bar the other bank's name.
MENU_BAR_ID_WIDE_MARK = 0xFF
MENU_BAR_IDS_WIDE = {
    0x00: "_MWI_PROPERTIES",
    0x02: "_MMB_MOVEITM",
    0x05: "_MTL_TASKPANE",
    0x06: "_MTL_TOOLBOX",
    0x07: "_MTL_REFERENCES",
}
# One corpus artifact (mhxpcontrol.vcx::edit) was built by an older VFP whose Edit-block
# ids sit exactly one BELOW the current table: its stored source names six bars whose
# wire ids are current-minus-one. The population ec census (round-37 G4) finds seven
# bar-position `73 06 fc ec` frames in the whole dev split — those six plus one current
# _MFI_SP100 — so the shift is that block's, never artifact-wide or table-wide.
# The six names are read off that method's stored source; the id map is DERIVED from the
# current table, never re-typed.
MENU_BAR_SHIFTED_NAMES = ("_MED_UNDO", "_MED_CUT", "_MED_COPY",
                          "_MED_PASTE", "_MED_CLEAR", "_MED_SLCTA")
MENU_BAR_IDS_SHIFTED = {i - 1: n for i, n in MENU_BAR_IDS.items()
                        if n in MENU_BAR_SHIFTED_NAMES}
# Ids whose shifted reading COLLIDES with a live current binding for a different name.
# With the Edit block completed (round 41) that is FIVE of the six: 0x3c current
# _MED_SP100, 0x3d _MED_CUT, 0x3e _MED_COPY, 0x40 _MED_PSTLK, 0x47 _MED_SP300. Only
# 0x39 is genuinely unbound, so it alone anchors the historical reading: those five may
# read shifted only inside a section that also carries 0x39. Before round 41 three of
# them looked free and would have re-bound `_MED_SP100`, `_MED_PSTLK` and `_MED_SP300`
# to Edit commands in ANY artifact — a broad "minus one inside menus" rule is exactly
# the silent re-binding this set exists to prevent.
MENU_BAR_SHIFT_AMBIGUOUS = frozenset(
    i for i in MENU_BAR_IDS_SHIFTED if i in MENU_BAR_IDS)
if set(MENU_BAR_SHIFTED_NAMES) - set(MENU_BAR_IDS.values()):
    raise AssertionError("shifted Edit-block name has no current-table id")
# `ON BAR <n> OF <popup> ACTIVATE POPUP <target>` stores the ACTIVATE action
# structurally rather than as command text: bc c6 f7<u16> (round-37 G1 probe b11
# `ON BAR 1 OF pp ACTIVATE POPUP q` -> 3106fcf80101fdc3f70000bcc6f70100). Any other
# action rides the ordinary fb payload (probe a01). Byte bc is PROPER's bare closer
# and the PAD kind under lead 31 — position inside the ON frame decides.
ON_ACTIVATE_MARK = 0xBC
