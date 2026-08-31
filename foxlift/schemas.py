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
# 53 16 f7 <u16> (AATest frstestharn s5[0] 5316f70000).
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
TEXT_FLAG_PRETEXT = 0xC3     # round-37 C07/J1: third in the fixed order 60 -> ce -> c3,
                             # followed by its numeric argument as fc f8 <digits> <u8>
                             # ('PRETEXT 2' = fc f8 01 02); corpus twins aatest.scx
                             # 'PRETEXT 14' = fc f8 02 0e, sstextbox.scx '{NOSHOW}
                             # PRETEXT 1' = fc f8 01 01
# 0xFB inside a TEXT frame = one verbatim body line, fb <u16 len excluding newline>
# <bytes>; reuse of the STR literal token, context-local to the frame.
AS_CLAUSE_MARK = 0x51        # WITH ... AS <class> (round-23 w3; class uppercased on the
                             # wire) AND typed-LOCAL '<name> AS <type>' (same byte; also
                             # SQL alias / DECLARE alias slots elsewhere)
LOCAL_OF_MARK = 0xC3         # typed-LOCAL 'AS <type> OF <library>' (chartadjust.scx::
                             # Command3 stmt0, OF "..\class\FoxCharts.Vcx"; corpus
                             # alignment -- round-23 logged it as corroboration only,
                             # confirmed against the pair's own bytes+source)
RETURN = 0x42      # 42 [fc expr fd]                              (f7_cal)
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
# SET setting names — Guineu SetToken enum, restricted to settings whose ON/OFF
# form is valid VFP (numeric/TO-valued settings stay Unsupported until forced).
# Landed oracle id-space sweep (HARVEST.md "SET-command id space — MEASURED,
# 43/43 forms") adds CONFIRM 09 / CONSOLE 0a / FIXED 1b / MULTILOCKS 5f.
# COMPATIBLE 41 and ASSERTS 85 are CORPUS ALIGNMENTS, not rows of that sweep:
#   41 <-> 'SET COMPATIBLE OFF'/'SET COMPATIBLE ON' (oaasstant.scx::Form1 s6 —
#          statements [1]/[2] sit exactly on those two source lines — and
#          vfp_skins.vcx::sysmenupop, whose only SET lines are COMPATIBLE);
#   85 <-> 'SET ASSERTS ON' (foxcharts.vcx::foxcharts s48, 2/2).
# TEXTMERGE 60 is a CORPUS ALIGNMENT too: 'SET TEXTMERGE ON'/'OFF' are the ONLY
# SET lines of 0d6f165ca4ec5020/1e14aeb167c60c8b/49a46e7871d5025f, which fail
# exactly on '47 60 1f'/'47 60 20' (plus the ON-NOSHOW/TO-MEMVAR forms below).
SET_ONOFF_NAMES = {
    0x02: "BELL",       0x09: "CONFIRM",     0x0A: "CONSOLE",     # landed sweep
    0x0F: "DELETED",     0x15: "ESCAPE",     # ESCAPE corpus-aligned
    0x16: "EXACT",      0x17: "EXCLUSIVE",   0x1B: "FIXED",
    0x2E: "SAFETY",
    0x30: "STATUS",     0x31: "STEP",        0x32: "TALK",
    0x41: "COMPATIBLE",                      # corpus alignment (see above)
    0x54: "RESOURCE",                        # HARVEST 43/43; r42 I9 ON/OFF
    0x5A: "NOTIFY",     0x5F: "MULTILOCKS",
    0x60: "TEXTMERGE",                       # corpus alignment (see above)
    0x83: "SYSFORMATS",  0x85: "ASSERTS",    # ASSERTS corpus-aligned (see above)
    0x86: "COVERAGE",
    0x88: "NULLDISPLAY",
}
# Bare-TO settings: '47 <id> 28' with no operand. FILTER/PROCEDURE aligned in iter. 29;
# 0x05 CENTURY bare-TO aligned to stored source 'SET CENTURY TO'
# (oaremotionweb.scx::rtx Init, 1/1; its ON/OFF forms were already measured).
# DECIMALS 0d bare-TO: '47 0d 28' <-> stored source 'SET DECIMALS TO'
# (5 methods incl. corpus .scx forms, e.g. 10e6d810ae3b4e19:0 stmt0) — the
# VALUE form of the same id keeps its own round-25 branch below. INDEX 21
# bare-TO: landed sweep identity (INDEX 21), observed '47 21 28' x2
# (foxcharts.vcx::foxcharts s82 twin pair). MESSAGE 26 / ORDER 28 / KEY 79 /
# DEBUGOUT 8a bare-TO: corpus-aligned ids (provenance at SET_VALUE_TO_NAMES)
# whose bare spellings are measured ('SET MESSAGE TO', 'SET ORDER TO',
# 'SET KEY TO', 'SET DEBUGOUT TO'); TEXTMERGE 60 bare-TO likewise.
# RELATION 2d bare-TO: '47 2d 28' <-> stored source 'SET RELATION TO'
# (xfrxlib.vcx::xfcont s66 stmt30, the relation-clearing form); the id itself is
# already measured by the INTO-bearing SET RELATION arm on its own carrier.
SET_BARE_TO_NAMES = {0x1A: "FILTER", 0x2B: "PROCEDURE", 0x05: "CENTURY",
                     0x0D: "DECIMALS", 0x21: "INDEX", 0x26: "MESSAGE",
                     0x28: "ORDER", 0x2D: "RELATION", 0x60: "TEXTMERGE",
                     0x79: "KEY", 0x8A: "DEBUGOUT"}

# ---- SET value-form grammar (population lane SET, offline-forced) ------------
# Measured wire: '47 <id> 28 fc <expr> [03] [fd] [01]' where the trailing
# runtime-paren marker 03 is the PAREN postfix INSIDE the value group
# ('(m.x)' values), fd is reader-stripped when statement-final, and 01 =
# ADDITIVE. Anchor: vfp_skins.vcx::sysmenupop s0 stmt10
#   '47 7e 28 fc f4 02 00 f7 06 00 03 fd 01'
#   <-> 'SET CLASSLIB TO (THIS.CLASSLIBRARY) ADDITIVE'.
# Ids from the LANDED oracle sweep: DEFAULT 0e · ORDER 28 · PATH 29 ·
# PROCEDURE 2b · POINT 3b · LIBRARY 62 (+ADDITIVE per HARVEST.md) · BELL 02.
# Ids from CORPUS ALIGNMENT (bytecode vs own stored METHODS): CLASSLIB 7e
# (vfp_skins/foxchartsbeta/excelxml et al.), MEMOWIDTH 24 ('SET MEMOWIDTH TO
# 1024', oaasstant.scx::Form1 s6 stmt5 — value int16 1024), MESSAGE 26
# ('SET MESSAGE TO …' x10 carriers incl. GBK prompt strings and bare TO),
# DEBUGOUT 8a ('SET DEBUGOUT TO "Debug.txt"' / bare TO, excelxml.vcx s17/s109).
SET_VALUE_TO_NAMES = {
    0x02: "BELL",       0x0E: "DEFAULT",     0x1A: "FILTER",
    0x24: "MEMOWIDTH",  0x26: "MESSAGE",     0x28: "ORDER",
    0x29: "PATH",       0x2B: "PROCEDURE",   0x3B: "POINT",
    0x54: "RESOURCE",   # r42-setres: 47 54 28 fc <expr> [03]; ON/OFF is 47 54 1f/20
    0x62: "LIBRARY",    0x79: "KEY",         0x7E: "CLASSLIB",
    0x8A: "DEBUGOUT",
}
# ADDITIVE (trailing 01) measured ONLY on these ids: PATH/PROCEDURE/LIBRARY/
# CLASSLIB ('SET PATH TO … ADDITIVE', 'SET PROCEDURE TO xfrx ADDITIVE',
# HARVEST.md 'ADDITIVE appends trailing 01'). A trailing 01 behind any other
# id stays Unsupported. KEY value form: 'SET KEY TO (lii+1)' xfrxlib s15.
SET_ADDITIVE_IDS = frozenset({0x29, 0x2B, 0x62, 0x7E})
SET_ADDITIVE_MARK = 0x01   # clause byte 'ADDITIVE' (CMD_SWEEP: same byte as
                           # RESTORE FROM ADDITIVE)
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

# SET PRINTER (excelxml.vcx s10, 3/3 alignment): '47 2a 28 0e' <->
# 'SET PRINTER TO DEFAULT'; '47 2a 28 4a fc <expr>' <-> 'SET PRINTER TO NAME
# (<expr>)'. 0e/4a here are inline keyword markers in the PRINTER slot.
SET_PRINTER_ID = 0x2A
SET_PRINTER_DEFAULT_MARK = 0x0E
SET_PRINTER_NAME_MARK = 0x4A

# SET REPORTBEHAVIOR (corpus alignment foxchartsbeta/scx carriers + oaasstant,
# 19 stmts): '47 93 fc <expr>' <-> 'SET REPORTBEHAVIOR 80|90' — NO TO marker;
# the value group follows the id directly.
SET_REPORTBEHAVIOR_ID = 0x93

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
SCATTER_LEAD = 0x5E # round-17 oracle-measured forms (probes/oracle_harvest/
                    # round17_streams.json): 5e 28 f7 <arr> = SCATTER TO <array>;
                    # 5e 1b c2 = SCATTER MEMVAR MEMO. Round-42 I8 exact-length
                    # extras (round42_scatter_streams.json): 5e 1b 4a f7 <sym>
                    # = SCATTER MEMO NAME <bare>; 5e 08 1b 4a f7 <sym> =
                    # SCATTER MEMO BLANK NAME <bare>. Every other 5e shape stays
                    # Unsupported. Selector bytes are CONTEXTUAL beneath this lead,
                    # never global tokens (the bare-67=VAL / ea-67=SQLDISCONNECT
                    # collision class; HARVEST.md round-17). The TO selector byte is
                    # the pre-existing TO_MARK — ONE name per byte on this path.
SCATTER_MEMVAR_MARK = 0x1B  # MEMVAR clause under leads 5e/5f context
                            # (collides with ELSE_LEAD / ALIAS closer elsewhere)
SCATTER_MEMO_MARK = 0xC2    # MEMO clause under lead 5e context (collides with
                            # USE SHARED / PUTFILE closer / OPEN-DATABASE marker)
GATHER_LEAD = 0x5F   # sole round-17-measured form: 5f 15 f7 <arr> = GATHER FROM
                     # <array>; any other 5f shape stays Unsupported.
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
SQLSEL_JOIN_ON = 0x20     # ON <expr> after the joined table/alias.
SQLSEL_FROM_ALIAS = 0x51  # FROM t alias uses the same 51 f7 <u16> as column AS.
SQLSEL_INTOCURSOR_MARK = (0xBC, 0xBD)
SQLSEL_NOFILTER_MARK = 0xCD  # trailing NOFILTER tag, the slot READWRITE (d7) also
                             # occupies; VFP spells them as alternatives on one
                             # INTO CURSOR. Round-40 lane F, oracle-measured and
                             # carried by two stored-source corpus pairs
C3_ORDER = 0xC3       # ORDER-BY section marker in SQL-SELECT (Guineu-clause consistent)
SQL_UNION_SUBLEAD = 0xC4  # second byte of the UNION-form SQL SELECT (6f c4 ...);
                          # measured on 5 corpus statements, every source a
                          # UNION ALL of two arms emitted in reverse order
SQL_UNION_CONST = (0x03, 0xE8)  # fixed u16 pair following the c4 sublead in all
                          # 5 measured instances; meaning unmeasured — opaque
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
    0x1F: (1, 1),
    0x6D: (1, 1),
    0x81: (2, 2),
    0x82: (1, 1),
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
    0x9F: (1, 1),   # r36-sim V-CLOSER-9F: RELATION — oracle id
                    # function_ids.json relation=bare 9f (arity "?"); corpus
                    # argument histogram {1:2} over decoder-reached closer
                    # positions (/tmp/foxlift-r35-impl-closers census), both
                    # sightings stored-source aligned. Name read from the
                    # generated registry at point of use.
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
SYSTEM_VARS = {
    0x05: "_PAGENO",
    0x1D: "_CLIPTEXT",
    0x20: "_TALLY",
    0x32: "_DOS",
    0x33: "_MAC",
    0x34: "_UNIX",
    0x39: "_SCREEN",
    0x47: "_GENHTML",
    0x57: "_REPORTOUTPUT",
    #   0x3E _ASCIICOLS, 0x3F _ASCIIROWS — round-40 lane H oracle probe f29
    #   ('_ASCIICOLS = 80' / '_ASCIIROWS = 63' -> 54ed3e10fcf80250 /
    #   54ed3f10fcf8023f), both rows RAW-EQUAL to _reports.vcx::_output #85/#86.
    #   The same probe also emitted _PADVANCE = ed 04; that id is recorded in
    #   the streams file but stays UNBOUND — no carrier needs it here.
    0x3E: "_ASCIICOLS",
    0x3F: "_ASCIIROWS",
    # round-42 E1: oracle `qq = _COVERAGE` -> ed 42; AATest b3a24153c66ca99a
    # sections 0/1/2 carry the same id (probes/oracle_harvest/round42_where03_*).
    0x42: "_COVERAGE",
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
