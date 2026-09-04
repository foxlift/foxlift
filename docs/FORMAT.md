# The Visual FoxPro compiled-module format

ABOUTME: Byte-level reference for the VFP compiled-module container, as established against a VFP9 oracle.
ABOUTME: Every claim here is measured; anything unverified is marked UNVERIFIED and must not be relied on.

Everything below was established either by compiling controlled sources on the VFP9 oracle
(see [ORACLE.md](ORACLE.md)) or by measuring the corpora. Offsets are hex, integers are
little-endian unless stated.

**Rule for this document: no claim goes in without evidence.** If you infer something, mark it
UNVERIFIED until an oracle probe or a corpus count confirms it. Three format assumptions in the
first implementation looked obviously right and were all wrong (§7).

## 1. Container magic

A compiled module begins with a 4-byte magic. The same magic introduces standalone `.fxp` files
**and** the `OBJCODE` memo of `.scx`/`.vcx` records — one decoder serves both.

| Magic | Count in public corpus | Meaning |
|---|---:|---|
| `fe f2 ff 20` | 24,518 | Normal module. VFP8 and VFP9 both emit this. |
| `fe f2 ff 22` | 16 | Normal module, **u32 section framing** (§3) |
| `fe f2 ff 1f` | 9 | Normal module, older variant |
| `fe f2 ee XX` | 6 files | **Encrypted/compressed APP**, see §8 |

The fourth byte varies and its meaning is UNVERIFIED. It correlates with section framing width
(`22` → u32) but the sample is 16 records, which is not enough to call it causal.

Bytes 4–8 are `02 01 00 00 00` in both VFP8 (a production EXE) and VFP9 (oracle output). Note this
establishes **container** compatibility only. It says nothing about opcode-semantics stability
across versions — do not repeat that inference.

## 2. Header

Immediately after the magic is a block of u32 fields, most of them section offsets and lengths.
The front-header field layout is still not fully mapped — code sections are located by
validation (§3) rather than by reading a length field.

**Class identities are not in that front header.** Oracle r43-fxphdr: DEFINE CLASS name,
AS base, and OLEPUBLIC live in a directory after the last section terminator and its
`55` symbol table (count may be 0):

```
<u16 nlen> <name bytes> <u16 blen> <base bytes> <u16 unk0> <u16 unk1> <u16 ole>
```

Name and base keep the stored source case. `ole` is 1 for `OLEPUBLIC`, 0 otherwise.
`unk0` grows when PROCEDURE/FUNCTION members are added; it is not a simple member
count (PROCEDURE and FUNCTION differ). Method names ride a second directory
immediately before the class-init section: `<u16 nlen> <name> <u32> <u32>`, with
the last u32 overlapping the next section marker. Names include ADD OBJECT
events (`object.event`). Each class-init `a2`/`a3`/`9e` INT32 is a 1-based
index into that list (public / PROTECTED / HIDDEN). A non-class program has
zero class records.

The sections between the start of a class module's body region and its
class-init section are its MEMBERS, one per class-init index, and a member with
an empty body occupies its section exactly like one with a body: `PROCEDURE m1 /
ENDPROC / PROCEDURE m2 / RETURN 1 / ENDPROC` and the same pair with a body in
m1 both compile to four sections with two `a2`. A module with no top-level code
carries one leading empty section of padding, which top-level code replaces when
it is present, and a comment-only body compiles to an empty section. So a
leading empty is padding only in the SURPLUS over the index count (r51-emptymethod). The same `object.event` spelling rides the non-class
procedure directory (`<u16 nlen> <name> <u32> <u16 0> <u16 0xffff>`) of
COMPILE FORM METHODS (commandgroup `cdSave.Click`); a standalone PRG
`PROCEDURE cdSave.Click` is rejected (r44-stmtcount). See
`foxlift.container.class_identities`, `procedure_names`, and
`probes/oracle_harvest/round43_fxphdr_batch.py`.

## 3. Code sections

A module holds one or more code sections. A section is:

```
<marker byte> <length field>   prologue; u16 field normally, u32 in some modules
  <statement>                  statements tile the section exactly
  <statement>
  ...
03 00                          section terminator
```

**The length value N counts marker + statements + terminator — everything except the length
field itself.** Established 2026-08-23 by fresh oracle compiles of 1/2/3-statement programs
(N = 18/33/50 = 3 + Σstmt for 15-byte `? 'one'`-shaped statements) and by `listener.vcx`
`fxabstract` (single 87-byte method, N = 1 + 87 + 2 = 90).

The historical reading — "N counts the marker byte onward, terminator not counted" — produces
identical numbers for u16 fields *by accident*: the field's own 2 bytes cancel the terminator's
2, so the terminator lands exactly at `fc + N`. With a u32 field they do not cancel, which is
why every early attempt to read those sections failed. Operationally:

- u16 field: statements begin at `fc+3`; terminator begins at `fc+N`
- u32 field: statements begin at `fc+5`; terminator begins at `fc+N+2`

The original 16/29/42 measurements are reproduced exactly by the corrected arithmetic
(`3 + 13n` = marker + n thirteen-byte statements + terminator).

**The marker byte is not a constant.** It is `0xFC` in standalone programs and other values
(`0x00` observed) in form and class methods. Do not match on it. Sections are found by scanning
for a candidate whose statements tile exactly up to the computed terminator position, then
confirming `03 00` sits there. Two extra rules prune garbage, both earned from real failures:
a candidate whose statements are ALL unknown-shaped is rejected (`frxbuilder2.vcx`
`panelmultirotate` had such metadata), while a genuinely EMPTY section (prologue + terminator,
zero statements) stays valid.

### u32 framing variant

Some sections use a **5-byte prologue** with a u32 length instead of u16:

```
<marker byte> <u32 N>
```

Confirmed in `ReportingApps/ReportOutput/listener.vcx` object `fxabstract` (magic `fe f2 ff 22`):
length field 90 at `0x5b`, single statement of length 87 at `0x5f`, terminator at `0xb6`
(= fc+N+2). A production single-program EXE's module at `0x5e00` carries the DOMINANT magic
`fe f2 ff 20` yet uses u32 fields throughout (5 sections; its first holds 1,775 statements) —
so the fourth magic byte does **not** select the field width, eliminating the leading hypothesis
for what it encodes. Both widths must be tried at every candidate offset; the narrow reading is
preferred and the wide one accepted when the narrow cannot tile.

## 4. Statements

```
<u16 len> <opcode stream ...> fd fe
```

`len` **includes its own 2 bytes.** A 13-byte statement has 11 bytes of body.

- `fd` — end of expression. Absent in statements with no expression.
- `fe` — end of statement. Always last.

Statement lengths reach at least **8,004 bytes** in real code
(`YiFeiERP/Frms/buyskpiprint.scx`, object `Command2`). Any plausibility cap below 65,535 silently
discards valid methods.

Because every statement declares its own length, a statement whose *shape* is not understood can
be skipped and decoding resumes at the next one. **An unknown construct must cost one statement,
never the module.**

## 5. Verbatim-source statements

Two kinds of line are stored as raw source text instead of compiled, sharing one envelope:

```
<u16 len> <marker> <ascii source text> 0a
```

| Marker | Kind | Evidence |
|---|---|---|
| `01` | Macro-substitution lines (`&var`) — not compiled by design | oracle + corpus; `? &x` → `08 00 \| 01 3f 20 26 78 0a` |
| `b4` | Lines the compiler REJECTED — measured 2026-08-23: a PRG whose SELECT contains a syntax error still emits an `.fxp`; the `.err` records the error and the offending line is stored verbatim | oracle probe + YiFeiERP `mainmenur.scx`, whose shipped source contains literal `????????` runs preserved byte-exactly in OBJCODE while the `.err` echo strips them to spaces |

For the decompiler both are free fidelity: the original bytes return exactly. For the migrator,
`01` lines have no static content to translate, and `b4` lines mark code that never compiled in
the first place — worth surfacing per method rather than silently emitting.

Consequences, which cut opposite ways:

- **For a decompiler this is the easiest construct in the language.** The original source returns
  verbatim, comments included. ReFox cannot do better than verbatim.
- **For a migrator it is the hardest.** There is nothing static to translate, which is the
  argument for an interpreter fallback rather than attempted static translation.

Measured prevalence across the public corpus:

| | |
|---|---|
| Methods containing ≥1 macro statement | **40.9%** |
| Statements that are macros | **3.1%** |

Sparse but pervasive. A tool that cannot handle them fails 41% of methods; a compatibility path
only has to carry 3% of lines.

## 6. Opcodes

The stream is **reverse Polish** — operands precede their operator. `x = y + 2`:

```
54 f7 01 00        STORE → symbol[1]
10 fc              begin expression
   f7 01 00        push symbol[1]   (y)
   f8 01 02        push numeric literal, width 1, value 2
   06              ADD
fd fe              end expression, end statement
```

Hand-verified opcodes:

| Opcode | Meaning |
|---|---|
| `54` | STORE / assignment |
| `f7 <u16>` | symbol reference by index |
| `f4 <u16>` | name/member reference by index (seen in `THIS.member` chains) |
| `f8 <width> <u8>` | numeric literal, 1-byte value |
| `f9 <width> <u16>` | numeric literal, 2-byte value |
| `fb <u16 len> <bytes>` | string literal |
| `af` | LPARAMETERS |
| `fc` / `fd` | begin / end expression |
| `fe` | end statement |
| `06` | ADD |
| `ea <u8>` | escape prefix into the second function range |

`build/coverage.json` holds ~157 more attributed by differential probing, **but that table is not
trustworthy yet** — it contains operand bytes misattributed as opcodes (§7). Treat it as a lead
list, not a reference.
### Folded zero-argument builtin calls collide with int32 literals

Measured 2026-08-23 (`fn_LINENO` roundtrip failure): some parameterless builtins fold at compile
time to their current value, producing an `e9`-framed constant byte-inseparable from a large
int32 literal by opcode alone:

| source | bytecode | reading |
|---|---|---|
| `x = 1000000` | `e9 07 40 42 0f 00` | digits `07` = `len("1000000")`; u32 LE = 1000000 |
| `x = LINENO()` | `e9 0a 01 00 00 00` | digits byte `0a` carries the FUNCTION escape number; u32 = folded line number (1) |

**Corrected 2026-08-26 (round-37 oracle lane, C01/C02 — this supersedes the earlier
"a real literal's digits byte always equals `len(str(value))`" claim, which hex spellings
refute).** The measured digit law for `e9 <D> <u32>` literals is:

| authored spelling | digits byte D |
|---|---|
| plain decimal / trailing-dot decimal (`65536` ≡ `65536.`, byte-for-byte identical wire) | `len(str(value))` |
| unpadded hex (`0x10000` → `06`, `0xFFFF` → `05`) | `hexdigit_count + 1` |
| zero-padded hex (`0x00080000` → `0a`, corpus alignment) | token length incl. `0x` |

Where two readings coincide — exactly when **`hexdigit_count + 1 == len(str(value))`**, which reaches far
beyond the all-nibble examples 15, 255, 4095, 65535 into whole bands such as 10–15, 100–255, 1000–4095,
10000–65535 — the wire cannot distinguish authorship **only when the value itself needs the e9
opcode** (|v| > 32767). **Corrected 2026-09-04 (round 65, r65-hexlit).** r48-intlit and r65-hexlit
compiled hexadecimal and decimal of the same 16-bit values: the opcode is the narrowest that holds
the value (255 and below ride `f8`, 256..32767 ride `f9`, 32768 and above ride `e9`), so a hex
token of a 16-bit value never rides e9 (`0x0000002a` → `f8 0a 2a`, `0x000002c2` → `f9 0a c202`).
A stored `e9 0a <u32>` whose payload fits f8/f9 is therefore not a hex token even though digit
byte `0x0a` is also the zero-padded-hex token length of a ten-character token. It is LINENO():
`x = LINENO()` at line 2 is `e9 0a 02 00 00 00`, and `x = ABS(LINENO())` folds the same way.
Emitting `0x000000NN` for that frame recompiles to f8/f9 (the `e9->f8` / `e9->f9` cluster). The
reader emits `LINENO()`. **Corrected 2026-09-04 (round 67, r67-lineno).** The stored u32 is the
physical line VFP counted, and the form decides which space:

| form | counting base (oracle r67-lineno) |
|---|---|
| `LINENO()` / `LINENO(0)` | 1-based physical lines of the compiled program (a `.prg` file, or a `.scx`/`.vcx` METHODS memo as stored). Comments, blanks, `#DEFINE`, `TEXT` body lines (including empty) count. An `#INCLUDE`d file's lines do not. A `DEFINE CLASS` method in a `.prg` still counts the file, not the method. |
| `LINENO(1)` | 1-based physical lines of the current procedure *body* — `PROCEDURE`/`FUNCTION` excluded, comments and blanks inside the body counted. A later method's first body line stores 1. |

The argument is not on the wire: `LINENO()` and `LINENO(1)` that store the same u32 are the same six bytes. They diverge once the fold is not on line 1 of a one-procedure program. A `;`-continued statement folds to the last physical line of the statement, not the token line (`x = LINENO() + ;` / ` y` stores 3). `LINENO()+LINENO()` and `LINENO()+0` constant-fold; e9 is gone. Hex/decimal of the same small value still ride f8/f9 (r65-hexlit). The `Num` carries the stored line as `lineno`. `lift_program` inserts blank lines before a fold-bearing statement so `LINENO()` occupies the stored program line, or emits `LINENO(1)` and pads inside the procedure when the stored value is body-relative and the program line cannot move back. Reconstruction ahead of the stored line is the named refusal `lineno_reconstruction_ahead`.

### Constant folding is irreversible

| Source | Bytecode | Note |
|---|---|---|
| `x = 3` | `f8 01 03` | width 1, value 3 |
| `x = 1 + 2` | `f8 02 03` | width 2, value 3 — the `1+2` is gone |
| `x = 300` | `f9 03 2c 01` | 2-byte literal, width 3 |

The width byte survives as a fingerprint of the original expression's shape; the expression does
not. This is why naive byte-exact roundtrip cannot be the pass criterion. Whether the width byte
is pure source provenance or carries runtime numeric-type meaning is UNVERIFIED, and it must be
settled by oracle probe before it is ever normalised away.

Also unrecoverable, for ReFox equally: **comments** (absent from bytecode entirely).

## 7. Symbol table

Follows the code section:

```
55 <u16 count>
   <u16 len> <name>
   <u16 len> <name>
   ...
```

Confirmed in `lans.scx`: `55 0a 00` then `08 00 THISFORM`, `03 00 PGF`, `0a 00 ACTIVEPAGE`,
`05 00 PAGE1`, `09 00 CMDEXPORT`, `05 00 CLICK`, …

Symbol indexes in `f7`/`f4` operands index this table. A strict parser now exists
(`container.parse_symbol_table`): it accepts only a clean run of count entries fitting the span.
Context-matrix probing extended the picture: multi-section modules carry **one table after EACH
section terminator**, not only after the last — `container.parse` reads them per-section and
exposes `Section.symbols` alongside the module-wide union. Whether a table ALWAYS follows a
section (as opposed to only when the section references symbols) is UNVERIFIED; parse failure
there is reported, never fatal.

## 8. Encrypted APP files

Six of eleven public `.app` files begin `fe f2 ee XX` and measure **exactly 8.00 bits/byte** —
maximal entropy, so encrypted or strongly compressed, not merely packed. The fourth byte differs
per file (`1c 68 84 cd 34 b9`), consistent with a per-file key or seed.

None of them carry `refox`/`xitech` markers, so this is VFP's own build-time encryption, not
ReFox protection.

All six are third-party **redistributables** (xfrx, FoxyPreviewer, foxcode, frx2any,
ReportBuilder, ReportPreview, AATest) — the population with a motive to obfuscate. Customer
applications are not like this: the two customer production EXEs measured are plain PE at 6.03 and
6.05 bits/byte with readable module magic.

Decrypting these is real work we would want eventually for ReFox parity. It is **not** on the
critical path, and it is explicitly not a feasibility question about module identity.

## 9. The DBF family

`.scx/.sct`, `.vcx/.vct`, `.frx/.frt`, `.mnx/.mnt` are DBF tables with an FPT-style memo
side-file sharing the stem. `foxlift/dbf.py` reads them.

**Memo block numbers are binary little-endian u32 inside the record**, not ASCII digits. Reading
them as ASCII returns zero everywhere and looks like "no memos exist" rather than like an error.

For `.scx`/`.vcx`, the interesting fields are:

- `METHODS` — the original source text
- `OBJCODE` — its compiled bytecode, a module in the §1 format

**24,541 records carry both**, pre-aligned. That is the gold standard for scoring, and it needs no
ReFox to produce.

`.frx` declares `OBJCODE` as numeric `N(3)`, not a memo — reports do not carry bytecode this way,
so `objcode_records()` correctly yields nothing for them. Report expressions live in other fields.

A `METHODS` memo may hold **several procedures**, while `OBJCODE` may omit code for empty ones. So
the 24,541 pairs are **record-aligned, not method-aligned** — the method directory has to be
decoded before they can supervise anything at statement granularity.

## 10. What is not known

Listed so nobody assumes these are settled:

- The header layout (§2), which is why section-finding is a search.
- The meaning of the fourth magic byte, and the authoritative u16/u32 framing selector.
- The method directory — how method names bind to sections.
- Operand lengths and types for most opcodes; the current table has operands in it.
- Whether the folded-constant width byte is runtime-relevant.
- The outer EXE/APP container: how modules and resources are enumerated. Raw magic scanning is
  **not** this — in one production EXE the hit at `0x38cc` is an embedded DBF header (`PLATFOR` appears
  at `+0x49`), not a module.
- VFP8 opcode semantics. Matching container header bytes does not establish it.

## 11. The project tables (.pjx/.pjt) and MAINPROG

A .pjx is a DBF table whose companion .pjt acts as its memo stream with BLOCK SIZE 1:
memo pointers are byte offsets into the .pjt, each entry being
[u32 marker=1][u32 len][bytes]. Measured against fb2p_test.pjx/pjt and
proj1.pjx/PJT.

Record length 130, header length 1192 (includes zero padding after the field
terminator). Fields, in order: NAME M, TYPE C(1), ID N(10), TIMESTAMP N(10),
OUTFILE M, HOMEDIR M, EXCLUDE L, MAINPROG L, SAVECODE L, DEBUG L, ENCRYPT L,
NOLOGO L, CMNTSTYLE N(1), OBJREV N(5), DEVINFO M, SYMBOLS M, OBJECT M, CKVAL
N(6), CPID N(5), OSTYPE C(4), OSCREATOR C(4), COMMENTS M, RESERVED1/2 M,
SCCDATA M, LOCAL L, KEY C(32), USER M.

TYPE codes measured against authored ground truth (KEY fields of real
projects): H = project-header pseudo-record (always record 0), d = database
(.dbc), K = form (.scx), P = program (.prg), R = report (.frx), V = classlib
(.vcx), x = image resource, T = text/config file.

**MAINPROG is a plain logical column** (T/F bytes). Setting it on one record -
no UI involved - designates the build entry point, which is what makes a
generated project buildable headlessly via BUILD APP ... FROM ... RECOMPILE.
This is load-bearing for phases 5 and 6: generated projects must emit exactly
one MAINPROG=.T. row.

**TIMESTAMP N(10) is a DOS-packed local datetime**
`((yy-1980)<<25 | mm<<21 | dd<<16 | hh<<11 | mi<<5 | ss/2)` with even
seconds. A member whose TIMESTAMP matches its source file mtime is fresh:
BUILD APP skips that compile. Measured 2026-08-29 against builder bytes:
1562204634 = 11:14:52; 1562206208 = 12:00:00. The builder's own TIMESTAMP
for a given mtime is the value to write — a naive pack of 12:00:00 was
1562206208, the builder wrote 1562206209 for the same guest LastWriteTime.

Reader/writer: foxlift/pjx.py (schema as data in _FIELDS); round-trip tests
against fb2p_test.pjx in tests/test_pjx.py.