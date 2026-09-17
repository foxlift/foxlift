# Changelog

FoxLift uses Semantic Versioning. Release tags use `vX.Y.Z` and must match the version in
`pyproject.toml`.

## 0.7.0 — 2026-09-17

Wave 4 on the development split of the second corpus, seals still shut.
Fifty-two refusal classes closed one at a time; this is not a wave close
and the held-out splits were not reopened.

- Development split of the second corpus: 103,317 of 103,363 sections
  lift with zero leaked bytes (0.6.0: 103,015). Blocked sections on the
  lift census fell from 348 to 46; the per-record blockers census reads
  45 sections in 40 classes over 42 records (0.6.0: 348 in 92 over 257).
  Compiled programs 5,296 of 5,476 (0.6.0: 5,266). Not one repository
  regressed.
- Authored population 1,876 of 1,917 equal, 0 regressed by name against
  every frozen checkpoint. Member conservation holds on both corpora
  with zero no-trace members; named refusals on the second corpus fell
  from 474 at the wave-3 close to 156.
- First-corpus pins unmoved: 10,514 of 10,514 development method
  sections, 2,007 of 2,007 validation, 1,971 system.app CLI, 522 writer
  fence. Four named refusals remain on corpus 1.
- Statement banks measured and read: PACK MEMO; ALTER TABLE DROP COLUMN
  with a bare column slot; SHOW WINDOW ALL and the modifier-before-IN
  form; DEFINE POPUP FONT and quoted IN; CLOSE DEBUGGER; ON SELECTION
  and ON BAR; CREATE DATABASE, CREATE FORM and CREATE CLASS; COMPILE
  FORM; APPEND FROM CSV and APPEND GENERAL; REPLACE WHILE/REST/NEXT/
  ADDITIVE; ACTIVATE WINDOW TOP/BOTTOM/NOSHOW; WAIT WINDOW TO; @ CLEAR
  and @ COLOR; DOCK NAME; LOCATE RECORD n; DO CASE OTHERWISE with no
  CASE; DOEVENTS FORCE; multiple CATCH in one TRY; SAVE TO / RESTORE
  FROM MEMO; MOVE; MOUSE modifier flags; INSERT INTO FROM ARRAY.
- Expression and SQL residue: the unterminated 43-group, array-element
  property tails, IIF/MAX close, SQL HAVING SUM, and FROM/JOIN table
  atoms.
- Sealed splits were not opened. Held-out figures in 0.6.0 (1,023 of
  1,030 on corpus 1, 13,845 of 13,978 on corpus 2) are still the last
  sealed readings. The wave-4 close is what re-measures them.

## 0.6.0 — 2026-09-12

The wave-3 close: five decoder lanes measured together on one tree, both sealed
splits opened once, and the blocked surface cut by a further 38%.

- Wave 3 measured whole. Development split of the second corpus: 103,015 of
  103,363 sections lift with zero leaked bytes (0.5.0: 102,798), and blocked
  sections fell from 565 to 348 across 92 refusal classes in 257 records
  (0.5.0: 106 classes, 406 records). Compiled programs 5,266 of 5,476. Not one
  repository regressed; every one gained or held.
- Both sealed splits opened once at the close, with no tuning after. The
  held-out split of the first corpus lifts 1,023 of 1,030 sections (99.3%),
  with its reconstruct identical at 1,174 of 1,918 and every compile-clean file
  holding at 110 of 110. The sealed split of the second corpus, opened for the
  third time ever, lifts 13,845 of 13,978 sections (99.05%, from 13,809): three
  refusal classes emptied, none new, none grew, and its table path re-read
  identical at 3,815 of 3,971.
- The first corpus's table path closed further: 29,595 of 29,597 form and class
  sections recompile to equal frames and symbol tables (0.5.0: 29,581), and
  compiled programs 1,041 of 1,050. Member conservation holds on both corpora
  with zero no-trace members; the second corpus's named refusals fell from 958
  to 474.
- The expression reader, value side: the multi-link scope-member run, the
  element under a system root, and the two-subscript element read.
- The round-78 residue closed: the CAST channel as a marker plus width groups,
  five system-variable ids the sweep missed, the `e0` member tail behind an
  element-hop run, and call-tailed PUT targets.
- The expression reader, statement side: nested-element reads take the WITH
  chain as receiver, an element under a system root resolves to its method
  tail's receiver, a non-first inner element packet closes implicitly at the
  outer bytes, and the statement arm routes multi-link scope runs.
- CREATE CURSOR field tails read whole: `0xbd` is NOCPTRANS and `0x0e` is
  DEFAULT, leaving the bank with no unknown mark.
- The record-level work queue's five largest families, closed in queue order:
  the DO WITH memvar slot, the thirteen SET ids round 71 left, UPDATE SET
  member-path columns, USE trailing bytes, and the DO CASE walker.
- Instruments: unique driver paths with a driver-wide mutex, shared-stage
  retry, content-checked seals, and the wave-3 scorecard with both reveals.

## 0.5.0 — 2026-09-06

The wave-2 close: both corpora and both sealed splits measured together on one
tree, and constant folds written back from an oracle-confirmed table.

- Wave 2 measured whole. Development split of the second corpus: 102,798 of
  103,363 sections lift with zero leaked bytes (0.4.0: 101,719); compiled
  programs 5,250 of 5,476; blocked sections 1,644 to 565. The held-out split of
  the first corpus, opened once at the close: 1,022 of 1,030 sections (99.2%).
  The sealed split of the second corpus, measured for the second time ever:
  13,809 of 13,978 sections (98.8%, from 13,328). The table path over all 19
  second-corpus repositories: 273,610 of 279,698 sections (97.8%).
- Member conservation holds everywhere: 0 no-trace members on both corpora and
  on the sealed second-corpus split. Every pin held through twenty-six serial
  merges and no new failure shape appeared on the first corpus.
- SQL SELECT: aggregates as operands of column expressions, comma-separated
  FROM lists each with its own JOIN chain, qualified stars, the whole
  destination bank (INTO CURSOR/TABLE/DBF/ARRAY, TO FILE ADDITIVE, TO PRINTER
  PROMPT, TO SCREEN, NOWAIT, PLAIN, NOCONSOLE, NOFILTER, READWRITE,
  PREFERENCE), UNION arms with their own WHERE, GROUP BY and HAVING and a
  shared ORDER BY list, and DISTINCT spelled as the author typed it, told
  apart from a variable of the same spelling.
- CREATE CURSOR and CREATE TABLE read from one declarative clause table:
  AUTOINC with NEXTVALUE and STEP, quoted and parenthesised field names, FREE
  and CODEPAGE.
- Statement banks measured whole: INDEX TO and OF with its options, UNLOCK,
  the MODIFY kinds, OPEN DATABASE, DEBUGOUT lists, KEYBOARD, EXTERNAL lists,
  READ's keywords, ADD and REMOVE CLASS; SEEK's clauses; RELEASE's operand
  banks, RELEASE PAD and BAR OF, RELEASE CLASS; DEACTIVATE; COPY's scope,
  FOR and WHILE, FIELDS, TYPE and DELIMITED forms and its MEMO and ARRAY
  spellings; bare statements rooted in a system object or a scope-resolved
  member; quoted REPLACE and DO FORM TO targets.
- Assignment targets: array-element PUT and READ hop runs, system-object
  roots, STORE target runs, WITH-scoped chains (a single letter behind the dot
  is a work-area alias), and indexed members reached through a second call
  link.
- Expressions: 159 measured closer arities from the generated sweep, EMPTY
  included. A constant-folded numeric literal is written back as the shortest
  source expression the oracle confirms compiles to the stored frame: 86
  frames, 275 literals in 74 sections, counted on their own line and never
  inside the lift count.
- Instruments: a content-addressed compile-result store in front of the
  oracle, one shared matrix runner for every measurement, a bijective
  certificate beside the ordered comparator, a record-level work queue, and
  the wave-2 scorecard with both reveals in docs/STATUS.md.

## 0.4.0 — 2026-09-05

A second benchmark corpus, member conservation on both, and the long tail of
statement and expression readings.

- Second benchmark corpus: 29 public repositories from 23 owners, 170,820
  modules, measured under the same criteria as the first. Development-split
  lift: 101,719 of 103,363 sections with zero leaked bytes; compiled
  programs 5,166 of 5,476. The held-out split of the first corpus, opened
  once at the wave close: 1,015 of 1,030 sections (98.5%).
- Member conservation: every declared member of every module on both corpora
  leaves a trace in the lifted source (0 no-trace members across 33,705 and
  291,134 declared members). The walker names members from the record's own
  directory, an empty class still spends its class-init, a length field carved
  out of a stored name is never mistaken for a section, and no code section
  begins inside the module header.
- Statement banks measured whole on the oracle and read in the compiler's own
  order: the SET family (`IN` work areas, the ON/OFF and value-TO ids, the
  word-valued settings, `SKIP`/`MARK OF`, `RELATION` with `ADDITIVE` and `IN`,
  `ORDER` direction, `CLASSLIB ALIAS`/`IN`, `PRINTER … PROMPT`, `REPROCESS`,
  `TEXTMERGE TO MEMVAR`); `BROWSE` and `DEFINE POPUP`/`DEFINE BAR` clauses;
  `SCATTER`/`GATHER` destinations, `FIELDS` and `ADDITIVE`; `CALCULATE`, `SUM`
  and `COUNT`; `CLEAR`; `RETURN TO`; `HELP`; the DO family (`DO … WITH` lists,
  `DO … IN`, `DO FORM NAME`/`TO`/`WITH`/`NOREAD`/`LINKED`/`NOSHOW`);
  `REPORT FORM` clauses; `TEXT … ENDTEXT` openers and verbatim body lines;
  `INSERT … FROM NAME` and `INSERT BLANK` forms; `DECLARE … IN` libraries;
  `CREATE CURSOR … FROM ARRAY`;
  the file verbs (`TYPE`, `COMPILE`, `BUILD`, `RUNSCRIPT`,
  `SAVE`/`RESTORE`, `GETEXPR`), `EXPORT` and `DOCK`; `TRANSACTION` and
  `PRINTJOB` frames; `RETURN @`; `FOR EACH … AS`; the `HIDDEN`, `IMPLEMENTS`
  and remaining `PRIVATE` declaration forms.
- SQL: `DELETE`, `UPDATE`, `DROP TABLE`/`DROP VIEW`, `INSERT … SELECT`,
  `SELECT` without `INTO`, subqueries (`ANY`, `ALL`, `EXISTS`, `IN`), `UNION`
  versus `UNION ALL` including nested unions, nested and flat `JOIN … ON`
  chains, `FULL JOIN`, and `LIKE` with any operands.
- Expressions: measured arities for the bare-id closers (`ORDER`, `MLINE`,
  `KEY`, `RELATION`, and more), `RLOCK`, `ERROR`, `POPUPS`, `COL`, `PROW`,
  `PCOL`, `PRINTSTATUS`, `LOCK`, `DISKSPACE`, `VARREAD`, `LUPDATE`, `QUARTER`;
  the omitted `DO FORM … WITH` argument; the `::` scope operator for
  properties and methods, with dotted prefixes; the indexed-member bracket
  spelling; the bare system-variable id space swept whole.
- Line layout: a folded `LINENO()` is recognised on the wire (a 16-bit frame
  whose digit byte is 0x0a), `LINENO()` counts the program while `LINENO(1)`
  counts the procedure body, and lifted programs put `LINENO()` back on its
  stored line with the padding the compiler measured.
- The shipped system application's command-line interface lifts whole:
  1,971 of 1,971 sections.
- Instruments: the frozen benchmarks distinguish hard failures from walk
  movement, the masking audit records every site that rewrites a refusal, and
  every census check replays its own frozen ledger rather than a live number.

## 0.3.0 — 2026-08-31

Application extraction, and closed parity on the development corpus.

- New command `foxlift extract`: unpack a compiled `.app` or `.exe` into a named
  project tree using only the container's own directory — compiled `.fxp`/`.mpx`
  members are lifted back to `.prg`/`.mpr` source, form and class tables are
  reconstructed with their method source restored, tables, memo sidecars, and
  raw resources are preserved byte-for-byte, and the startup program is
  detected from its measured container marker.
- Project reassembly: `foxlift.project` builds a `.pjx` project table from an
  extracted tree; Visual FoxPro 9 rebuilds the result with `BUILD APP` /
  `BUILD EXE` (rebuilding requires VFP9; extraction does not).
- Statement coverage from four measurement rounds: bare `THROW`; `SUSPEND`;
  `INSERT BLANK` / `INSERT BEFORE BLANK` / `INSERT INTO … FROM NAME`;
  `SELECT … HAVING` and aggregates over full expressions, nested calls
  included; `CREATE TABLE … FREE`; `APPEND FROM` / `COPY TO` file-type
  clauses; `SHOW` / `HIDE WINDOW`; `MODIFY` editing-window clauses; the
  `@ … SAY` command; `EXTERNAL` kinds; and completed system-menu name tables.
- Source-order recovery: clauses the compiler stores in one canonical order
  (`LOCATE`, `COUNT`, `SUM`, `REPLACE … ALL`, `SELECT … INTO`) are emitted in
  the order the source wrote them, recovered from the section symbol table.
- Literal fidelity: integer literals reproduce their stored spelling (decimal,
  zero-padded, or hex — measured width laws); string literals keep their
  original delimiter; high-byte (GBK) strings stay quoted; `TEXT … ENDTEXT`
  bodies are preserved verbatim, indentation included.
- Measured parity at release: on the development corpus every method section
  lifts (10,514 of 10,514); recompiling the output on real VFP9 reproduces the
  original bytecode frames for 29,579 of 29,597 form and class sections and
  2,007 of 2,007 validation sections. Every remaining difference is an
  oracle-proven, documented loss in compilation — never a guess.

## 0.2.0 — 2026-08-28

Compiled-program support and a measured round-trip baseline.

- Decompile standalone compiled programs: `DEFINE CLASS` scaffolds in `.fxp`
  (properties, `PROTECTED`/`HIDDEN`, `ADD OBJECT … WITH`), with class name,
  base class, and `OLEPUBLIC` recovered from the container directory.
- Decompile compiled menu programs (`.mpx`): `DEFINE PAD`/`DEFINE BAR`/popup
  clauses, `ON PAD`/`ON SELECTION`, `SET SYSMENU` forms.
- SQL decode: `DISTINCT`, `TOP n`, `GROUP BY`, `INNER`/`LEFT`/`RIGHT JOIN`,
  and aggregate columns (`COUNT`/`SUM`/`AVG`/`MIN`/`MAX`).
- Non-Latin code pages: symbol names, string literals, and verbatim payloads
  decode via the table's code-page mark instead of Latin-1 mojibake.
- Emission fidelity: a large catalog of spellings the VFP9 compiler proves
  canonical (operator and keyword aliases, `#DEFINE`d literals, clause
  orders) is documented as unrecoverable and emitted in canonical form.
- Round-trip: recompiling decompiled output on real VFP9 reproduces the
  original bytecode frames for 95% of the measured population; procedure
  names are preserved on emit, and the one statement lead no probe could
  produce is annotated in place rather than guessed.

## 0.1.0 — 2026-08-27

First public release.

- Decompile Visual FoxPro 9 `.fxp`, `.app`, `.exe`, `.scx`, and `.vcx` files to
  buildable source with `foxlift decompile`; structural dumps with
  `foxlift inspect --json`.
- Verified output: `decompile` exits `0` only when every discovered section was
  lifted inside the supported slice; partial output exits `2`.
- Authored round-trip demo under `demo/`: source compiled on real VFP9,
  decompiled, recompiled byte-identical — receipts in `demo/receipts.json`.
- Proven-unrecoverable constructs (comments, DECLARE parameter names,
  WAIT WINDOW clause order) are documented and never invented.
- Package the `foxlift` command for pip, pipx, and uv installs.
- Add open-source automation, contribution, and security infrastructure.
- License FoxLift under AGPL-3.0-only.
- Name Timo Bejan as the copyright holder and commercial licensor.
- Add contributor, commercial-licensing, and trademark terms.
