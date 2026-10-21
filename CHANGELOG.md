# Changelog

FoxLift uses Semantic Versioning. Release tags use `vX.Y.Z` and must match the version in
`pyproject.toml`.

## 0.9.4 — 2026-10-21

Line numbers and SQL clause order. Each rule was measured with authored programs compiled
by VFP9 and checked section by section against 0.9.3 on both corpora's development and
validation splits.

- `LINENO()` written inside an ON ERROR, ON ESCAPE, ON SHUTDOWN, ON READERROR or ON KEY
  LABEL handler, or on a `\` or `\\` text-merge line, is not a stored line number: the
  compiler keeps that statement as text. 0.9.3 counted those spellings, found more than the
  compiled code holds, and wrote the whole record without line placement, so every
  `LINENO()` in it recompiled on the wrong line. Now the handler and merge-line spellings
  are skipped and the record is placed. On the development splits 190 sections recompile
  equal that did not: 140 in seven copies of one class library (115,425 to 115,565 equal of
  115,586) and 50 in two forms (404 to 454 of 454), with 0 broken. Four programs recompile
  equal whole. Placement pads with blank lines to reach the stored line numbers, so one of
  those programs lifts to 162,137 lines where 0.9.3 wrote 7,450.
- `LINENO()` inside a string literal is not a stored line number either, but this release
  does not skip it: on the development program where these strings make the count
  disagree, skipping them makes placement fail at a later fold. That program keeps 0.9.3's
  text.
- SQL SELECT writes INTO ARRAY, INTO CURSOR and INTO TABLE against ORDER BY where the
  source wrote it, when the target's name is first written by that statement. The compiler
  numbers names in source order, so 0.9.3, which wrote INTO after ORDER BY, recompiled 27
  of 62 authored statements with their symbols numbered differently; all 62 recompile equal
  now. A name that an earlier statement already wrote, or an ORDER BY that names nothing new,
  compiles the same in either order, and INTO stays last. GROUP BY and HAVING keep INTO
  last. On the development and validation splits 5 sections and 1 program recompile equal
  that did not, 0 broken.
- Measured figures are 0.9.0's. None of these changes moves a program of the authored
  population. The sealed splits were not reopened.

## 0.9.3 — 2026-10-11

`decompile` reads APP and EXE files through their directory, and SQL SELECT keeps
INTO ARRAY ahead of WHERE. Both came up on the same production application. The
directory walk and the INTO ARRAY order were each reproduced with authored programs
compiled by VFP9 and fixed against those; running the walk over both corpora found the
code-page, report and deleted-record fixes below. None of that application's code is
evidence or ships.

- `decompile` on an `.app` or `.exe` walks the container's own directory. Every compiled
  member and every form, class library or report gets a `NNNN_<name>/` folder, `NNNN`
  its directory position, and is lifted as the same file on its own would be; the JSON
  result lists every entry with its kind. 0.9.2 scanned the bytes for module headers and
  wrote `module_<offset>/` folders. That scan read the APP header as one more module,
  and in a form's or class library's memo file it read past each record's code into
  leftover memo bytes, lifting procedures and sections no record holds. Its `verified`
  on an APP or EXE counted those. On the production application's EXE, whose APP header
  sits behind an application icon, the header module came out empty and `decompile`
  exited 2.
- Forms and class libraries whose code holds names or strings in their table's code
  page, GBK for example, decompile. 0.9.2 stopped on such a file with an encoding error
  (exit 1). The text reaches `source.prg` as the bytes the table stores.
- `decompile` and `inspect` read reports and labels (`.frx`, `.lbx`), on their own and
  inside an APP or EXE: the compiled code of a report's data environment is lifted as a
  form's is. 0.9.2 refused these files as unsupported input.
- A deleted record's code is still not lifted. The JSON result now counts the deleted
  records that hold code, in `records_deleted_with_code`.
- SQL SELECT keeps INTO ARRAY ahead of WHERE when the source wrote it there and the
  array, a bare name, `m.name` or an object's property, is first named by that
  statement. The compiler numbers the array's names where INTO was written. 0.9.2 read
  that order for INTO CURSOR and INTO TABLE only and wrote INTO ARRAY behind WHERE, so
  the recompiled program numbered its symbols differently. Where the array was declared
  earlier, or the WHERE names nothing new, both orders compile to the same bytes and
  WHERE stays first. INTO ARRAY with ORDER BY is not covered.
- Measured figures are 0.9.0's. The INTO ARRAY change moves no section in either corpus
  or in the authored population. The directory walk changes none of the code those
  figures read; it was measured with `decompile` itself, 0.9.2 against 0.9.3, over the
  68 APP and EXE files of both corpora's scored splits. 19 verify where 14 did, and none
  that verified stops verifying. Modules rise from 12,152 to 12,336 and sections fall
  from 51,815 to 51,714. 118 lifted texts in 0.9.2's output are not in 0.9.3's: 91 were
  read past a record's code, 20 were APP headers, 6 came from deleted records and 1 from
  a report memo block no record points to. The sealed splits were not reopened.

## 0.9.2 — 2026-10-10

More fixes from the same production application, each reproduced with authored
programs compiled by VFP9 and fixed against those; none of that application's code is
evidence or ships.

- `extract` names APP and EXE members whose name VFP stored as the tail of an earlier
  name. BUILD APP and BUILD EXE do not write a name twice: a name that ends a name
  already in the pool points into it (`open.bmp` after `xopen.bmp`, and directory names
  alike). 0.9.1 read a name only where a pool entry starts, so these members had no
  name and were not extracted.
- SQL SELECT keeps INTO ahead of WHERE when the source wrote it there and the WHERE
  names the FROM table, a FROM alias or a projection column. The compiler stores INTO
  behind WHERE either way, and the order survives only in how it numbers the INTO name
  against the names the WHERE introduces; 0.9.1 counted those three as the WHERE's
  own. INTO ARRAY is not covered.
- Statements read for the first time: assignment to an array property of an array
  element with bracket subscripts (`o.a[i, 4].b[j, 1] = v`); a method call, a macro
  line or a complete nested DO CASE between DO CASE and its first CASE; `@ ... GET
  m.var`; and REPLACE into a field qualified by a work-area letter (`REPLACE a.f WITH v`).
- Measured figures are 0.9.0's. First corpus and the authored population: output
  unchanged. Second corpus, development split: the SQL change rewrites 21 table records
  in 21 files; read file by file on the live-record table path, those files stay at 746
  of 750 equal sections, none gained or lost. Of the scored splits' APP and EXE files,
  56 members in 9 containers that 0.9.1 left unnamed now have names, and no other name
  changes. The sealed splits were not reopened.

## 0.9.1 — 2026-10-10

Fixes found by running 0.9.0 on a production VFP9 application, its executables and
its source archive. Each was reproduced with authored programs compiled by VFP9 and
fixed against those; none of that application's code is evidence or ships.

- `extract` opens an EXE built with a custom application icon. VFP9 writes the icon
  file at the start of the EXE's overlay and the APP container after it, behind a
  14-byte trailer whose last field is the distance to the container. FoxLift reads the
  icon's own directory, checks it against that field, and refuses an overlay where the
  two disagree.
- REPLACE writes its scope words where the symbol table says they stood. VFP9 records
  ALL before the field list, FOR before ALL and IN before FOR only in the order it
  numbers symbols, so 0.9.0's spelling compiled to the same statement bytes with a
  shifted symbol table. The recompiled program now matches, including a REPLACE ALL ...
  FOR whose names earlier lines already declared. REPLACE ALL ... WHILE no longer loses
  WHILE, and ADDITIVE ALL no longer loses ALL.
- Statements read for the first time: TEXT without TO (NOSHOW, TEXTMERGE, PRETEXT,
  FLAGS, ADDITIVE); RENAME with a parenthesised or single-quoted old name; EXPORT TO ...
  XLS, XL5 or DIF without TYPE; ERASE with an unquoted name and RECYCLE; DELETE TRIGGER
  ON ... FOR DELETE, INSERT or UPDATE; SET STRICTDATE TO; APPEND FROM ... XL5 or XLS
  SHEET, and DELIMITED WITH a string without CHARACTER; @ ... GET ... VALID without
  PICTURE; FOR EACH over an array element's property with bracket subscripts; ALEN of
  an array element's array property; DIMENSION of an array property of an array
  element; and an array element's property as a statement with paren subscripts.
- Measured figures are 0.9.0's. First corpus: table path 29,595 of 29,597 and compiled
  programs 1,051 of 1,051, output unchanged. Authored population unchanged. Second
  corpus, development split: every section still lifts; the REPLACE changes rewrite 119
  table records in 114 files and 8 programs. Read file by file on the live-record table
  path, those files gain 118 equal sections and lose none, and 7 of the 8 programs now
  recompile frame- and symbol-equal (the eighth fails the same way before and after).
  The sealed splits were not reopened.

## 0.9.0 — 2026-10-10

The wave-5 close: on the second corpus's development split every compiled
program now lifts and no refusal is left, and both sealed splits were opened
once more.

- Second corpus, development split: every section lifts (103,363 of 103,363),
  and now every compiled program does too, 5,476 of 5,476 (0.8.0: 5,305).
  Named refusals on the scored walk fell from 85 to 0. Table path 274,262 of
  279,698 positional (0.8.0: 274,063) and 275,522 of 277,658 live-record
  (99.23%, 0.8.0: 275,323), with no section lost against 0.8.0.
- First corpus: table path 29,595 of 29,597 and compiled programs 1,051 of
  1,051, unchanged. The wave-5 close read 29,593: one wave-5 law, REPLACE's
  FOR-before-ALL order, took a FOR that a later statement interned for the
  current statement's own. Round 281 narrowed it before this release; the
  second corpus's development output is byte-identical with and without the
  fix.
- Both sealed splits opened once at the wave-5 close, with no tuning after,
  on the lifter before that fix. The first corpus's held-out split lifts
  1,030 of 1,030. The second corpus's sealed split lifts 13,976 of 13,978
  (99.99%, 0.8.0: 13,969); its refusal classes fell from 5 to 2, none new.
  Its table path reads 3,811 of 3,971 (0.8.0: 3,807), and half of the
  registered eight-section symbol-table pattern closed.
- Authored population 1,913 of 1,917 equal (0.8.0: 1,880), 0 regressed. The
  lifter refuses none of it; the four left are three `/`-fold programs and
  one phantom section.
- Statements measured and read since 0.8.0: ASSERT ... MESSAGE; SET CLOCK
  STATUS, SET HELP SYSTEM, SET SCOREBOARD and SET PRINTER TO NAME; SET
  PROCEDURE and SET INDEX name lists; DISPLAY MEMORY LIKE; PROTECTED and
  HIDDEN with array dimensions; ON SELECTION PAD, POPUP and MENU; DEFINE
  WINDOW SHADOW and COLOR pairs; SHOW GET; @ SAY BITMAP, the @ GET clause
  bank and VALID after PICTURE; ALTER TABLE ... AUTOINC NEXTVALUE and ADD
  without COLUMN; REPLACE NOOPTIMIZE and its FOR/ALL and IN/FOR clause
  orders; LIST STRUCTURE TO ... ADDITIVE; CALCULATE ... IN; PACK IN; APPEND
  FROM ... FIELDS; PRIVATE and ZOOM WINDOW with quoted names; VALIDATE
  DATABASE; DROP TABLE ... RECYCLE; SUM ALL TO ARRAY; BROWSE FIELDS with a
  member reference; EXPORT ... FOR; RUN with a double-quoted payload; SELECT
  with a star between columns, a second qualified star, a star in a UNION
  arm or a trailing DISTINCT, ORDER BY ahead of WHERE, COUNT spelled COUN or
  CNT, and integer items in an IN list; DO WITH/IN, SEEK IN/ORDER and COPY
  FOR/WHILE in the order the symbol table records; ISBLANK by reference;
  currency literals; SHOW and HIDE of GETS, MENU, OBJECT and POPUP; MENU TO;
  SIZE POPUP; APPEND GENERAL FROM; RENAME with quoted names; `?` with an AT
  column; a bare AS type mark; and a zero-argument memory-variable call.
- Reconstruction moves a procedure's leading blank lines ahead of its
  PROCEDURE line when VFP9's line numbering needs them there.
- The compile oracle deletes its transfer archives after each batch.

## 0.8.0 — 2026-09-25

The wave-4 close: every wave-4 lane measured together on one tree, both sealed
splits opened once, and a table-path measurement defect found and corrected
before either seal opened.

- Development split of the second corpus: every section lifts, 103,363 of
  103,363 with zero leaked bytes (0.7.0: 103,317). The record-level blocker
  queue is empty. Compiled programs 5,305 of 5,476.
- First corpus: every development, validation and held-out section lifts, and
  the last six named refusals are closed. Two of them were shapes earlier
  rounds had registered as unreachable: `28 08 2d` is INSERT BLANK AFTER, and a
  bare `b8` is the stray ENDIF VFP9 still writes beside its own "IF | ELSE |
  ENDIF statement is missing" diagnostic. Compiled programs recompile 1,051 of
  1,051.
- Both sealed splits opened once at the close, with no tuning after. The
  held-out split of the first corpus lifts 1,030 of 1,030 sections (0.6.0:
  1,023). The sealed split of the second corpus lifts 13,969 of 13,978 (99.94%,
  0.6.0: 13,845): 25 of its 30 refusal classes emptied, none new, none grew.
  Its table path reads 3,807 of 3,971, eight sections below the wave-3 reading
  in one registered symbol-table pattern.
- Table-path measurement fix. VFP9's COMPILE CLASSLIB drops deleted records,
  and the table path paired original and recompiled records by position, so
  every record after a deleted one was scored against the wrong neighbour.
  Every table-path figure now carries the historic positional reading beside
  a live-record reading, with sections inside deleted records counted on
  their own line. Second-corpus development: 274,063 of 279,698 positional
  (0.6.0: 273,404) and 275,323 of 277,658 live-record (99.16%), 2,040 sections
  in deleted records. First-corpus held-out: every live section recompiles
  equal, 1,524 of 1,524.
- Authored population 1,880 of 1,917 equal, 0 regressed by name. Member
  conservation holds on both corpora with zero no-trace members; named
  refusals on the second corpus fell from 474 at the wave-3 close to 85.
- Statement banks measured and read since 0.7.0: COUNT TO an array element;
  CREATE SQL VIEW with no connection; DEFINE WINDOW NAME; DIMENSION ... AS;
  GETEXPR TO; ON KEY LABEL with a quoted label; negative numeric widths; the
  shared DISPLAY/LIST OBJECTS frame; DEFINE PAD name, OF, BEFORE and AFTER
  slots; ON PAD operands; HIDE WINDOW ALL; DEFINE BAR KEY and DEFINE BAR OF a
  quoted popup; WAIT WINDOW TIMEOUT and an optional message; bare CREATE,
  CREATE CLASSLIB and keyword-less CREATE; ON READERROR; DECLARE DOUBLE; LIST
  MEMORY; POP MENU TO MASTER; chained OTHERWISE; ASCAN's stranded opener;
  APPEND MEMO FROM; the lone WITH-scope dot; EDIT with BROWSE's clauses; FLUSH
  with an operand; BLANK with its record scope; RENAME CLASS; DEFINE MENU;
  ACTIVATE POPUP with a quoted name; DO FORM ... WITH argument order; negated
  SELECT columns; and bracket-quoted literals that hold an apostrophe.
- The compile oracle's table-path driver refuses a session whose code page has
  drifted, and the matrix instrument keeps the module VFP9 writes beside a
  diagnostic, which is how the stray-ENDIF producer was found.

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
