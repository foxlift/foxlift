# Changelog

FoxLift uses Semantic Versioning. Release tags use `vX.Y.Z` and must match the version in
`pyproject.toml`.

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
