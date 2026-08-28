# Changelog

FoxLift uses Semantic Versioning. Release tags use `vX.Y.Z` and must match the version in
`pyproject.toml`.

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
