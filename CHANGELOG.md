# Changelog

FoxLift uses Semantic Versioning. Release tags use `vX.Y.Z` and must match the version in
`pyproject.toml`.

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
