# Contributing

FoxLift is a clean-room decompiler. Contributions must preserve that boundary.

## Set up

Use Python 3.10 or newer:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]" ruff build twine
```

On Windows, activate the environment with `.venv\Scripts\activate`.

Run the same VM-free checks used by CI:

```bash
ruff check --select E9,F63,F7,F82 .
python -m pytest -ra --strict-markers
python -m build
python -m twine check --strict dist/*
```

The required checks do not need Visual FoxPro, the oracle VM, or the external corpus.

## Inputs and evidence

- Inspect only inputs you own or are authorized to analyze. Submit only material you created or
  may redistribute publicly.
- Never submit proprietary or confidential customer files, credentials, licensed VFP media, or
  material whose redistribution rights are unclear.
- Never submit ReFox output, ReFox-derived code or evidence, or results obtained by comparing
  FoxLift with ReFox.
- Reduce test cases to authored or publicly redistributable fixtures before committing them.
- Oracle evidence must state its authored source and include only redistributable derived data.

If a bug depends on material that cannot be shared publicly, describe the structure without
attaching the material. Use the private vulnerability reporting flow for security issues.

## Pull requests

Keep changes focused. Add tests for behavior changes, preserve the two-line `ABOUTME:` header in
code files, and update `CHANGELOG.md` for user-visible changes. Do not weaken or skip a check to
make a pull request pass.

Each copyrightable contributor must accept the [Individual Contributor License
Agreement](CLA.md) before merge. The agreement leaves ownership with the contributor while allowing
Timo Bejan to offer FoxLift under both AGPL-3.0-only and separate commercial terms.

The individual agreement does not cover work owned by an employer or another legal entity. Obtain
an entity agreement or a written employer waiver before submitting that work.
