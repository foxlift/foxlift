# FoxLift

[![CI](https://github.com/foxlift/foxlift/actions/workflows/ci.yml/badge.svg)](https://github.com/foxlift/foxlift/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/foxlift.svg)](https://pypi.org/project/foxlift/)
[![Python](https://img.shields.io/pypi/pyversions/foxlift.svg)](https://pypi.org/project/foxlift/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://github.com/foxlift/foxlift/blob/main/LICENSE)

FoxLift is an open-source Visual FoxPro 9 decompiler. It reads compiled VFP files and produces a source tree that can be inspected, versioned, and rebuilt where the input is fully supported.

FoxLift is under active development. Treat output as unverified unless the command reports `"verified": true`.

## Install

Install the command with [pipx](https://pipx.pypa.io/) or [uv](https://docs.astral.sh/uv/):

```console
pipx install foxlift
# or
uv tool install foxlift
```

To install into the current Python environment instead:

```console
python -m pip install foxlift
```

## Use

Inspect a compiled file without writing output:

```console
foxlift inspect app.exe --json
```

Decompile it to a directory:

```console
foxlift decompile app.exe -o recovered
```

`decompile` exits with `0` only when every discovered section was lifted inside the supported slice. Exit code `2` means partial output was written but could not be fully verified. Invalid or unsupported input exits with `1`.

Extract an application into a named project tree:

```console
foxlift extract app.exe -o recovered
```

`extract` names every file from the container's own directory: compiled `.fxp` and `.mpx` members come back as `.prg` and `.mpr` source, form and class tables are reconstructed with their method source restored, and tables, memo sidecars, and raw resources are written byte-for-byte. The detected startup program is reported. Exit `0` means every entry landed; `2` means the tree was written with named misses.

FoxLift works offline and does not require Visual FoxPro at runtime.

A worked example ships in [demo/](demo/): authored source, compiled on a real VFP9, decompiled with this CLI, recompiled byte-identical — with every exit code, hash, and per-section verdict recorded in its receipts.

## Scope

FoxLift targets unprotected Visual FoxPro 9 artifacts, including `.fxp`, `.app`, `.exe`, `.scx`, `.vcx`, `.frx`, and `.mnx` files. Coverage varies by format and language feature while development continues.

Decompiler output is functionally equivalent source, not the original source. Comments are not present in compiled bytecode, and some expressions lose their original spelling during compilation. Protected or encrypted applications are not supported.

Only decompile software you own or are authorized to inspect.

## Contributing

See [CONTRIBUTING.md](https://github.com/foxlift/foxlift/blob/main/CONTRIBUTING.md) for setup and contribution rules. Do not submit proprietary binaries, confidential data, or output derived from ReFox.

FoxLift is licensed under the [GNU Affero General Public License v3.0](https://github.com/foxlift/foxlift/blob/main/LICENSE). [Separate commercial terms](https://github.com/foxlift/foxlift/blob/main/COMMERCIAL-LICENSE.md) may be available for proprietary integrations that cannot comply with the AGPL. The FoxLift name and logo are covered by the [trademark policy](https://github.com/foxlift/foxlift/blob/main/TRADEMARKS.md). Project updates are published at [foxlift.dev](https://foxlift.dev).
