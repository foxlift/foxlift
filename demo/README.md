# FoxLift demo — round-trip, with receipts

A small Visual FoxPro 9 project, authored for this demo and free to redistribute. It exists to
back one claim with evidence: **source → compiled → FoxLift → recompiled → byte-identical
statement frames and symbol tables**, through the shipped CLI, with every exit code and hash
recorded in [`receipts.json`](receipts.json).

## What is in it

| File | What it exercises |
|---|---|
| [`src/partsbin.prg`](src/partsbin.prg) | CREATE CURSOR, INSERT, SCATTER/GATHER, DO CASE, FOR/ENDFOR, GO/SKIP, arrays in both subscript spellings (`laBand[1]` and `laBand(2)`), deliberate numeric spellings (`0048`, `0.50`) |
| [`src/counterform.prg`](src/counterform.prg) | a runtime form built through member paths (`loForm.lblTitle.Caption`), method calls, DECLARE DLL (one API with a named parameter), an `@` by-reference call, TEXT/ENDTEXT, WAIT WINDOW with deliberately scrambled clause order |

Both programs compile clean on VFP9 and run as ordinary standalone programs.

## Run it yourself

You need Visual FoxPro 9 to compile (FoxLift itself runs anywhere Python runs and never needs
VFP to decompile). From the repo root:

```console
# 1. compile the authored source (in VFP9)
COMPILE demo\src\partsbin.prg

# 2. inspect the compiled artifact
foxlift inspect demo/src/partsbin.fxp --json

# 3. decompile it — exit code 0 means every section was lifted and verified
foxlift decompile demo/src/partsbin.fxp -o recovered

# 4. recompile the decompiled source (in VFP9)
COMPILE recovered\module_000000\source.prg

# 5. compare recompiled bytecode against the original
python3 -c "
from pathlib import Path
from foxlift import compare
c = compare.compare_compiled(Path('demo/src/partsbin.fxp').read_bytes(),
                             Path('recovered/module_000000/source.fxp').read_bytes())
print(c.equal, c.reason)"
```

Step 5 prints `True all original sections matched in order` when the round trip holds. Raw `.fxp` files are never compared byte-for-byte — VFP embeds a compile timestamp
and the source path in the container, so two compiles of identical source always differ there.
The comparison that means something, and the one used everywhere in this project, is:
**statement frames byte-equal AND symbol tables equal** (`foxlift/compare.py`).

## What the receipts say

[`receipts.json`](receipts.json) was produced by [`make_receipts.py`](make_receipts.py) against
a real VFP9 (the exact commands and their exit codes are recorded inside it):

- 2 programs, compiled on VFP9, hashes recorded.
- `foxlift inspect` exit 0 on both; every statement recognised (30 + 22 = 52 statements).
- `foxlift decompile` exit 0 on both — every section lifted, `"verified": true`.
- Recompiled decompiled output on the same VFP9: **2 of 2 sections byte-identical** in frames
  and symbol tables against the original bytecode.
- One negative control: a single mutated literal (`500` → `501`) recompiled and compared — the
  comparator reports it unequal. An instrument that cannot say "no" proves nothing.

## What comes back different, and why that is honest

Decompiled output is functionally equivalent canonical source, not a facsimile. Each difference
below is a measured property of the VFP9 compiler — the information is not in the bytecode, and
a decompiler that "recovered" it would be inventing it. All of them recompile to byte-identical
bytecode; that is the invariant the receipts pin.

| Authored | Decompiled | Why |
|---|---|---|
| `* Top up the first part…` | absent | comments are never compiled |
| `lnRestock`, `parts.qty` | `LNRESTOCK`, `PARTS.QTY` | identifier case is not recorded (symbol tables are case-folded); names that ride the wire as strings — cursor names, DECLARE targets, string literals, TEXT bodies — keep their exact spelling |
| `WAIT WINDOW … NOWAIT NOCLEAR` | `… NOCLEAR NOWAIT` | VFP9 canonicalises WAIT WINDOW clauses to one wire order; the authored order is unrecoverable (oracle-measured) |
| `STRING @ lpPoint` | `STRING @` | DECLARE parameter names are discarded by the compiler — proved by compiling named, renamed, and nameless variants to identical bytecode |
| `laRow[3]` as a read | `LAROW(3)` | an array *read*'s subscript spelling is not on the wire; array *writes* (`LAROW[3] =`, `DIMENSION LAROW[4]`) record it, and the demo shows both preserved |
| `0.50`, `0048`, `18.20` | `0.50`, `0048`, `18.20` | numeric literal spelling is restored from the compiled width/decimals header — including leading zeros |

The `* --- section 0 ---` marker lines in decompiled output are comments; they compile to
nothing and do not disturb the round trip.

## Reproducing receipts.json

```console
python3 demo/make_receipts.py
```

This drives a licensed VFP9 over SSH (see `docs/ORACLE.md`), compiles both rounds as batched
single invocations, runs the shipped CLI as subprocesses, and writes the receipts. Without a
VFP9 oracle configured you can still verify the shipped artifacts' hashes and re-run steps 2–5
above against your own VFP9.
