# The VFP9 compile oracle

ABOUTME: How to reach and drive the licensed VFP9 install that foxlift is validated against.
ABOUTME: The oracle is the project's core advantage — it turns opcode semantics into a script.

## Why it exists

VFP9 itself is the compiler, so it settles questions about the format that would otherwise be
guesswork:

```
source ──VFP──▶ bytecode ──foxlift──▶ source′ ──VFP──▶ bytecode′
```

Because we author the source, the expected answer is known exactly. Opcode semantics become a
harvest rather than research, and correctness becomes a measured percentage rather than a claim.
ReFox was built without one. Every format fact in [FORMAT.md](FORMAT.md) came from here or from
counting the corpora.

## Where it is

A licensed **VFP9 SP2 (9.0.0.5815)**, 32-bit x86, running under Prism emulation on Windows 11 ARM,
in a UTM QEMU VM on the Mac.

| | |
|---|---|
| VM | UTM VM named `Windows` — `utmctl start Windows` |
| Reach | `ssh -i <your-key> oracle@<vm-ip>` (UTM shared network) |
| VFP | `C:\Program Files (x86)\Microsoft Visual FoxPro 9\vfp9.exe` |
| Host dir | `~/vfp9-oracle/` — media, keys, `STATE.md`, shell drivers |

`~/vfp9-oracle/` is **local-only and stays out of this repo**: it holds licensed install media and
the VM's SSH key. `foxlift/oracle.py` reaches it over SSH; it never vendors it.

## Driving it

From Python, which is what the harnesses use:

```python
from foxlift import oracle
oracle.alive()                      # False if the VM is not started
results = oracle.compile_dir(path)  # {stem: CompileResult(fxp=bytes, err=str, ok=bool)}
```

`compile_dir` ships the directory up as one zip, compiles the whole batch in a **single** VFP
invocation, and pulls the results back as one zip. Per-file scp dominates wall-clock past a few
dozen files; VFP startup dominates past a few dozen invocations.

There are also shell drivers at `~/vfp9-oracle/oracle.sh` (`eval`, `compile`, `shell`) for
one-off interactive work.

## Gotchas that will cost you an hour

**VFP re-runs a stale `.fxp`.** If a `.fxp` is not older than its `.prg`, `vfp9.exe` executes the
cached one and silently ignores your edit. Always delete the harness `.fxp` before running.
`oracle.py` does this; anything hand-rolled must too.

**A detached launch dies with its SSH session.** Windows OpenSSH wraps each session in a job
object with kill-on-close: `Start-Process` without `-Wait` followed by exiting the PowerShell
reaps the child vfp9 seconds later — measured as a whole poll window with no log. `-Wait` (what
`compile_dir` does) is load-bearing because it holds the session open for the whole build; for
genuinely detached work, spawn via WMI `Win32_Process.Create`, whose parent is the WMI service
and survives the disconnect.

**Driver PRGs must be CRLF ASCII written guest-side.** The proven path is `Set-Content -Encoding
ascii` on the guest (what `compile_dir` does). A host-written LF-only file differs from every
run that has ever worked; do not test whether VFP tolerates it.

**`BUILD PROJECT ... FROM` takes comma-separated files.** Space-separated lists are a parse
error, and under `SCREEN=OFF` a driver-level compile error kills the whole batch silently.
For unattended drivers also set `SYS(2335, 0)` first (suppresses modal prompts), plus `SET
SAFETY OFF`, `SET TALK OFF`, an `ON ERROR` handler that logs and QUITs, and `ON SHUTDOWN QUIT`.
A logged build error beats a hung session — see `probes/exe_container/vfpdrv.py`.

**foxlift.vmlock's flock is not reentrant per-fd.** A nested `hold()` in the same process
deadlocks against itself — it waits on a lock its own caller holds, with no children and no
output. Pass `lock=False` down to helpers when the outer frame already holds it.

**SSH-launched processes land in session 0 — no interactive desktop.** Detached
`Start-Process`, blocking `-Wait`, WMI `Win32_Process.Create`, and scheduled tasks as SYSTEM
all run there. If a run needs a real desktop (dialogs, COM automation that renders), schedule a
task as the logged-on user in session 1 instead. On 2026-08-23 an unattended guest stuck at the
lock screen plus a half-applied Windows update produced hours of "vfp9 starts but executes no
driver" that survived reboots; it cleared only after updates finished AND an interactive login
existed. When the oracle behaves strangely, check
`query session` for an active console session before debugging anything else.

**Fixed-width filenames in probe corpora.** The compiler embeds the source path in the output, so
`p1.prg` and `p01.prg` produce outputs differing in length. That shifts every downstream byte and
destroys minimal-pair diffs. `corpus.py` names everything `s%04d.prg` for this reason.

**Quoting through ssh → cmd → PowerShell.** Base64-UTF16LE the script and use
`powershell -EncodedCommand`. `oracle.powershell()` does this.

**Headless runs need `SCREEN=OFF`** in `C:\oracle\config.fpw`, invoked as
`vfp9.exe -cC:\oracle\config.fpw -t prog.prg`.

**Output comes back uppercase.** The guest writes `.FXP`/`.ERR`; index case-insensitively.

**Only standalone PRGs are compiled today.** `compile_dir` handles `*.prg`. Scoring against real
form/class methods needs a method-compilation path — see below.

## Method compilation

Canonical scoring compares the original `OBJCODE` against a recompile of the emitted source, which
means compiling a *method*, not a program.

Evidence says a `DEFINE CLASS` PRG wrapper is sufficient rather than needing real SCX compilation.
The same method text —

```foxpro
LPARAMETERS vNewVal
THIS.Caption = m.vNewVal
```

— compiled inside `ctl32_classes.prg` (`ctl32_menuitem AS Custom`) and stored in
`foxcharts.vcx` (`_tooltip AS Label`) produces **byte-identical statement frames**:

```
07 00 af f7 00 00 fe
12 00 54 f4 01 00 f7 02 00 10 fc f5 0d f7 00 00 fd fe
```

Neither PRG-versus-VCX storage nor the differing base class changed the instruction stream.
`_base.vcx` corroborates: 35 objects sharing a `METHODS` memo share one byte-identical `OBJCODE`
despite different base classes.

**Matrix result, 2026-08-23 (`probes/context_matrix/`): the wrapper is ACCEPTED for scoring.**
All six construct families probed (local-only, `THIS.member`, `THISFORM.member`, `WITH`,
local-shadowing-property, LPARAMETERS+THIS) produce byte-identical framed statement streams
across standalone PRG, `DEFINE CLASS … AS Custom`, `… AS Label` and `… AS Form`; the ctl32
witness reproduced across four provenances; a real `.scx` method (`BuyTrack.scx` `cdCancel`
Click) matched its stored OBJCODE exactly. Literal/operator/declaration-order mutations all
fail the comparison; *pure renames* do not, because names live only in the symbol table — so
the comparator MUST resolve symbol indexes to names before comparing semantics. Two comparator
conditions are mandatory: compare method-section frames only (never whole files), and compare
per-section symbol tables alongside frames. Remaining UNVERIFIED: implicit-property and
property-shadowing contexts beyond those probed.

VFP has `COMPILE FORM` and `COMPILE CLASSLIB` if the wrapper turns out not to hold.

## Rebuilding the VM

`~/vfp9-oracle/STATE.md` has the full build log. The parts that matter if it is ever lost:

- Use UTM's **QEMU** backend with HVF. The Apple Virtualization backend is broken for Windows —
  it boots to a black framebuffer and pegs the CPU.
- Install VFP9 with `msiexec /i vs_setup.msi /qn VSEXTUI=1 PIDKEY=<key> REBOOT=ReallySuppress`.
  Running `vs_setup.msi` directly fails 1603 on a launch condition, and the `setup.exe`
  bootstrapper hangs headless in session 0. Then apply `VFP9_sp2.exe /q`.

## Measured throughput and two negative results (2026-08-23)

Cost model, measured with identical batches before and after a config change:

| batch | wall | per file |
|---|---|---|
| 1 | 5.5s | 5.47s |
| 10 | 9.4s | 0.94s |
| 100 | 57.1s | 0.57s |

**Fixed overhead ~4.9s per batch; marginal ~0.52s per file.** A one-file call is 88% transport
(ssh, scp, zip, VFP process start). Batch everything; a probe that compiles one snippet per call
spends almost all its time on overhead, which is why small-batch work feels far slower than the
corpus runs.

**Negative result — TSO does not help.** UTM's Total Store Ordering was off, and the theory was that
it would speed Windows-on-ARM's x86 translation of vfp9 (a 32-bit x86-only binary). Enabling it,
with RAM 4 GB → 12 GB and 8 vCPUs, moved the marginal cost 0.521s → 0.514s per file: noise. The
0.5s/file is the emulation floor and is not reachable by host tuning. Only a real x86 machine
removes it.

**Negative result — vfp9 does NOT need an interactive desktop session.** During the afternoon
outage the guest sat at the lock screen with no `explorer.exe` and console session 1 unoccupied,
which looked like a strong explanation for driver programs never executing. It was not: after the
update-reboot the oracle compiles normally with session 1 still showing no username. The outage is
attributable to the pending Windows/Defender update, not to the missing session. SSH-launched
processes do still land in session 0, so anything that genuinely needs a desktop must run as a
scheduled task in the logged-on session — but ordinary compiles do not.

**`.fxp` is not byte-reproducible.** Two serial compiles of identical source differ at 17 offsets
(embedded timestamps). Compare with `compare.compare_compiled`, which looks at statement frames and
symbol tables; a raw byte comparison reports 100% mismatch and means nothing. See `foxlift/vmlock.py`
for the concurrency measurement this instrument settled.
