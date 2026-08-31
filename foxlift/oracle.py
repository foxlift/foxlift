# ABOUTME: Drives the VFP9 compile oracle VM (Win11 ARM + Prism) over SSH as a batch compiler.
# ABOUTME: Ships a directory of .prg up as one archive, compiles in a single VFP run, pulls .fxp/.err back.

import base64
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

VM = os.environ.get("FOXLIFT_ORACLE_VM", "")  # ssh destination of the compile VM, e.g. "user@host"
KEY = Path.home() / "vfp9-oracle/ssh/id_vfp9"
VFP = r"C:\Program Files (x86)\Microsoft Visual FoxPro 9\vfp9.exe"

_SSH_OPTS = [
    "-i", str(KEY),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=15",
]


class OracleError(RuntimeError):
    pass


def _ssh(args, **kw):
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    return subprocess.run(["ssh", *_SSH_OPTS, VM, *args],
                          capture_output=True, text=True, **kw)


def _scp(src, dst):
    r = subprocess.run(["scp", *_SSH_OPTS, "-q", src, dst], capture_output=True, text=True)
    if r.returncode:
        raise OracleError(f"scp {src} -> {dst}: {r.stderr.strip()}")


def powershell(script: str) -> str:
    """Run a PowerShell script in the guest via base64-UTF16LE, dodging ssh->cmd->pwsh quoting."""
    script = "\x24ProgressPreference = 'SilentlyContinue'\n" + script
    b64 = base64.b64encode(script.encode("utf-16-le")).decode()
    r = _ssh([f"powershell -NoProfile -EncodedCommand {b64}"])
    if r.returncode:
        raise OracleError(f"powershell failed rc={r.returncode}: {r.stderr.strip()}")
    return r.stdout


def alive() -> bool:
    return _ssh(["echo ok"]).stdout.strip() == "ok"


@dataclass
class CompileResult:
    name: str          # source stem
    fxp: bytes | None  # compiled output, None if compilation produced nothing
    err: str           # contents of the .err file, empty when clean

    @property
    def ok(self) -> bool:
        return self.fxp is not None and not self.err


def driver_script(bench: str, in_zip: str, out_zip: str, driver: str,
                  compile_as: int | None = None) -> str:
    """Build the PowerShell guest script for one compile batch.

    Extracted from compile_dir so its load-bearing string-construction properties are
    testable without the VM. Two properties keep single-file batches alive:

    - Get-ChildItem output is coerced with @(...). Without it $cmds is a SCALAR for a
      one-file batch and ($cmds + 'QUIT') string-concatenates into "COMPILE x.prgQUIT";
      VFP then waits forever on a file named x.prgQUIT. Batches of two or more masked
      this for the harness's entire life.
    - 'QUIT' is appended as its own array element — a separate driver line — never glued
      onto the last COMPILE argument.
    """
    as_clause = (" + ' AS %d'" % compile_as) if compile_as else ""
    return rf"""
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path '{bench}' | Out-Null
Expand-Archive -Path {in_zip} -DestinationPath '{bench}' -Force
# @() forces an array even for a single file: otherwise $cmds is a scalar and
# ($cmds + 'QUIT') string-concatenates into "COMPILE x.prgQUIT", which hangs VFP on a
# missing filename. Batches of two or more files masked this since the harness was written.
$cmds = @(Get-ChildItem '{bench}\*.prg' | ForEach-Object {{ 'COMPILE ' + $_.FullName{as_clause} }})
Set-Content {driver}.prg -Value ($cmds + 'QUIT') -Encoding ascii
Start-Process '{VFP}' -ArgumentList '-cC:\oracle\config.fpw','-t','{driver}.prg' -Wait | Out-Null
Compress-Archive -Path '{bench}\*' -DestinationPath {out_zip}
Remove-Item -Recurse -Force '{bench}' -EA SilentlyContinue
"""


def compile_dir(src_dir: Path, compile_as: int | None = None) -> dict[str, CompileResult]:
    """Compile every .prg in src_dir on the oracle. One VFP invocation for the whole batch.

    Transfers both ways as a single zip — per-file scp costs a round trip each and dominates
    wall-clock once the corpus passes a few dozen files.

    Callers driving the VM concurrently MUST hold foxlift.vmlock: one licensed VFP serves
    every lane, and unlocked overlap surfaces as unexplained compile errors in whichever
    batch lost the race — hours of phantom debugging that is not in the decoder.
    """
    prgs = sorted(src_dir.glob("*.prg"))
    if not prgs:
        return {}

    # A unique remote workspace per batch: concurrent compile_dir calls would otherwise clobber
    # each other's zips, bench dir and driver program on the guest. The fresh directory also
    # retires the stale-.fxp gotcha structurally — nothing from a previous run can be re-run.
    rid = uuid.uuid4().hex[:8]
    bench = rf"C:\oracle\bench_{rid}"
    in_zip = f"C:/oracle/in_{rid}.zip"
    out_zip = f"C:/oracle/out_{rid}.zip"
    driver = rf"C:\oracle\_bench_{rid}"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        up = td / "in.zip"
        shutil.make_archive(str(up.with_suffix("")), "zip", src_dir)
        _scp(str(up), f"{VM}:{in_zip}")

        powershell(driver_script(bench, in_zip, out_zip, driver,
                                 compile_as=compile_as))

        down = td / "out.zip"
        _scp(f"{VM}:{out_zip}", str(down))
        got = td / "out"
        shutil.unpack_archive(str(down), str(got))

        # the guest reports .FXP/.ERR uppercase; index case-insensitively by stem
        by_stem: dict[str, dict[str, Path]] = {}
        for f in got.iterdir():
            by_stem.setdefault(f.stem.lower(), {})[f.suffix.lower()] = f

        results = {}
        for prg in prgs:
            slot = by_stem.get(prg.stem.lower(), {})
            fxp = slot.get(".fxp")
            err = slot.get(".err")
            results[prg.stem] = CompileResult(
                name=prg.stem,
                fxp=fxp.read_bytes() if fxp else None,
                err=err.read_text(errors="replace").strip() if err else "",
            )
        return results
