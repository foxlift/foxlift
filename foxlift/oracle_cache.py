# ABOUTME: Content-addressed store in front of the VFP9 compile oracle's batch compiler.
# ABOUTME: A key covers the source bytes, the file name, COMPILE AS and the guest's identity.

"""The compile-result store.

`oracle.compile_dir` pays about 0.52s per file plus 4.9s per batch to the guest
(docs/ORACLE.md). Nothing about that cost is unavoidable when the input has not
changed: the same source bytes, compiled by the same vfp9.exe under the same
driver script and the same config.fpw, produce the same statement frames every
time. This module remembers the outcome so the second run is free.

What the key covers, and why each part is in it:

- the **source bytes** exactly as they are shipped to the guest;
- the **file name**, because the compiler embeds the source path in the output.
  `p1.prg` and `p01.prg` compile to outputs of different length even from
  identical text (docs/ORACLE.md), and the authored population holds 18 source
  blobs shared by 36 different program names — without the name in the key one
  of them would be served the other's `.fxp`;
- the `COMPILE AS` argument or its absence;
- the **oracle identity**: the sha256 of the driver-script template, and the
  guest's `vfp9.exe` hash and size and `C:\\oracle\\config.fpw` contents, read
  once per process over the existing PowerShell channel. A guest that cannot be
  read has no identity, and then the store is not used at all.

What is never stored: a file whose text names `#INCLUDE` or `SET PROCEDURE`,
whose result depends on files the key cannot see; and a batch the guest cut
short, which returns neither an `.fxp` nor an `.err` and is not an outcome.

`FOXLIFT_ORACLE_CACHE=<dir>` moves the store; `FOXLIFT_ORACLE_NOCACHE=1`
bypasses it, which is the negative control every instrument can invoke.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

SCHEMA = "foxlift-oracle-cache/1"
CONFIG_FPW = r"C:\oracle\config.fpw"
DEFAULT_DIR = "~/.foxlift-oracle-cache"

# A source that pulls in text the key cannot see is compiled every time.
_UNCACHEABLE = re.compile(rb"#\s*include|set\s+procedure", re.IGNORECASE)

_IDENTITY: str | None = None  # read once per process, on first success


def store_dir() -> Path:
    return Path(os.environ.get("FOXLIFT_ORACLE_CACHE")
                or DEFAULT_DIR).expanduser()


def bypassed() -> bool:
    return os.environ.get("FOXLIFT_ORACLE_NOCACHE", "").strip() not in ("", "0")


def cacheable(raw: bytes) -> bool:
    """False for a source whose result depends on files the key cannot see."""
    return _UNCACHEABLE.search(raw) is None


def guest_identity(powershell, vfp_path: str) -> str:
    """`<vfp9 sha256> <vfp9 size> <config.fpw base64>`, read from the guest."""
    out = powershell(
        "$f = Get-Item -LiteralPath '%s'\n"
        "$h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash\n"
        "$c = [Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))\n"
        "Write-Output ($h + ' ' + $f.Length + ' ' + $c)\n"
        % (vfp_path, CONFIG_FPW))
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if not lines:
        raise ValueError("guest returned no identity line")
    parts = lines[-1].split(" ")
    if len(parts) != 3 or len(parts[0]) != 64 or not parts[1].isdigit():
        raise ValueError("guest identity line is not <sha> <size> <config>")
    base64.b64decode(parts[2], validate=True)  # a truncated read fails here
    return lines[-1]


def identity(powershell, driver_script, vfp_path: str) -> str:
    """The oracle identity, computed once per process and cached on success."""
    global _IDENTITY
    if _IDENTITY is None:
        guest = guest_identity(powershell, vfp_path)
        driver = hashlib.sha256(driver_script(
            r"C:\oracle\bench_identity", "C:/oracle/in_identity.zip",
            "C:/oracle/out_identity.zip",
            r"C:\oracle\_bench_identity").encode("utf-8")).hexdigest()
        _IDENTITY = hashlib.sha256(
            ("%s\ndriver=%s\nguest=%s\n" % (SCHEMA, driver, guest))
            .encode("utf-8")).hexdigest()
    return _IDENTITY


def forget_identity() -> None:
    """Drop the per-process identity. For tests and for a guest that changed."""
    global _IDENTITY
    _IDENTITY = None


class Store:
    """A directory of entries named by key. No database, no daemon."""

    def __init__(self, root: Path, oracle_identity: str,
                 compile_as: int | None):
        self.root = root
        self.identity = oracle_identity
        self.compile_as = compile_as

    def key(self, name: str, raw: bytes) -> str:
        h = hashlib.sha256()
        h.update(("%s\n" % SCHEMA).encode("utf-8"))
        h.update(("identity=%s\n" % self.identity).encode("utf-8"))
        h.update(("compile_as=%s\n" % ("" if self.compile_as is None
                                       else self.compile_as)).encode("utf-8"))
        h.update(b"name=" + name.encode("utf-8", "surrogateescape") + b"\n")
        h.update(("source=%s\n" % hashlib.sha256(raw).hexdigest())
                 .encode("utf-8"))
        return h.hexdigest()

    def _paths(self, key: str):
        d = self.root / key[:2]
        return d, d / (key + ".json"), d / (key + ".fxp")

    def load(self, name: str, raw: bytes):
        """`(fxp, err)` for a stored outcome, or None. Never raises."""
        _, meta_path, fxp_path = self._paths(self.key(name, raw))
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, ValueError):
            return None
        # The identity is already inside the key; re-reading it here means a
        # store carried over from another guest can never be believed by
        # accident, whatever produced the file names.
        if meta.get("identity") != self.identity:
            return None
        fxp = None
        if meta.get("fxp_bytes") is not None:
            try:
                fxp = fxp_path.read_bytes()
            except OSError:
                return None
            if len(fxp) != meta["fxp_bytes"]:
                return None
        err = meta.get("err") or ""
        if fxp is None and not err:
            return None
        return fxp, err

    def save(self, name: str, raw: bytes, fxp: bytes | None, err: str) -> bool:
        """Store one real outcome. False when there is nothing to store."""
        if fxp is None and not (err or "").strip():
            return False  # the guest cut the batch short: not an outcome
        key = self.key(name, raw)
        d, meta_path, fxp_path = self._paths(key)
        d.mkdir(parents=True, exist_ok=True)
        # The .fxp lands before the .json that vouches for it, so a torn write
        # leaves an unreadable entry rather than a readable half-entry.
        if fxp is not None:
            tmp = fxp_path.with_suffix(".fxp.tmp")
            tmp.write_bytes(fxp)
            os.replace(tmp, fxp_path)
        meta = {
            "schema": SCHEMA,
            "name": name,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "compile_as": self.compile_as,
            "identity": self.identity,
            "fxp_bytes": None if fxp is None else len(fxp),
            "err": err or "",
            "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        tmp = meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, indent=1) + "\n")
        os.replace(tmp, meta_path)
        return True


def open_store(compile_as, powershell, driver_script, vfp_path: str):
    """`(store, off_reason)`. `store` is None whenever it must not be used."""
    if bypassed():
        return None, "nocache"
    try:
        ident = identity(powershell, driver_script, vfp_path)
    except Exception as e:  # noqa: BLE001 - the guest is the only authority
        # Loud, not silent: a store keyed on a guessed identity would serve
        # results from a compiler that is no longer the one in the room.
        print("oracle-cache: no oracle identity (%s: %s) — store not used"
              % (type(e).__name__, e), flush=True)
        return None, "identity"
    root = store_dir()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print("oracle-cache: %s is not writable (%s) — store not used"
              % (root, e), flush=True)
        return None, "store"
    return Store(root, ident, compile_as), None


def receipt(files: int, hits: int, misses: int, stored: int,
            off: str | None) -> str:
    return ("oracle-cache: files=%d hits=%d misses=%d stored=%d%s"
            % (files, hits, misses, stored, "" if off is None else " off=" + off))


def ship_dir(src_dir: Path, wanted, staging: Path) -> Path:
    """The directory to zip up: `src_dir` itself, or a copy minus the hits.

    Non-`.prg` files travel either way — a batch may carry headers or data the
    compile needs, and dropping them would change what the guest sees.
    """
    keep = {p.name for p in wanted}
    if keep == {p.name for p in src_dir.glob("*.prg")}:
        return src_dir
    staging.mkdir(parents=True, exist_ok=True)
    for f in sorted(src_dir.iterdir()):
        if f.is_dir():
            shutil.copytree(f, staging / f.name)
        elif f.suffix.lower() != ".prg" or f.name in keep:
            shutil.copy2(f, staging / f.name)
    return staging
