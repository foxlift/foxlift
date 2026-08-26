# ABOUTME: Produces demo/receipts.json — the measured round-trip evidence for the demo project.
# ABOUTME: Authored source -> VFP9 oracle compile -> foxlift CLI -> VFP9 recompile -> compare.
#
#     python3 demo/make_receipts.py        # needs the VFP9 oracle VM (utmctl start Windows)
#
# The product path is exercised exactly as a user would type it: `python3 -m foxlift inspect`
# and `python3 -m foxlift decompile` run as subprocesses and their exit codes are recorded.
# Compilation runs on a real VFP9 through foxlift.oracle.compile_dir (one batched invocation
# per round, held under foxlift.vmlock). The comparison criterion is the project's canonical
# one: per-section statement frames byte-equal AND symbol tables equal (foxlift.compare).
#
# A negative control rides in the recompile batch: one literal of one program is mutated, and
# the comparator MUST report that pair unequal — otherwise every equal verdict above it would
# prove nothing about the instrument.

import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from foxlift import compare, container, oracle, vmlock  # noqa: E402

SRC = ROOT / "demo" / "src"
OUT = ROOT / "build" / "demo"
RECEIPTS = ROOT / "demo" / "receipts.json"

CONTROL_STEM = "partsbin"
CONTROL_OLD = "INSERT INTO parts VALUES ('AX-0048', 'Hex bolt M6', 500, 0.50)"
CONTROL_NEW = "INSERT INTO parts VALUES ('AX-0048', 'Hex bolt M6', 501, 0.50)"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_cli(*args):
    """Run the real product CLI the way a user would, capturing output and exit code."""
    r = subprocess.run([sys.executable, "-m", "foxlift", *args],
                       capture_output=True, text=True, cwd=ROOT, timeout=120)
    return r


def compile_batch(src_dir: Path, label: str):
    t0 = time.time()
    with vmlock.hold(label=label):
        results = oracle.compile_dir(src_dir)
    wall = round(time.time() - t0, 1)
    for stem, res in sorted(results.items()):
        if not res.ok:
            raise SystemExit(f"oracle compile FAILED for {stem}: {res.err}")
    return results, wall


def section_verdicts(orig_fxp: bytes, recompiled_fxp: bytes):
    """Canonical per-section comparison of two standalone compiles."""
    mo, mr = container.parse(orig_fxp), container.parse(recompiled_fxp)
    if len(mo.sections) != len(mr.sections):
        return [], {"equal": False,
                    "reason": f"section count {len(mo.sections)} != {len(mr.sections)}"}
    rows = []
    all_equal = True
    for i, (a, b) in enumerate(zip(mo.sections, mr.sections)):
        c = compare.compare_sections(a, b)
        rows.append({"section": i, "statements": len(a.statements),
                     "equal": c.equal, "reason": c.reason})
        all_equal = all_equal and c.equal
    agg = compare.compare_compiled(orig_fxp, recompiled_fxp)
    return rows, {"equal": all_equal and agg.equal,
                  "reason": agg.reason if agg.equal else f"aggregate: {agg.reason}"}


def main():
    if not oracle.alive():
        raise SystemExit("oracle VM not alive; start it with: utmctl start Windows")

    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                          text=True, cwd=ROOT).stdout.strip()

    if OUT.exists():
        shutil.rmtree(OUT)
    orig_dir, fxp_dir = OUT / "orig", OUT / "fxp"
    dec_dir, re_dir, refxp_dir = OUT / "decompiled", OUT / "re_src", OUT / "re_fxp"
    for d in (orig_dir, fxp_dir, dec_dir, re_dir, refxp_dir):
        d.mkdir(parents=True)

    programs = sorted(p.stem for p in SRC.glob("*.prg"))
    for stem in programs:
        shutil.copy(SRC / f"{stem}.prg", orig_dir / f"{stem}.prg")

    # --- round 1: compile the authored source, one batched oracle invocation ---
    res1, wall1 = compile_batch(orig_dir, "v1-demo")
    for stem in programs:
        (fxp_dir / f"{stem}.fxp").write_bytes(res1[stem].fxp)

    receipts = {
        "provenance": {
            "date": date.today().isoformat(),
            "repo_commit": head,
            "compiler": "Visual FoxPro 9 (SP2) driven via foxlift.oracle.compile_dir, "
                        "one batched invocation per round under foxlift.vmlock",
            "criterion": "per-section statement frames byte-equal AND symbol tables equal "
                         "(foxlift.compare); raw .fxp container bytes are never compared — "
                         "they embed compile timestamps and the source path",
            "compile_wall_s": {"round1": wall1},
        },
        "programs": {},
    }

    # --- the product path: inspect + decompile each artifact, record exit codes ---
    failures = []
    for stem in programs:
        art = f"build/demo/fxp/{stem}.fxp"
        entry = {"authored_source": f"demo/src/{stem}.prg",
                 "authored_source_sha256": sha256((SRC / f"{stem}.prg").read_bytes()),
                 "compiled_fxp_sha256": sha256(res1[stem].fxp)}

        r = run_cli("inspect", art, "--json")
        entry["inspect"] = {"command": f"python3 -m foxlift inspect {art} --json",
                            "exit_code": r.returncode,
                            "result": json.loads(r.stdout)}

        outdir = f"build/demo/decompiled/{stem}"
        r = run_cli("decompile", art, "-o", outdir, "--json")
        entry["decompile"] = {"command": f"python3 -m foxlift decompile {art} -o {outdir} --json",
                              "exit_code": r.returncode,
                              "result": json.loads(r.stdout)}
        if r.returncode != 0:
            failures.append(stem)
            for meta in sorted((ROOT / outdir).glob("module_*/meta.json")):
                for s in json.loads(meta.read_text()).get("sections", []):
                    if not s.get("lifted"):
                        print(f"NOT LIFTED {stem} section {s['index']}: {s.get('reason')}")

        lifted = ROOT / outdir / "module_000000" / "source.prg"
        entry["decompiled_source_sha256"] = sha256(lifted.read_bytes())
        shutil.copy(lifted, re_dir / f"{stem}.prg")
        receipts["programs"][stem] = entry

    if failures:
        raise SystemExit(f"decompile did not exit 0 for: {failures} — fix before receipts")

    # --- negative control: a mutated recompile input MUST compare unequal ---
    ctrl_src = (re_dir / f"{CONTROL_STEM}.prg").read_text()
    ctrl_mut = ctrl_src.replace(CONTROL_OLD, CONTROL_NEW)
    if ctrl_mut == ctrl_src:
        raise SystemExit("negative control mutation found nothing to change")
    (re_dir / "control_mutated.prg").write_text(ctrl_mut)

    # --- round 2: recompile the decompiled output, one batched oracle invocation ---
    res2, wall2 = compile_batch(re_dir, "v1-demo")
    receipts["provenance"]["compile_wall_s"]["round2"] = wall2

    for stem in programs:
        (refxp_dir / f"{stem}.fxp").write_bytes(res2[stem].fxp)
        entry = receipts["programs"][stem]
        entry["recompiled_fxp_sha256"] = sha256(res2[stem].fxp)
        rows, verdict = section_verdicts(res1[stem].fxp, res2[stem].fxp)
        entry["sections"] = rows
        entry["roundtrip"] = verdict

    ctrl = compare.compare_compiled(res1[CONTROL_STEM].fxp, res2["control_mutated"].fxp)
    receipts["negative_control"] = {
        "description": f"one literal mutated ({CONTROL_OLD!r} -> {CONTROL_NEW!r}) "
                       "and recompiled; the comparator must say unequal",
        "equal": ctrl.equal, "reason": ctrl.reason,
        "as_expected": not ctrl.equal,
    }

    n_sections = sum(len(e["sections"]) for e in receipts["programs"].values())
    n_equal = sum(1 for e in receipts["programs"].values()
                  for s in e["sections"] if s["equal"])
    receipts["summary"] = {
        "programs": len(programs),
        "sections_compared": n_sections,
        "sections_byte_identical": n_equal,
        "all_inspect_exit_0": all(e["inspect"]["exit_code"] == 0
                                  for e in receipts["programs"].values()),
        "all_decompile_exit_0": all(e["decompile"]["exit_code"] == 0
                                    for e in receipts["programs"].values()),
        "negative_control_unequal": not ctrl.equal,
    }

    RECEIPTS.write_text(json.dumps(receipts, indent=1) + "\n")
    print(json.dumps(receipts["summary"], indent=1))
    for stem, e in receipts["programs"].items():
        print(f"{stem}: decompile exit {e['decompile']['exit_code']}, "
              f"roundtrip {'EQUAL' if e['roundtrip']['equal'] else 'UNEQUAL: ' + e['roundtrip']['reason']}")
    print(f"wrote {RECEIPTS}")


if __name__ == "__main__":
    main()
