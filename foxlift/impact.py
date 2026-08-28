# ABOUTME: Phase-4 impact ranking — which missing schemas block how many complete methods.
# ABOUTME: VM-free; multi-label attribution; solo vs combination split; per-repo always shown.

"""Phase-4 widening lead list, measured — not guessed.

PLAN.md §4: widening is ordered by *how many complete methods each missing schema blocks*,
not by table completeness. Until now that ranking did not exist reproducibly: the old
probes/schema_harvest/IMPACT.md was produced by a build/ script that was never committed,
and run_phase2.py attributes only the FIRST Unsupported reason per method
(`fail = "lift: " + str(e)[:70]`). This module replaces both with measured, attributed data:

- **Multi-label attribution**: every statement of a method is decoded AND emitted
  individually (:func:`lifter.statement_source`), so a method blocked by three missing
  schemas is attributed to all three — while counting as ONE method everywhere. Nothing is
  credited only to the first failure hit, and no method is double-counted.
- **Solo vs combination**: ``solo`` = methods whose blocker set is exactly this schema
  (fixing the schema alone unblocks them); ``combo`` = methods where it appears alongside
  others (fixing it alone unblocks nothing there). The two numbers order differently and
  both are published.
- **Per repository, always**: the dominant corpus repo is ~94% of the gold pairs, so an aggregate ranking
  mostly measures one vendor's house style. A schema that tops the aggregate but exists in
  one repo is exactly the trap the per-repo tables make visible.
- **Reuse, not parallel counting**: denominators come from :func:`foxlift.report.select_dev_sample`
  (the frozen seed-42 n=300 rule), buckets from :func:`foxlift.report.outcome_bucket`,
  exclusions from :func:`foxlift.gold_mismatch.partition`, rates as
  :class:`foxlift.report.Rate`. Where this run and the frozen scoreboard can be compared
  (shared pair ids, VM-free-decidable buckets) they ARE compared, and any disagreement is
  printed as the bug it probably is.

Everything runs without the VM: corpus payloads are read locally, no oracle call exists here.

What this module does NOT claim: it cannot reproduce the oracle-only verdicts
(compile/canonical pass) of the frozen run; it describes the CURRENT freeze's development
population, whose overlap with the frozen sample is measured and printed, never assumed.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

from foxlift import container, dbf, gold_mismatch, lifter, report, schemas

DEFAULT_CORPUS = Path.home() / "work" / "foxlift-root" / "foxlift-corpus"
DEFAULT_BENCH = Path("build/benchmark.json")

# --- language coverage vs the ALANGUAGE() denominator ---------------------------------------
#
# Lane A enumerated the full VFP language on the oracle: 174 commands, 445 functions.
# Coverage below counts what THIS decoder can decode AND emit, each entry citing its
# measured bytecode shape; partial forms are flagged rather than rounded up.

COMMANDS_TOTAL = 174
FUNCTIONS_TOTAL = 445

SUPPORTED_COMMANDS = {
    # keyword: (status, note)  -- status "full" = all measured corpus forms handled;
    # "partial" = a measured variant remains Unsupported (named in the note).
    "=": ("full", "54 <lv> 10 fc expr fd"),
    "STORE": ("full", "4a form"),
    "?": ("full", "02"),
    "??": ("full", "03"),
    "LOCAL": ("partial", "typed AS-clause measured; m.-prefixed names added iter.12"),
    "LPARAMETERS": ("full", "af f7/f5-0d names, ARGJOIN lists"),
    "RETURN": ("full", "bare and fc-expr forms"),
    "DIMENSION": ("full", "15 form"),
    "WITH": ("full", "a6 frame"),
    "IF": ("full", "25 frame, ELSE(1b) verified"),
    "DO CASE": ("full", "18 48 frame, CASE clauses verified; OTHERWISE unforced -> fails loudly"),
    "DO": ("full", "file/name-expr forms; DO WHILE via 18 2b"),
    "ENDDO": ("full", "1d"),
    "SKIP": ("full", "bare 48 only"),
    "SELECT (workarea)": ("full", "46 f7 sym"),
    "SELECT-SQL": ("partial", "star-projection ORDER BY INTO CURSOR only; WHERE/columns unforced"),
    "REPLACE": ("partial", "pairs + ALL clause; FOR/FOR-clauses unforced"),
    "GO TOP": ("full", "23 29"),
    "WAIT": ("full", "WINDOW clause matrix + CLEAR + bare expr + bare TIMEOUT"),
}

SUPPORTED_FUNCTIONS = sorted(
    set(schemas.BUILTIN_ESCAPES.values())
    | set(schemas.BUILTIN_X1A.values())
    | {schemas.BUILTIN_BARE[b] for b in (
        schemas.CORPUS_ALIGNED_BARE_CLOSERS | schemas.DECODER_ENABLED_BARE
    )})

#: Buckets this VM-free run CAN decide. The oracle-only buckets (canonical_pass,
#: compile_failed, canonical_mismatch) require compiling emitted source — out of scope here.
VMFREE_DECIDABLE = {"lift_unsupported", "method_directory", "no_code_sections",
                    "unparsed", "record_not_found"}


# --- schema taxonomy -----------------------------------------------------------------------
#
# An Unsupported message names its gap, but several messages are PARAMETERISED. The
# parameter is the actionable unit of widening (one handler per lead byte / opcode /
# literal type), so the id keeps the parameter — except where the parameter is incidental
# (which index overflowed, which exception class) and the fix is one schema regardless.

_MALFORMED = re.compile(r"^malformed statement:")
_SYMBOL_INDEX = re.compile(r"^symbol index \d+ beyond table")
_TYPED_LIT = re.compile(r"^typed literal 0x([0-9a-fA-F]{2})")
_BUILTIN = re.compile(r"^builtin escape number (\d+) unmapped")


def schema_id(msg: str) -> str:
    """Normalise one Unsupported message to its missing-schema id."""
    m = msg.strip()
    if _MALFORMED.match(m):
        # The embedded text varies by exception class; robustness is ONE schema.
        return "malformed statement shape"
    if _SYMBOL_INDEX.match(m):
        return "symbol index beyond table"
    g = _TYPED_LIT.match(m)
    if g:
        return f"typed literal 0x{g.group(1).lower()}"
    g = _BUILTIN.match(m)
    if g:
        return f"builtin escape number {int(g.group(1))}"
    return m


# --- per-method attribution ------------------------------------------------------------------

def section_blockers(sec, extra_syms=None) -> set[str]:
    """EVERY missing schema a section's lift trips over — not just the first.

    The whole-section walk runs FIRST (it owns block-frame accounting: an ENDIF only
    means anything relative to its IF). Per-statement probing then adds statement-level
    gaps, SKIPPING frame sentinels whose failure is already attributable to the frame
    opener — otherwise every method with a broken IF would also fake-charge an emitter
    tuple row for each of its ENDIFs, inflating that schema's count.
    Verbatim macro statements carry no schema gap by construction.
    ``extra_syms`` extends the section's symbol table (module-wide fallback).
    """
    eff_syms = list(sec.symbols)
    if extra_syms and len(extra_syms) > len(sec.symbols):
        eff_syms = extra_syms
    ids: set[str] = set()
    try:
        lifter.lift_section(sec, syms_override=eff_syms)
        return ids                       # whole section lifts: nothing is blocked
    except lifter.Unsupported as e:
        ids.add(schema_id(str(e)))
    sentinel_leads = (bytes([lifter.S.ENDWITH]), bytes([lifter.S.ENDIF_LEAD]),
                      bytes([lifter.S.ELSE_LEAD]), bytes([lifter.S.CASE_CLAUSE]),
                      bytes([lifter.S.ENDCASE_LEAD]), bytes([lifter.S.ENDDO_LEAD]),
                      bytes([lifter.S.ENDFOR_LEAD]), bytes([lifter.S.OTHERWISE_LEAD]),
                      bytes([lifter.S.TRY_LEAD]), bytes([lifter.S.CATCH_LEAD]),
                      bytes([lifter.S.ENDTRY_LEAD]))
    for st in sec.statements:
        if st.text is not None:
            continue
        if st.stream[:1] in sentinel_leads:
            continue                     # sentinel: framed by the walk, not standalone
        try:
            lifter.statement_source(st.stream, eff_syms)
        except lifter.Unsupported as e:
            ids.add(schema_id(str(e)))
    return ids


# --- row collection (the phase-2 dev score, VM-free, with full attribution) -------------------

def collect_rows(bench: dict, corpus_root: Path,
                 sample_ids: list[str] | None = None) -> list[dict]:
    """Run the dev-score pipeline MINUS the oracle over the fixed dev sample — one row
    PER NON-EMPTY SECTION (per METHOD), not per record.

    Phase-2's harness only scored single-section records; ordinary .scx/.vcx forms
    (several methods each) were binned ``method_directory`` and never reached the lifter.
    The container reader has handled nested sections with per-section symbol tables since
    phase 1a, so this iterates every non-empty section and resolves operand indexes
    against the OWNING section's table (pinned by tests/test_cluster.py).

    Row units:
    - ``method`` rows: one per non-empty section — ``m.blockers``, ``m.vmfree_lift_ok``
      or ``m.fail``; ``section_index``/``record_sections`` describe the record shape;
    - ``record_failure`` rows: input that yields no liftable method at all —
      record not found / unparsed / zero non-empty sections (kept explicit so the
      fixed sample denominator stays auditable).

    Oracle verdicts (compile/canonical) are NOT re-run here.
    """
    pairs = [p for p in bench.get("pairs", []) if p.get("split") == report.DEV_SPLIT]
    by_id = {p["pair_id"]: p for p in pairs}
    ids = sample_ids if sample_ids is not None else report.select_dev_sample(
        [p["pair_id"] for p in pairs])
    rows = []
    records_by_path: dict[Path, dict[str, bytes]] = {}
    codec_by_path: dict[Path, str | None] = {}
    for pid in ids:
        p = by_id.get(pid)
        if p is None:                      # cannot happen for ids drawn from this bench
            rows.append({"pair_id": pid, "unit": "record_failure",
                         "m": {"fail": "record not found"}})
            continue
        rel, objname = p["example"].split("::", 1)
        code = None
        artifact_path = corpus_root / rel
        try:
            if artifact_path not in records_by_path:
                records = {}
                for name, _src, record_code in dbf.objcode_records(artifact_path):
                    records.setdefault(name, record_code)
                records_by_path[artifact_path] = records
                try:
                    codec_by_path[artifact_path] = dbf.table_codec(artifact_path)
                except Exception:  # noqa: BLE001 — missing/unreadable table: latin-1
                    codec_by_path[artifact_path] = None
            code = records_by_path[artifact_path].get(objname)
        except Exception:                  # noqa: BLE001 — unreadable input stays a row
            records_by_path[artifact_path] = {}
            codec_by_path[artifact_path] = None
            code = None
        meta = {
            "pair_id": pid,
            "repos": p.get("repos") or ["?"],
            "variant": p.get("magic_hex") or "?",
            "code_page_mark": p.get("code_page_mark") or "?",
            "artifact_type": p.get("artifact_type") or "?",
            "example": p["example"],
        }
        if not code:
            rows.append({**meta, "unit": "record_failure",
                         "m": {"fail": "record not found"}})
            continue
        try:
            codec = codec_by_path.get(artifact_path)
            mod = (container.parse(code, codec=codec) if codec
                   else container.parse(code))
        except ValueError as e:
            rows.append({**meta, "unit": "record_failure",
                         "m": {"fail": f"unparsed: {e}"}})
            continue
        non_empty = [s for s in mod.sections if not s.is_empty]
        if not non_empty:
            rows.append({**meta, "unit": "record_failure",
                         "m": {"fail": "0 non-empty sections"}})
            continue
        # Module-wide symbol fallback: multi-section records sometimes reference
        # symbols beyond their own section's parsed table (VFP uses a shared namespace
        # for some constructs). Build a union table as fallback for resolution.
        all_syms = []
        seen_names = set()
        for sec0 in non_empty:
            for nm in sec0.symbols:
                if nm not in seen_names:
                    seen_names.add(nm)
                    all_syms.append(nm)

        for si, sec in enumerate(non_empty):
            total = decoded = macro = 0
            for st in sec.statements:
                total += 1
                if st.text is not None:
                    macro += 1
                    decoded += 1
                    continue
                try:
                    lifter.dec_statement(st.stream, sec.symbols)
                    decoded += 1
                except lifter.Unsupported:
                    pass
            m = {"stmts": total, "decoded": decoded, "macro": macro}
            # Per-statement blocking uses section-local symbols first; on failure,
            # retries with module-wide union before declaring blocked.
            blockers = sorted(section_blockers(sec, extra_syms=all_syms))
            m["blockers"] = blockers
            if blockers:
                m["fail"] = "lift: " + "; ".join(blockers)[:70]
            else:
                m["vmfree_lift_ok"] = True   # oracle verdicts NOT re-run
            rows.append({**meta, "unit": "method", "section_index": si,
                         "record_sections": len(non_empty), "m": m})
    return rows


# --- ranking ----------------------------------------------------------------------------------
#
# Multi-label axis: one record counts ONCE PER blocking schema (its denominator entry per
# schema), never twice within one schema. Solo/combo predicates ride on the same row data.

SCHEMA_AXIS = {"blocked_schema": lambda r: (r.get("m") or {}).get("blockers") or []}

SCHEMA_COUNTERS = {
    "solo_methods": lambda r: len(set((r.get("m") or {}).get("blockers") or [])) == 1,
}

SCHEMA_CRITERIA = {
    "solo_methods": "methods whose ENTIRE blocker set is this one schema — fixing it "
                    "alone unblocks exactly these",
}

SCHEMA_DENOM_CRITERION = (
    "complete methods blocked by this schema, multi-label: a method blocked by N schemas "
    "counts once in EACH of their denominators and once per schema nowhere else; "
    "'records' column = blocked methods; failures stay attributed")


def _bucket_of(row: dict) -> str:
    """Bucket for one row of the per-method run.

    Method rows: ``lift_unsupported`` or ``lifted_vmfree``. Record rows: the input-level
    failures (record not found / unparsed / no_code_sections). ``method_directory`` is NO
    LONGER a bucket — a multi-section record is a RECORD SHAPE (record_sections > 1), not
    a failure; its sections are scored as methods like any other.
    """
    m = row.get("m") or {}
    if row.get("unit") == "method":
        return "lift_unsupported" if m.get("blockers") else "lifted_vmfree"
    fail = m.get("fail", "")
    if fail == "0 non-empty sections":
        return "no_code_sections"
    if fail == "record not found":
        return "record_not_found"
    if fail.startswith("unparsed"):
        return "unparsed"
    return "other_record_failure"


def _collapse_records(rows: list[dict]) -> dict:
    """Derive OLD phase-2 per-record verdicts from per-method rows (frozen comparability).

    A record maps to: its failure bucket when input yielded no liftable method;
    ``method_directory`` when it has several non-empty sections (the old harness skipped
    those); otherwise its single section's lift outcome."""
    by_pid = {}
    order = []
    for r in rows:
        pid = r["pair_id"]
        if pid not in by_pid:
            by_pid[pid] = {"unit": None, "methods": [], "meta": r}
            order.append(pid)
        e = by_pid[pid]
        if r.get("unit") == "method":
            e["unit"] = "method"
            e["methods"].append(r)
        else:
            e["unit"] = "record_failure"
            e["fail"] = (r.get("m") or {}).get("fail", "")
    out = {}
    for pid in order:
        e = by_pid[pid]
        if e["unit"] == "record_failure":
            f = e["fail"]
            out[pid] = ("no_code_sections" if f.startswith("0 non-empty")
                        else "record_not_found" if f == "record not found"
                        else "unparsed" if f.startswith("unparsed") else "other")
        elif len(e["methods"]) != 1:
            out[pid] = "method_directory"
        else:
            mm = e["methods"][0]["m"]
            out[pid] = "lift_unsupported" if mm.get("blockers") else "lifted_vmfree"
    return out


def reconcile_with_frozen(rows: list[dict], frozen_run: dict) -> dict:
    """Compare this VM-free run against the frozen phase-2 run on SHARED pair ids.

    Agreement is required only where BOTH sides can decide (VMFREE_DECIDABLE). A shared id
    this run lifts cleanly but the frozen run recorded as canonical_pass/compile/canonical
    verdict is COMPATIBLE, not agreeing — the oracle decided that one, not the lifter.
    Any other mismatch is returned itemised: given identical input bytes it indicates a
    real divergence (lifter change, payload-extraction change) and must be investigated,
    never averaged away.
    """
    frozen_by_id = {}
    for r in frozen_run.get("rows") or []:
        pid = str(r.get("pair_id"))
        if pid:
            frozen_by_id.setdefault(pid, r)
    mine_records = _collapse_records(rows)
    # The disagreement table promises both sides' failure text -- it is the whole point of
    # itemising rather than averaging. Keep a pair_id -> fail map so the producer can supply it;
    # omitting it is what left render_reconciliation_md reading a key nothing set.
    mine_fail = {}
    for r in rows:
        pid = str(r.get("pair_id") or "")
        if pid and not mine_fail.get(pid):
            mine_fail[pid] = ((r.get("m") or {}).get("fail") or "")
    shared, agreements, disagreements, compatible = [], 0, [], 0
    for pid, mine in mine_records.items():
        fr = frozen_by_id.get(pid)
        if fr is None:
            continue
        theirs = report.outcome_bucket(fr)
        shared.append(pid)
        if mine == theirs:
            agreements += 1
        elif mine == "lifted_vmfree" and theirs in (
                "canonical_pass", "compile_failed", "canonical_mismatch"):
            compatible += 1
        elif mine == "method_directory":
            # EXPECTED systematic divergence since the per-method pipeline landed: the
            # old harness SKIPPED multi-section records; this one lifts their sections.
            compatible += 1
        else:
            disagreements.append({
                "pair_id": pid,
                "this_run": mine,
                "frozen": theirs,
                "this_fail": mine_fail.get(pid, ""),
                "frozen_fail": ((fr.get("m") or {}).get("fail") or ""),
            })
    return {
        "shared_ids": len(shared),
        "agreements": agreements,
        "oracle_only_compatible": compatible,
        "disagreements": disagreements,
        "criterion": ("bucket agreement on shared pair ids where both sides decide "
                      "VM-free; oracle-only frozen verdicts are counted compatible, "
                      "never as agreement"),
    }


def rank_from_rows(rows: list[dict]) -> dict:
    """Ranking tables from collected rows (pure; tests drive this without corpus/freeze)."""
    measured, excluded = gold_mismatch.partition(rows)

    denom = SCHEMA_DENOM_CRITERION
    agg = report.aggregate(measured, "blocked_schema", SCHEMA_COUNTERS,
                           SCHEMA_CRITERIA, denom, axes=SCHEMA_AXIS)

    # per-repo views: filter by the standard repository axis, then re-run the SAME
    # schema aggregation — never a hand-rolled parallel count.
    per_repo = {}
    for r in measured:
        for repo in report.axis_values(r, "repository"):
            per_repo.setdefault(repo, []).append(r)
    repo_tables = {repo: report.aggregate(recs, "blocked_schema", SCHEMA_COUNTERS,
                                          SCHEMA_CRITERIA, denom, axes=SCHEMA_AXIS)
                   for repo, recs in sorted(per_repo.items())}

    # json-friendly ranking rows with the solo/combo arithmetic spelled out
    def _rows_of(table):
        return {row["value"]: row for row in table.rows}

    agg_by_schema = _rows_of(agg)
    ranking = []
    for schema, row in sorted(agg_by_schema.items(),
                              key=lambda kv: (-kv[1]["records"], kv[0])):
        solo = row["counters"].get("solo_methods", 0)
        blocked = row["records"]
        shares = []
        for repo, t in repo_tables.items():
            rr = _rows_of(t).get(schema)
            if rr:
                shares.append((repo, rr["records"]))
        shares.sort(key=lambda x: (-x[1], x[0]))
        top_repo, top_count = shares[0] if shares else ("?", 0)
        ranking.append({
            "schema": schema,
            "blocked_methods": blocked,
            "solo_unblocks": solo,
            "combo_only": blocked - solo,
            "repos_present": sorted(repo for repo, _ in shares),
            "top_repo": top_repo,
            "top_repo_blocked": top_count,
        })

    # which COMBINATIONS actually recur — combo-only columns become actionable when the
    # pairs are known (fix two schemas together, or nothing unblocks)
    pair_counts: Counter = Counter()
    for r in measured:
        bs = sorted((r.get("m") or {}).get("blockers") or [])
        if len(bs) < 2:
            continue
        for i in range(len(bs)):
            for j in range(i + 1, len(bs)):
                pair_counts[(bs[i], bs[j])] += 1
    top_combos = [{"schemas": list(pair), "methods": n}
                  for pair, n in sorted(pair_counts.items(),
                                        key=lambda kv: (-kv[1], kv[0]))[:8]]
    method_rows = [r for r in rows if r.get("unit") == "method"]
    record_ids = {r["pair_id"] for r in rows}
    multi = sum(1 for r in method_rows if r.get("record_sections", 1) > 1
                and r.get("section_index") == 0)
    return {
        "measured_rows": len(measured),
        "gold_mismatch_excluded": sorted(str(r.get("pair_id")) for r, _ in excluded),
        "buckets": dict(sorted(Counter(_bucket_of(r) for r in rows).items())),
        "n_records": len(record_ids),
        "n_methods": len(method_rows),
        "multi_section_records": multi,
        "ranking": ranking,
        "top_combos": top_combos,
        "aggregate_table": agg,
        "repo_tables": repo_tables,
    }


def rank(bench: dict, corpus_root: Path) -> dict:
    """The full measurement: fixed dev draw -> rows -> :func:`rank_from_rows`."""
    ids = report.select_dev_sample([p["pair_id"] for p in bench.get("pairs", [])
                                    if p.get("split") == report.DEV_SPLIT])
    rows = collect_rows(bench, corpus_root, ids)
    out = rank_from_rows(rows)
    out["sample_n"] = len(rows)
    out["sample_rule"] = report.DEV_SAMPLE_RULE
    out["population_dev_pairs"] = sum(1 for p in bench.get("pairs", [])
                                      if p.get("split") == report.DEV_SPLIT)
    out["sample_n_records"] = report.DEV_SAMPLE_N
    out["rows"] = rows            # in-memory only; the CLI writes explicit keys
    return out


# --- rendering ---------------------------------------------------------------------------------

def render_ranking_md(result: dict, drift: dict | None) -> str:
    """Human-readable ranking: how to read it is part of the output, not external lore."""
    lines = [
        "# Phase-4 impact ranking — complete methods blocked per missing schema", "",
        f"Sample: {result.get('sample_n_records', result['sample_n'])} development "
        f"RECORDS — {result['sample_rule']}.",
        f"Population: {result['population_dev_pairs']} unique dev pairs in the CURRENT "
        f"freeze (build/benchmark.json); payloads read VM-free from the local corpus.",
    ]
    cov = result["coverage"]
    lines += [
        "**Language coverage vs ALANGUAGE(): "
        f"{cov['commands']['count_any_support']} of {cov['commands']['denominator']} "
        f"commands ({cov['commands']['count_full']} full, "
        f"{len(cov['commands']['supported_partial'])} partial), "
        f"{cov['functions']['count']} of {cov['functions']['denominator']} functions.** "
        "Criterion: distinct emitted keywords / mapped call ids backed by aligned stored "
        "pairs; partials name their unforced variants. NOT comparable to 'N blocking "
        "schemas': schemas are byte shapes, coverage is language elements.",
        "",
        "section of every sampled record is scored with its OWN symbol table "
        f"({result['n_methods']} methods from {result['n_records']} records; "
        f"{result['multi_section_records']} multi-section records were previously "
        "skipped whole). Complete-method pass is reported over METHODS; the pre-change "
        "series (9.3% -> 20.0% -> ... -> 34.0%) was over RECORDS and is NOT directly "
        "comparable.",
        "",
        "**How to read this ranking:**",
        "",
        "- *blocked methods*: methods whose blocker set CONTAINS the schema (multi-label; "
        "a 3-blocker method appears in three rows and in no row twice).",
        "- *solo*: subset where this schema is the ONLY blocker — fixing it alone unblocks "
        "exactly these. *combo-only* = blocked − solo: fixing it alone unblocks none of "
        "these because another gap still fails the method.",
        "- Ordering by blocked desc answers 'how much does each schema participate'; the "
        "solo column answers 'what does fixing it buy immediately'. Prefer high-solo "
        "schemas when sequencing single-schema work.",
        "- Per-repository tables follow the aggregate. A schema topping the aggregate but "
        "present in one repository measures that vendor's house style, not the corpus.",
        "",
        "## Aggregate ranking (criterion beside each column)", "",
        "Denominator per row: " + SCHEMA_DENOM_CRITERION + ".", "",
        "| blocked methods | solo | combo-only | schema |", "|---|---:|---:|---|",
    ]
    for r in result["ranking"]:
        lines.append(f"| {r['blocked_methods']} | {r['solo_unblocks']} "
                     f"| {r['combo_only']} | `{r['schema']}` |")
    total_methods = sum(1 for r in result["rows"]
                        if r.get("unit") == "method"
                        and (r.get("m") or {}).get("blockers"))
    lines += ["", f"Methods carrying ≥1 blocker: {total_methods} of {result['n_methods']} "
              f"(criterion: method rows with non-empty blocker sets; denominator = all "
              f"extracted methods). Sum of 'blocked' exceeds this whenever methods are multi-blocker "
              f"— that overlap is the point, not an error.", ""]
    if result.get("top_combos"):
        lines += ["### Most frequent blocker combinations", "",
                  "Combo-only methods are only unblocked when EVERY schema in their set "
                  "lands. The recurring pairs, by methods carrying both (multi-label):",
                  "", "| methods | combination |", "|---:|---|"]
        for c in result["top_combos"]:
            lines.append(f"| {c['methods']} | {' + '.join(f'`{s}`' for s in c['schemas'])} |")
        lines.append("")
    for repo, t in result["repo_tables"].items():
        lines += [f"### Per repository: {repo}", "", t.render_markdown()]
    lines.append(render_reconciliation_md(result))
    lines.append(report.render_staleness(drift))
    return "\n".join(lines)


def render_reconciliation_md(result: dict) -> str:
    """Bucket comparison against the frozen run — printed, never smoothed over."""
    rec = result.get("reconciliation")
    if rec is None:
        return ""
    lines = ["## Reconciliation with the frozen phase-2 scoreboard", "",
             f"- shared pair ids with the frozen n=300 draw: **{rec['shared_ids']}**",
             f"- bucket agreement where both sides decide VM-free: **{rec['agreements']}** "
             f"({rec['criterion']})",
             f"- oracle-only frozen verdicts compatible with a clean VM-free lift: "
             f"{rec['oracle_only_compatible']}"]
    if rec["disagreements"]:
        lines += ["", "DISAGREEMENTS — same pair id, different VM-free-decidable bucket. "
                  "Given identical payload bytes this indicates lifter or extraction "
                  "drift: investigate before trusting either side.", "",
                  "| pair_id | this run | frozen | this fail | frozen fail |",
                  "|---|---|---|---|---|"]
        for d in rec["disagreements"]:
            lines.append(f"| `{d['pair_id']}` | {d['this_run']} | {d['frozen']} "
                         f"| {d['this_fail'][:50]} | {d['frozen_fail'][:50]} |")
    else:
        lines += ["", "No disagreements on any shared id where both sides decide.", ""]
    lines.append("")
    return "\n".join(lines)


# --- CLI ---------------------------------------------------------------------------------------

def coverage_summary() -> dict:
    """Decode+emit coverage against lane A's ALANGUAGE() denominator.

    Criterion per command: the keyword is emitted by this decoder for at least one
    stored-pair statement shape, and every MEASURED variant of that command either lifts
    or is named as partial. Functions: escape/bare-id mapped to canonical call spelling,
    each id backed by >=1 aligned stored pair. Counts are of DISTINCT keywords/functions,
    not byte shapes."""
    full_cmds = [k for k, v in SUPPORTED_COMMANDS.items() if v[0] == "full"]
    part_cmds = [k for k, v in SUPPORTED_COMMANDS.items() if v[0] == "partial"]
    return {
        "commands": {
            "supported_full": sorted(full_cmds),
            "supported_partial": sorted(part_cmds),
            "count_full": len(full_cmds),
            "count_any_support": len(SUPPORTED_COMMANDS),
            "denominator": COMMANDS_TOTAL,
            "criterion": "distinct emitted keywords with all MEASURED variants lifting "
                         "(full) or named partial variants (partial); denominator from "
                         "lane A's ALANGUAGE() enumeration",
        },
        "functions": {
            "names": SUPPORTED_FUNCTIONS,
            "count": len(SUPPORTED_FUNCTIONS),
            "denominator": FUNCTIONS_TOTAL,
            "criterion": "escape/bare-id mapped to canonical call spelling, each id "
                          "backed by >=1 aligned stored pair; denominator from "
                          "lane A's ALANGUAGE() enumeration",
        },
    }


def main(argv=None) -> int:
    """`python3 -m foxlift.impact` — measure the phase-4 lead list, VM-free.

    Exit codes: 0 measured and rendered; 3 inputs missing (no benchmark freeze or no
    corpus) — reported, never silently skipped.
    """
    import argparse

    ap = argparse.ArgumentParser(prog="foxlift.impact",
                                 description="Phase-4 widening impact ranking (VM-free)")
    ap.add_argument("--benchmark-json", type=Path, default=DEFAULT_BENCH,
                    help="freeze_benchmark.py output (default: build/benchmark.json)")
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS,
                    help="local corpus root (default: ~/work/foxlift-root/foxlift-corpus)")
    ap.add_argument("--frozen-run", type=Path,
                    default=report._default_fixtures() / "phase2_run.json",
                    help="frozen phase-2 run for the reconciliation section")
    ap.add_argument("--frozen-ids", type=Path,
                    default=report._default_fixtures() / "dev_pair_ids.txt")
    ap.add_argument("--out", type=Path, default=Path("build/impact_ranking.json"),
                    help="where to write the machine-readable result")
    args = ap.parse_args(argv)

    problems = []
    if not args.benchmark_json.is_file():
        problems.append(f"no benchmark freeze at {args.benchmark_json} — run "
                        f"python3 freeze_benchmark.py first (VM-free)")
    if not args.corpus.is_dir():
        problems.append(f"no corpus at {args.corpus} — ./tools/fetch-corpus.sh reproduces it")
    if problems:
        for p in problems:
            print("error: " + p, file=sys.stderr)
        return 3

    bench = json.loads(args.benchmark_json.read_text())
    frozen_run = json.loads(args.frozen_run.read_text())

    result = rank(bench, args.corpus)
    frozen_ids = [l.strip() for l in args.frozen_ids.read_text().splitlines() if l.strip()]
    current_dev_ids = report.dev_pair_ids_from_benchmark(bench)
    frozen_sample = json.loads(args.frozen_ids.with_name("frozen_dev_sample.json").read_text())
    drift = report.sample_drift(current_dev_ids, frozen_ids,
                                frozen_sample["draw_300_in_order"])
    result["reconciliation"] = reconcile_with_frozen(result["rows"], frozen_run)
    result["staleness"] = drift
    result["provenance"] = {
        "command": "python3 -m foxlift.impact",
        "benchmark": str(args.benchmark_json),
        "corpus": str(args.corpus),
        "attribution": "multi-label: every statement decoded+emitted individually; "
                       "whole-section lift attempted for frame gaps",
    }

    # render and the JSON payload must see the SAME coverage figures: computing it only inside
    # the payload left render_ranking_md reading a key nothing had set (KeyError after the
    # main<-scoreboard merge -- textually clean, semantically split).
    result["coverage"] = coverage_summary()

    md = render_ranking_md(result, drift)
    print(md)

    # machine-readable payload: plain data only (AxisTable objects render, they don't serialise)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "provenance": result["provenance"],
        "coverage": result["coverage"],
        "sample_n_records": result.get("sample_n_records"),
        "n_methods": result["n_methods"],
        "n_records": result["n_records"],
        "multi_section_records": result["multi_section_records"],
        "sample_rule": result["sample_rule"],
        "population_dev_pairs": result["population_dev_pairs"],
        "measured_rows": result["measured_rows"],
        "gold_mismatch_excluded": result["gold_mismatch_excluded"],
        "buckets": result["buckets"],
        "ranking": result["ranking"],
        "top_combos": result["top_combos"],
        "reconciliation": result["reconciliation"],
        "staleness": drift,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
