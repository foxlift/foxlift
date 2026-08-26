# ABOUTME: Per-axes reporting with fixed denominators — repo x variant x code page x artifact.
# ABOUTME: Every rate leaves here as numerator/denominator/criterion; gold_mismatch is always surfaced.

"""Per-axes reporting for foxlift scores and structural facts.

PLAN.md requires numbers reported PER REPOSITORY, PER CONTAINER VARIANT and PER CODE PAGE,
never aggregate-only, with fixed denominators. This module is the single place those tables
are built, so honesty rules are enforced once:

- every rate is a :class:`Rate` carrying its own denominator and pass criterion;
- a record that fails, is missing, or is unparsable STAYS in the denominator and lands in an
  explicit failure bucket (a skipped case is never a passing case);
- the gold_mismatch bucket (:mod:`foxlift.gold_mismatch`) is surfaced in every rendered
  report, and :func:`partition` keeps those pairs out of measured numerators;
- the development-sample denominator is encoded, not folklore:
  n=300 of the 5,893 unique development pairs, seed 42, ordered by pair_id ascending then
  ``random.Random(42).sample`` (see :data:`DEV_SAMPLE_RULE`). The gold-validation run used
  the same rule with n=200, which is byte-for-byte a prefix of the n=300 draw (measured,
  see tests).

The module is VM-free: it aggregates summaries. Anything needing the oracle lives elsewhere.
Run ``python3 -m foxlift.report`` for the phase-2 scoreboard from the frozen run artifacts
(also VM-free); pass ``--benchmark-json build/benchmark.json`` to additionally check whether
the frozen dev sample can still be redrawn from the current freeze.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from foxlift import gold_mismatch

# --- the fixed dev-sample denominator -------------------------------------------------

DEV_SPLIT = "development"
DEV_SAMPLE_N = 300
DEV_SEED = 42
DEV_POPULATION = 5893          # measured 2026-08-23 from build/benchmark.json (dominant repo only)
GOLD_VALIDATION_N = 200        # the earlier gold-validation draw, same rule

DEV_SAMPLE_RULE = (
    f"sorted by pair_id ascending, then random.Random({DEV_SEED}).sample(ordered, "
    f"min(n, population)); dev population {DEV_POPULATION} unique pairs ({DEV_SPLIT} split); "
    f"phase-2 uses n={DEV_SAMPLE_N}, gold-validation used n={GOLD_VALIDATION_N} which equals "
    f"the first {GOLD_VALIDATION_N} draws of the n={DEV_SAMPLE_N} sample (measured)"
)


def select_dev_sample(pair_ids, n: int = DEV_SAMPLE_N, seed: int = DEV_SEED) -> list[str]:
    """The frozen sampling rule. Deterministic; caps at the population."""
    ordered = sorted(str(p) for p in pair_ids)
    return random.Random(seed).sample(ordered, min(n, len(ordered)))


# --- axes ------------------------------------------------------------------------------

#: Axis name -> extractor over a pair/row mapping. Order fixes table order.
AXES = {
    "repository": lambda r: (r.get("repos") or r.get("repo") or ["?"]) if isinstance(
        r.get("repos"), list) else (r.get("repos") or r.get("repo") or "?"),
    "container_variant": lambda r: r.get("magic_hex") or r.get("variant") or "?",
    "code_page": lambda r: r.get("code_page_mark") or r.get("cp_mark") or "?",
    "artifact_type": lambda r: r.get("artifact_type") or r.get("artifact") or "?",
}


def axis_values(record: dict, axis: str, axes: dict | None = None) -> list[str]:
    """Values of one axis for one record; [] when the axis is not recorded for this record
    (the table then states how many rows lack the axis — it never invents a value).
    ``axes`` overrides the standard :data:`AXES` map (multi-label axes such as the
    phase-4 blocked-schema ranking pass their own extractor)."""
    v = (axes or AXES)[axis](record)
    if v in (None, "", "?"):
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, "", "?")] or []
    return [str(v)]


# --- rates -----------------------------------------------------------------------------

@dataclass
class Rate:
    """A number that cannot travel without its criterion and denominator."""

    numerator: int
    denominator: int
    criterion: str

    @property
    def pct(self) -> float:
        return 100.0 * self.numerator / self.denominator if self.denominator else 0.0

    def render(self) -> str:
        if not self.denominator:
            return f"{self.numerator} (count; {self.criterion})"
        return (f"{self.numerator}/{self.denominator} = {self.pct:.1f}% "
                f"({self.criterion})")


# --- aggregation -----------------------------------------------------------------------

@dataclass
class AxisTable:
    """One axis's table: every value present in the data, fixed per-value denominator."""

    axis: str
    denominator_criterion: str
    rows: list[dict]                      # sorted; each has value, records, counters, rates
    total_records: int
    records_missing_axis: int = 0

    def render_markdown(self) -> str:
        lines = [f"### Per {self.axis.replace('_', ' ')}",
                 "",
                 f"Denominator: {self.denominator_criterion}",
                 ""]
        if self.records_missing_axis:
            lines.append(f"({self.records_missing_axis} of {self.total_records} records do "
                         f"not record this axis and appear in no row below; totals that "
                         f"need the full denominator are stated separately.)")
            lines.append("")
        cols = ["value", "records"]
        counters: set[str] = set()
        for r in self.rows:
            counters.update(r["counters"])
        counter_names = sorted(counters)
        cols += counter_names
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "---|" * len(cols))
        for r in self.rows:
            cells = [str(r["value"]), str(r["records"])]
            cells += [str(r["counters"].get(c, 0)) for c in counter_names]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
        for r in self.rows:
            if r["rates"]:
                lines.append(f"- **{r['value']}**: "
                             + "; ".join(rate.render() for rate in r["rates"]))
        if not any(r["rates"] for r in self.rows):
            lines.append("- (no oracle-run outcome columns present: structural counts only)")
        lines.append("")
        return "\n".join(lines)


def aggregate(records: list[dict], axis: str,
              counters: dict[str, callable],
              criteria: dict[str, str],
              denominator_criterion: str,
              rate_deltas: dict[str, callable] | None = None,
              rate_criteria: dict[str, str] | None = None,
              axes: dict | None = None) -> AxisTable:
    """Aggregate records by one axis value.

    ``counters``: name -> predicate(record). Every record increments its axis value's
    denominator exactly once per axis value it carries (a pair spanning two repositories
    counts once in each), whatever the predicates say — exclusions must happen upstream via
    :func:`gold_mismatch.partition`, never by dropping records here.

    ``rate_deltas``: name -> fn(record) -> (numerator_delta, denominator_delta), for
    statement-level quantities where one record contributes many statements. The deltas
    accumulate per axis-value bucket and surface as Rates with their own criteria —
    a record with zero statements moves neither side.

    ``axes``: optional replacement extractor map (same shape as :data:`AXES`). A multi-label
    axis returns SEVERAL values per record and the record then counts once per value — the
    schema-impact ranking uses this so a method blocked by three schemas is attributed to
    all three without becoming three methods anywhere.
    """
    buckets: dict[str, dict] = {}
    total = 0
    records_seen = 0
    records_missing = 0
    for rec in records:
        records_seen += 1
        hit_any = False
        for value in axis_values(rec, axis, axes):
            hit_any = True
            b = buckets.setdefault(value, {"records": 0, "counters": {}, "deltas": {}})
            b["records"] += 1
            total += 1
            for name, pred in counters.items():
                try:
                    hit = bool(pred(rec))
                except Exception:
                    hit = False
                b["counters"][name] = b["counters"].get(name, 0) + int(hit)
            for name, fn in (rate_deltas or {}).items():
                try:
                    num, den = fn(rec)
                except Exception:
                    num, den = 0, 0
                cur_num, cur_den = b["deltas"].get(name, (0, 0))
                b["deltas"][name] = (cur_num + int(num), cur_den + int(den))
        if not hit_any:
            records_missing += 1
    rows = []
    for value in sorted(buckets):
        b = buckets[value]
        rates = [
            Rate(b["counters"].get(name, 0), b["records"], criteria[name])
            for name in sorted(criteria)
            if name in counters
        ]
        rates += [
            Rate(num, den, (rate_criteria or {}).get(
                name, f"rate '{name}' (see run criterion)"))
            for name, (num, den) in sorted(b["deltas"].items())
        ]
        rows.append({"value": value, "records": b["records"],
                     "counters": b["counters"], "rates": rates})
    return AxisTable(axis=axis, denominator_criterion=denominator_criterion,
                     rows=rows, total_records=records_seen,
                     records_missing_axis=records_missing)


# --- score-overlay semantics (frozen phase-2 run format) --------------------------------

def outcome_bucket(row: dict) -> str:
    """Classify one phase-2 run row into an honest, mutually exclusive bucket.

    The denominator never changes: every sampled row lands in exactly one bucket, and the
    pass bucket is 'canonical_pass'. Mirrors run_phase2.py's m{} fields.

    '0 non-empty sections' is its own bucket (no_code_sections): an empty module is not a
    method-directory failure — the frozen n=300 run holds 3 such rows. Lumping them into
    method_directory overstated that bucket (STATUS printed 83; the artifact's
    multi-section keys alone sum to 82 once empty modules are split out).
    """
    m = row.get("m") or {}
    if m.get("canonical"):
        return "canonical_pass"
    fail = m.get("fail") or ""
    if fail.startswith("0 non-empty sections"):
        return "no_code_sections"
    if fail.startswith("lift"):
        return "lift_unsupported"
    if fail.startswith("emit-compile"):
        return "compile_failed"
    if fail.startswith("canonical"):
        return "canonical_mismatch"
    if "non-empty sections" in fail:
        return "method_directory"
    if fail.startswith("unparsed"):
        return "unparsed"
    if fail == "record not found":
        return "record_not_found"
    if fail:
        return "other:" + fail.split(":")[0][:40]
    # No fail marker and no canonical flag: the row never reached a verdict.
    return "no_verdict"


def score_counters():
    """Counters/criteria for phase-2-style runs. Criteria match docs/STATUS.md verbatim.

    Statement-level quantities are NOT counters: a statement is not boolean per record.
    They travel as rate_deltas (see aggregate) so each axis row accumulates the true
    numerator AND denominator instead of a meaningless zero column.
    """
    counters = {
        "compiled_clean": lambda r: bool((r.get("m") or {}).get("compiled")),
        "canonical_pass": lambda r: bool((r.get("m") or {}).get("canonical")),
    }
    criteria = {
        "compiled_clean": "emitted source compiles clean on the oracle",
        "canonical_pass": "frames byte-equal AND symbol tables equal via comparator",
    }
    return counters, criteria


def stmt_rate_deltas():
    """Per-record (numerator, denominator) deltas for statement-level rates.

    A record that failed to parse contributes (0, 0) to all of these — its statements are
    unknowable — but it still sits in every ROW denominator and in an explicit failure
    bucket, so missing input can never improve a rate.

    Two decode rates are carried because the published figure's criterion is weaker than
    it sounds, and hiding that would repeat the exact defect this lane exists to prevent:
    - statements_decoded_incl_macro: run_phase2.py's convention (macros counted as
      decoded). This is the criterion behind the published 19.4%.
    - statements_decoded_schema_only: macros excluded from BOTH sides. This is the stricter
      criterion; on the frozen run it is 2,052/11,144 = 18.4%, not 19.4%.
    - macro_verbatim: count-only (denominator 0), never folded into decode coverage.
    """
    def _m(r):
        return r.get("m") or {}

    def _schema_only(r):
        m = _m(r)
        total = m.get("stmts", 0)
        macro = m.get("macro", 0)
        return (m.get("decoded", 0) - macro, total - macro)

    return {
        "statements_decoded_incl_macro": lambda r: (_m(r).get("decoded", 0),
                                                    _m(r).get("stmts", 0)),
        "statements_decoded_schema_only": _schema_only,
        "macro_verbatim": lambda r: (_m(r).get("macro", 0), 0),
    }


STMT_RATE_CRITERIA = {
    "statements_decoded_incl_macro":
        "statements decoding under thin-slice schemas, all sections of all sampled "
        "records, WITH verbatim macro statements counted as decoded (run_phase2.py "
        "convention; the criterion behind the published 19.4%)",
    "statements_decoded_schema_only":
        "same, but verbatim macro statements are excluded from BOTH numerator and "
        "denominator (stricter criterion; lower than the published figure by design)",
    "macro_verbatim":
        "01/b4 verbatim statements re-emitted as their exact stored bytes (preserved by "
        "construction); count only, never folded into decode coverage",
}


def summarize_run(run: dict) -> dict:
    """Aggregate a phase-2-format run summary: totals + per-axis tables + buckets.

    Denominators are FIXED: every row of run['rows'] counts toward every table, keyed by
    the axes it carries. Nothing is excluded upstream except gold_mismatch pairs, which are
    partitioned out of the measured rows and reported separately (still counted).
    """
    rows = run.get("rows") or []
    measured_rows, excluded = gold_mismatch.partition(rows)

    buckets: dict[str, int] = {}
    for r in rows:
        b = outcome_bucket(r)
        buckets[b] = buckets.get(b, 0) + 1

    stmt_total = sum((r.get("m") or {}).get("stmts", 0) for r in rows)
    stmt_decoded = sum((r.get("m") or {}).get("decoded", 0) for r in rows)
    stmt_macro = sum((r.get("m") or {}).get("macro", 0) for r in rows)

    counters, criteria = score_counters()
    deltas = stmt_rate_deltas()
    all_criteria = dict(criteria)
    all_criteria.update(STMT_RATE_CRITERIA)
    denom = (f"all sampled rows on this axis (fixed; failures stay in the denominator); "
             f"sample rule: {DEV_SAMPLE_RULE}")
    tables = [
        aggregate(measured_rows, axis, counters, criteria, denom,
                  rate_deltas=deltas, rate_criteria=STMT_RATE_CRITERIA)
        for axis in AXES
    ]

    n = len(rows)
    canonical = buckets.get("canonical_pass", 0)
    summary = {
        "sample": {
            "n": n,
            "rule": run.get("sample", {}).get("rule", DEV_SAMPLE_RULE),
            "seed": run.get("sample", {}).get("seed", DEV_SEED),
        },
        # PLAN/CLAUDE rule, encoded: this exact sample is the phase-4 widening lead list
        # (probes/schema_harvest/IMPACT.md was produced FROM it), so nothing measured on
        # it may ever be presented as held-out or generalization evidence.
        "held_out": False,
        "held_out_reason": ("development sample; the SAME n=300 draw is the schema-harvest "
                            "lead-list population (probes/schema_harvest/IMPACT.md) — data "
                            "used to infer schemas can never be counted as held-out"),
        "denominator_note": ("complete_method_pass shares the canonical_pass denominator "
                             "exactly; unsupported statements FAIL their method and are "
                             "never removed from the denominator"),
        "totals": {
            "sampled": Rate(n, n, "fixed sample denominator").render(),
            "compiled_clean": Rate(sum(1 for r in rows
                                       if (r.get("m") or {}).get("compiled")), n,
                                   "emitted source compiles clean on the oracle").render(),
            "canonical_pass": Rate(canonical, n,
                                   "frames byte-equal AND symbol tables equal via "
                                   "comparator, among ALL sampled").render(),
            "complete_method_pass": Rate(canonical, n,
                                         "SAME denominator as canonical_pass — a method "
                                         "with any unsupported statement fails here and is "
                                         "never dropped from the denominator").render(),
            "statement_decode_incl_macro": Rate(stmt_decoded, stmt_total,
                                                STMT_RATE_CRITERIA[
                                                    "statements_decoded_incl_macro"]).render(),
            "statement_decode_schema_only": Rate(stmt_decoded - stmt_macro,
                                                 stmt_total - stmt_macro,
                                                 STMT_RATE_CRITERIA[
                                                     "statements_decoded_schema_only"]).render(),
            "macro_verbatim": (f"{stmt_macro} statements "
                               f"({STMT_RATE_CRITERIA['macro_verbatim']})"),
        },
        "statements": {
            "total": stmt_total,
            "decoded_incl_macro": stmt_decoded,
            "decoded_schema_only": stmt_decoded - stmt_macro,
            "macro_verbatim": stmt_macro,
        },
        "failure_buckets": dict(sorted(buckets.items())),
        "gold_mismatch_excluded": {
            "count": len(excluded),
            "note": ("these sampled pairs are measured-stale gold; they keep their place in "
                     "the sample denominator above and are listed in the exclusions section"),
            "pair_ids": sorted(str((r.get('pair_id'))) for r, _ in excluded),
        },
        "tables": tables,
    }
    return summary


# --- structural-summary semantics (freeze/format facts) ---------------------------------

STRUCTURAL_COUNTERS = {
    "with_objcode": lambda rec: bool(rec.get("objcode_bytes")),
    "macro_statements_present": lambda rec: bool(rec.get("macro_statements")),
}


def summarize_structural(pairs: list[dict]) -> dict:
    """Per-axis structural counts over unique benchmark pairs.

    Expects one dict per pair carrying: repos/magic_hex/code_page_mark/artifact_type/split
    (benchmark.json fields) plus optional recomputed facts (objcode_bytes, statements,
    macro_statements). Missing facts simply leave their counters at zero — they are counts,
    never rates pretending to be scores.
    """
    denom = ("unique pairs on this axis (deduped by normalised-source+OBJCODE sha256; "
             "per freeze_benchmark.py rule)")
    counters = dict(STRUCTURAL_COUNTERS)
    criteria = {
        "with_objcode": "non-empty OBJCODE blob present",
        "macro_statements_present": ">=1 verbatim-text (01/b4) statement in OBJCODE",
    }
    tables = [aggregate(pairs, axis, counters, criteria, denom) for axis in AXES]
    split_counts: dict[str, int] = {}
    for p in pairs:
        s = str(p.get("split", "?"))
        split_counts[s] = split_counts.get(s, 0) + 1
    return {
        "unique_pairs": len(pairs),
        "unique_pairs_criterion": ("distinct (normalised METHODS, raw OBJCODE) sha256 pairs"),
        "splits": dict(sorted(split_counts.items())),
        "tables": tables,
    }


# --- sample-staleness gate ---------------------------------------------------------------
#
# The published phase-2 rates are facts about the FROZEN run. They are only reproducible
# from the current tree while the freeze that produced the frozen sample is still the
# freeze the tree generates. Code-page work changed the pair_id scheme and six corpus
# tables became unreadable (GBK decode errors), so the regenerated dev population shrank
# (5,893 -> 5,802 measured 2026-08-23) and the redrawn seed-42 sample shared only 10/300
# ids with the frozen one. This gate exists so that drift is PRINTED, never silent.

def dev_pair_ids_from_benchmark(bench: dict) -> list[str]:
    """Development-split pair ids from a freeze_benchmark.py output dict."""
    return sorted(p["pair_id"] for p in bench.get("pairs", [])
                  if p.get("split") == DEV_SPLIT)


def sample_drift(current_dev_ids, frozen_dev_ids, frozen_draw,
                 n: int = DEV_SAMPLE_N, seed: int = DEV_SEED) -> dict:
    """Compare the frozen draw against a redraw under the current population.

    ``frozen_dev_ids``: the full development population at freeze time;
    ``frozen_draw``: the frozen seed-{seed} sample itself. Drift is a REPORT, never an
    exception — silently hiding it is exactly the failure mode this module prevents.
    """
    current_dev_ids = sorted(str(p) for p in current_dev_ids)
    frozen_dev_ids = sorted(str(p) for p in frozen_dev_ids)
    frozen_draw = [str(p) for p in frozen_draw]
    redraw = select_dev_sample(current_dev_ids, n=min(n, len(current_dev_ids)), seed=seed)
    overlap = len(set(redraw) & set(frozen_draw))
    same_population = (len(current_dev_ids) == len(frozen_dev_ids)
                       and set(current_dev_ids) == set(frozen_dev_ids))
    if same_population and set(redraw) == set(frozen_draw):
        verdict = ("reproducible: same population, redrawn sample identical to the "
                   "frozen draw")
    elif same_population:
        verdict = (f"population unchanged but redrawn sample differs "
                   f"({overlap}/{len(frozen_draw)} shared) — sampling rule drifted")
    else:
        verdict = (f"STALE: current freeze holds {len(current_dev_ids)} development pairs "
                   f"vs {len(frozen_dev_ids)} frozen; redrawn seed-{seed} sample shares only "
                   f"{overlap}/{len(frozen_draw)} ids with the frozen sample. Rates "
                   f"measured on the frozen run describe THAT population, not this tree's.")
    return {
        "frozen_population": len(frozen_dev_ids),
        "current_population": len(current_dev_ids),
        "sample_n": len(frozen_draw),
        "shared_sample_ids": overlap,
        "same_population": same_population,
        "verdict": verdict,
    }


def render_staleness(drift: dict | None) -> str:
    """Markdown section stating whether the frozen figures can be redrawn today."""
    lines = ["## Sample staleness", ""]
    if drift is None:
        lines += ["NOT CHECKED: no benchmark.json was available, so it is UNKNOWN whether "
                  "the frozen dev sample can be redrawn from the current tree. Treat the "
                  "rates above as historical until this check runs.", ""]
        return "\n".join(lines)
    d = drift
    lines += [
        f"- frozen dev population: {d['frozen_population']}",
        f"- current-tree dev population: {d['current_population']}",
        f"- shared ids in seed-{DEV_SEED} n={d['sample_n']} draws: "
        f"{d['shared_sample_ids']}/{d['sample_n']}",
        f"- verdict: **{d['verdict']}**",
        "",
    ]
    return "\n".join(lines)


# --- rendering --------------------------------------------------------------------------

GOLD_MISMATCH_SECTION_TITLE = "## gold_mismatch exclusions (structural, never normalisations)"


def render_gold_mismatch_section(extra_pair_ids=None) -> str:
    """The bucket section appended to EVERY report."""
    s = gold_mismatch.summary()
    lines = [GOLD_MISMATCH_SECTION_TITLE, "",
             f"{s['count']} pairs measured stale ({s['criterion']}).",
             "They are EXCLUDED from gold status explicitly; they must never become "
             "normalisation rules.", "",
             "| pair_id | example | cluster | mismatch type | measured reason |",
             "|---|---|---|---|---|"]
    seen = set()
    for p in s["pairs"]:
        lines.append(f"| `{p['pair_id']}` | {p['example']} | {p['cluster']} "
                     f"| {p['mismatch_type']} | {p['measured_reason']} |")
        seen.add(p["pair_id"])
    if extra_pair_ids:
        unexpected = [pid for pid in extra_pair_ids if pid not in seen]
        if unexpected:
            lines.append("")
            lines.append(f"UNEXPECTED gold_mismatch ids encountered in data: "
                         f"{', '.join(f'`{u}`' for u in unexpected)} — investigate before "
                         f"trusting any rate computed over them.")
    lines.append("")
    return "\n".join(lines)


def render_report(title: str, sections: list[str], notes: list[str] | None = None) -> str:
    parts = [f"# {title}", ""]
    parts += sections
    parts.append(render_gold_mismatch_section())
    if notes:
        parts.append("## Notes")
        parts.append("")
        parts += [f"- {n}" for n in notes]
        parts.append("")
    return "\n".join(parts)


def render_scoreboard(summary: dict) -> str:
    """Markdown scoreboard from summarize_run output: totals, buckets, per-axis tables."""
    lines = ["## Headline rates (fixed denominators; criterion stated beside every number)",
             ""]
    for name, rendered in summary["totals"].items():
        lines.append(f"- **{name}**: {rendered}")
    lines += ["", f"Denominators: {summary['denominator_note']}", ""]
    if summary.get("held_out") is False:
        lines += [f"NOT held-out: {summary['held_out_reason']}", ""]

    lines += ["## Failure buckets (mutually exclusive; sum to the sample denominator)", "",
              "| bucket | rows |", "|---|---:|"]
    for b, c in summary["failure_buckets"].items():
        lines.append(f"| {b} | {c} |")
    total_rows = summary["sample"]["n"]
    lines.append(f"| *(total)* | {sum(summary['failure_buckets'].values())} "
                 f"(sample n={total_rows}) |")
    lines.append("")

    for t in summary["tables"]:
        lines.append(t.render_markdown())

    gm = summary["gold_mismatch_excluded"]
    lines += [f"{len(gm['pair_ids'])} of {total_rows} sampled rows are measured-stale gold "
              f"pairs (gold_mismatch); they keep their place in every denominator above.",
              ""]
    return "\n".join(lines)


def _default_fixtures() -> Path:
    return Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "report"


def main(argv=None) -> int:
    """`python3 -m foxlift.report` — the phase-2 scoreboard, VM-free.

    Reproduces the published complete-method pass from the FROZEN run artifacts and prints
    its criterion. With --benchmark-json it additionally checks sample staleness against
    the current tree's freeze. Exit codes: 0 reproducible-or-checked; 3 staleness gate
    found drift (--strict turns that into failure).
    """
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(prog="foxlift.report",
                                 description="Phase-2 scoreboard with fixed denominators")
    ap.add_argument("--run", type=Path, default=_default_fixtures() / "phase2_run.json",
                    help="phase-2 run JSON (default: frozen fixture)")
    ap.add_argument("--frozen-ids", type=Path,
                    default=_default_fixtures() / "dev_pair_ids.txt",
                    help="frozen development pair ids, one per line")
    ap.add_argument("--benchmark-json", type=Path,
                    default=Path("build/benchmark.json"),
                    help="current freeze output; staleness is NOT CHECKED when missing")
    ap.add_argument("--strict", action="store_true",
                    help="exit 3 when the staleness gate finds drift or cannot check")
    args = ap.parse_args(argv)

    run = _json.loads(args.run.read_text())
    summary = summarize_run(run)
    sections = [render_scoreboard(summary)]

    notes = [
        "VM-free reproduction from the FROZEN run artifacts — this re-aggregates a "
        "recorded run; it does not re-run phase 2 against the corpus.",
    ]

    drift = None
    if args.benchmark_json.is_file():
        bench = _json.loads(args.benchmark_json.read_text())
        frozen_ids = [l.strip() for l in args.frozen_ids.read_text().splitlines()
                      if l.strip()]
        frozen_sample = _json.loads(
            args.frozen_ids.with_name("frozen_dev_sample.json").read_text())
        drift = sample_drift(dev_pair_ids_from_benchmark(bench), frozen_ids,
                             frozen_sample["draw_300_in_order"])
        stale = not drift["same_population"] \
            or drift["shared_sample_ids"] < drift["sample_n"]
        if stale:
            notes.append("STALENESS: the frozen sample can NOT be redrawn from the current "
                         "freeze — see the Sample staleness section. Re-measure before "
                         "comparing any new rate to these.")
    else:
        notes.append(f"staleness NOT CHECKED ({args.benchmark_json} not found).")

    out = render_report(
        f"Phase-2 scoreboard — complete-method pass {summary['totals']['complete_method_pass'].split(' ')[0]}",
        sections + [render_staleness(drift)], notes)
    print(out)

    if args.strict and (drift is None or "reproducible" not in drift["verdict"]):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
