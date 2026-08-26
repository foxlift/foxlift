# ABOUTME: The explicit gold_mismatch bucket PLAN.md phase 0 requires.
# ABOUTME: Stale METHODS/OBJCODE pairs live here as data — they must NEVER become normalisation rules.

"""gold_mismatch — the structural exclusion list for stale gold pairs.

PLAN.md phase 0: "Mismatches go in an explicit ``gold_mismatch`` bucket — never into a new
normalisation." This module IS that bucket. The six pairs below were measured stale by the
2026-08-23 gold-validation run (docs/STATUS.md §"Gold validation"): their stored METHODS text,
recompiled standalone on the VFP9 oracle, does NOT canonically match the stored OBJCODE.

The exclusion is structural, not conventional:
- every report built through :mod:`foxlift.report` surfaces this list verbatim;
- :func:`partition` splits any result stream so an excluded pair cannot silently enter a
  numerator or denominator;
- nothing in this file feeds a normalisation path — there is none to feed.

Measured origin of every field (criterion stated per row): oracle run
``build/gold_validation_gbk.json`` in the main repo — stratified sample of 200 development
pairs (seed 42, sorted-by-pair_id then random.sample) staged as standalone PRGs, compiled
clean in 160/197 = 81.2% of staged cases, compared via ``compare.compare_module_frames``
(frames byte-equal AND symbol tables equal). These 6 are the 6/160 = 3.8% mismatches among
cleanly compiled records. They are facts about the CORPUS's stored pairs, not about foxlift.
"""

from dataclasses import dataclass

@dataclass(frozen=True)
class GoldMismatchEntry:
    """One measured-stale pair, with its measurement provenance attached."""

    pair_id: str                 # full 16-hex benchmark pair id
    example: str                 # "path::object" as recorded in benchmark.json, repo prefix dropped
    artifact: str                # "scx" | "vcx"
    category: str                # provenance of the table the record lives in
    mismatch_type: str           # coarse kind: what differs between recompiled source and OBJCODE
    measured_reason: str         # verbatim comparator reason from the gold-validation run
    criterion: str               # the pass criterion under which it was measured


ENTRIES = (
    GoldMismatchEntry(
        pair_id="08cd502a53069ccd",
        example="class/xfrxlib.vcx::cbozoom",
        artifact="vcx",
        category="third-party (xFRX)",
        mismatch_type="section_statement_count",
        measured_reason="original section 4: statement count 7 != 4",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
    GoldMismatchEntry(
        pair_id="573e750045013227",
        example="class/xfrxlib.vcx::cmdPage",
        artifact="vcx",
        category="third-party (xFRX)",
        mismatch_type="frame_byte",
        measured_reason="original section 2: frame 0 differs",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
    GoldMismatchEntry(
        pair_id="01575b9998b75f42",
        example="class/xfrxlib.vcx::cmdFind",
        artifact="vcx",
        category="third-party (xFRX)",
        mismatch_type="frame_byte",
        measured_reason="original section 2: frame 0 differs",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
    GoldMismatchEntry(
        pair_id="27525db827dae6c4",
        example="class/_reports.vcx::_outputdialog",
        artifact="vcx",
        category="VFP system classlib",
        mismatch_type="section_statement_count",
        measured_reason="original section 31: statement count 12 != 22",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
    GoldMismatchEntry(
        pair_id="4440716eede3282e",
        example="Frms/hetong.scx::cdCancel",
        artifact="scx",
        category="application code",
        mismatch_type="frame_byte",
        measured_reason="original section 2: frame 3 differs",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
    GoldMismatchEntry(
        pair_id="b2ce8063977b34e9",
        example="Frms/checkmatinput.scx::txtDateID",
        artifact="scx",
        category="application code",
        mismatch_type="no_nonempty_sections",
        measured_reason="original has no non-empty sections",
        criterion="compare_module_frames: frames byte-equal AND symbol tables equal, "
                  "200-pair dev sample (seed 42), 160/197 compiled clean",
    ),
)

BY_ID = {e.pair_id: e for e in ENTRIES}

#: Set membership test for full ids.
GOLD_MISMATCH_IDS = frozenset(BY_ID)

#: The named cluster: three stale pairs in ONE third-party classlib (see docs/xfrxlib-cluster.md).
XFRXLIB_PAIR_IDS = frozenset(
    e.pair_id for e in ENTRIES if "/xfrxlib." in e.example
)


def resolve_pair_id(pair_id: str) -> GoldMismatchEntry | None:
    """Resolve a full id OR an unambiguous prefix (the form used in prose/docs).

    Returns the entry, or None when the id is not in the bucket or the prefix matches
    nothing/more than one entry (never guesses).
    """
    if not pair_id:
        return None
    hit = BY_ID.get(pair_id)
    if hit is not None:
        return hit
    matches = [e for pid, e in BY_ID.items() if pid.startswith(pair_id)]
    return matches[0] if len(matches) == 1 else None


def is_gold_mismatch(pair_id: str) -> bool:
    """True when the id (full or unambiguous prefix) is in the bucket."""
    return resolve_pair_id(pair_id) is not None


def cluster_of(entry_or_id) -> str:
    """Cluster label for reporting: 'xfrxlib.vcx', '_reports.vcx' or 'application'."""
    entry = entry_or_id if isinstance(entry_or_id, GoldMismatchEntry) \
        else BY_ID.get(entry_or_id)
    if entry is None:
        raise KeyError(entry_or_id)
    if "/xfrxlib." in entry.example:
        return "xfrxlib.vcx"
    if "/_reports." in entry.example:
        return "_reports.vcx"
    return "application"


def partition(records):
    """Split a result stream around the bucket.

    ``records``: iterable of mappings (or objects) carrying ``pair_id``. Returns
    ``(measured, excluded)`` — ``excluded`` items are ``(record, entry)`` tuples. Anything
    returned from ``measured`` is guaranteed free of gold_mismatch pairs, so a caller cannot
    silently fold a stale pair into a rate.
    """
    measured, excluded = [], []
    for rec in records:
        pid = rec["pair_id"] if isinstance(rec, dict) else getattr(rec, "pair_id")
        entry = resolve_pair_id(pid) if isinstance(pid, str) else None
        if entry is not None:
            excluded.append((rec, entry))
        else:
            measured.append(rec)
    return measured, excluded


def summary() -> dict:
    """Report-ready summary. Every count carries its criterion."""
    clusters: dict[str, int] = {}
    types: dict[str, int] = {}
    for e in ENTRIES:
        clusters[cluster_of(e)] = clusters.get(cluster_of(e), 0) + 1
        types[e.mismatch_type] = types.get(e.mismatch_type, 0) + 1
    return {
        "bucket": "gold_mismatch",
        "count": len(ENTRIES),
        "criterion": ("stale = stored METHODS recompiled standalone does NOT canonically match "
                      "stored OBJCODE (compare_module_frames); measured on 160/197 cleanly "
                      "compiled records of the 200-pair dev sample (seed 42), 2026-08-23"),
        "never_becomes_normalisation": True,
        "clusters": dict(sorted(clusters.items())),
        "mismatch_types": dict(sorted(types.items())),
        "pairs": [
            {
                "pair_id": e.pair_id,
                "example": e.example,
                "artifact": e.artifact,
                "category": e.category,
                "cluster": cluster_of(e),
                "mismatch_type": e.mismatch_type,
                "measured_reason": e.measured_reason,
            }
            for e in ENTRIES
        ],
    }
