#!/usr/bin/env python3
# VM-free tests for the resync invariant (CLAUDE.md: "an unrecognised construct must cost
# one statement, never the module"). Harness lives in foxlift/resync.py; these tests pin
# its guarantees: builder integrity, per-mutation-family behaviour, lifter discipline,
# explicit accounting of lost spans, and campaign determinism.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from foxlift import container, lifter, resync


# --- builder integrity -------------------------------------------------------------------

def test_builder_roundtrips_exactly():
    """The synthetic baseline must parse to exactly what was built — a broken baseline
    would make every mutation verdict meaningless."""
    buf = resync.build_module()
    m = container.parse(buf, 0)
    assert len(m.sections) == 2
    assert [len(sec.statements) for sec in m.sections] == [2, 2]
    # every statement lies inside its own section's span
    for sec in m.sections:
        for st in sec.statements:
            assert sec.offset <= st.offset and st.offset + st.declared <= sec.end + 2
    # verbatim macro survived as text; compiled statements kept their streams
    texts = [st.text for st in m.statements if st.text is not None]
    assert texts == ["? &x"]
    assert all(st.known for st in m.statements)
    # symbol table after EACH section (context-matrix rule)
    assert all(sec.symbols_parsed and sec.symbols[:2] == ["X", "Y"] for sec in m.sections)


def test_builder_supports_u32_framing_sections():
    m = container.parse(resync.build_module(wide_flags=[False, True]), 0)
    assert [s.framing for s in m.sections] == ["u16", "u32"]
    assert len(m.statements) == 4


def test_fixture_seeds_are_modules():
    for name, buf in sorted(resync.fixture_seeds().items()):
        assert container.is_module(buf, 0), name
        m = container.parse(buf, 0)
        assert m.sections, f"{name}: fixture lost its sections"


# --- lifter discipline -------------------------------------------------------------------

def test_deep_nesting_is_unsupported_never_recursion_error():
    """Corrupt/hostile input must degrade to Unsupported — a stack blowout is one
    unrecognised construct, not a crash (the invariant, lifter edition)."""
    for depth in (10, 200, 700):
        try:
            lifter.dec_statement(resync.deep_nesting_stream(depth), ["X"])
        except lifter.Unsupported:
            pass  # fine at any depth: lift or Unsupported, nothing else
        except RecursionError:
            raise AssertionError(f"raw RecursionError escaped at depth {depth}")


def test_deep_nesting_lifts_at_shallow_depth():
    """The nesting shape itself is valid modulus code — small depth must actually lift,
    proving the Unsupported at depth comes from the recursion budget, not a broken shape."""
    out = lifter.dec_statement(resync.deep_nesting_stream(2), ["X"])
    assert out is not None


# --- mutation families -------------------------------------------------------------------

def test_zero_cost_families_change_no_accounting():
    """Opcode flips and zeroed symbol operands are semantic damage only: statement count
    and every untouched statement must be byte-identical."""
    for kind, mut in (("flip_opcode", resync.mut_flip_opcode),
                      ("zero_symbol_operand", resync.mut_zero_symbol_operand)):
        import random
        rng = random.Random(7)
        buf = resync.build_module()
        hits = 0
        for _ in range(10):
            got = mut(buf, rng)
            if got is None:
                continue
            mbuf, lo, hi, k = got
            assert k == kind
            resync.check_mutant(buf, mbuf, lo, hi, kind, f"direct/{kind}")
            hits += 1
        assert hits >= 5, f"{kind}: mutation never fired on the synthetic seed"


def test_corrupt_length_costs_at_most_its_own_section_and_is_traced():
    """THE invariant: one corrupted length prefix must never cost the module, and the loss
    must be explicit (a rejection traced in the damaged span), never silent."""
    import random
    rng = random.Random(11)
    buf = resync.build_module()
    base = container.parse(buf, 0)
    base_by_sec = [len(s.statements) for s in base.sections]
    fired = 0
    for _ in range(30):
        got = resync.mut_corrupt_length(buf, rng)
        if got is None:
            continue
        mbuf, lo, hi, kind = got
        resync.check_mutant(buf, mbuf, lo, hi, kind, f"direct/corrupt_length@{lo:#x}")
        fired += 1
    assert fired >= 10


def test_truncate_returns_intact_prefix_without_raising():
    import random
    rng = random.Random(13)
    buf = resync.build_module()
    fired = 0
    for _ in range(20):
        got = resync.mut_truncate(buf, rng)
        if got is None:
            continue
        mbuf, lo, hi, kind = got
        resync.check_mutant(buf, mbuf, lo, hi, kind, f"direct/truncate@{lo:#x}")
        m = container.parse(mbuf, 0)
        assert all(st.offset < lo for st in m.statements)
        fired += 1
    assert fired >= 10


def test_break_terminator_yields_known_false_statement_not_a_drop():
    """An unrecognisable SHAPE inside a surviving section must surface as an explicit
    known=False statement — silently dropping it would be the inverted-denominator bug
    one layer down."""
    import random
    rng = random.Random(17)
    buf = resync.build_module()
    base = container.parse(buf, 0)
    # corrupt the fe of the FIRST statement of section 0 (a 2-statement section: the
    # section survives, one statement goes unknown-shaped)
    sec0 = base.sections[0]
    st0 = sec0.statements[0]
    fe_pos = st0.offset + st0.declared - 1
    assert buf[fe_pos] == container.END_STMT
    mbuf = buf[:fe_pos] + b"\x77" + buf[fe_pos + 1:]
    resync.check_mutant(buf, mbuf, fe_pos, fe_pos + 1, "break_terminator",
                        "direct/break_terminator")
    m = container.parse(mbuf, 0)
    assert len(m.sections) == 2, "section must survive one unknown-shaped statement"
    unknown = [st for st in m.statements if not st.known]
    assert len(unknown) == 1 and unknown[0].offset == st0.offset


def test_overrun_section_is_rejected_locally():
    import random
    rng = random.Random(19)
    buf = resync.build_module()
    fired = 0
    for _ in range(10):
        got = resync.mut_overrun_section(buf, rng)
        if got is None:
            continue
        mbuf, lo, hi, kind = got
        resync.check_mutant(buf, mbuf, lo, hi, kind, f"direct/overrun@{lo:#x}")
        fired += 1
    assert fired >= 5


# --- the campaign ------------------------------------------------------------------------

def test_full_fuzz_campaign_deterministic_and_clean():
    """The whole battery over synthetic + fixture seeds. Same seed twice must give the
    identical summary — failures reproduce from the seed in the violation message."""
    r1 = resync.run_fuzz(rounds_per_kind=6, seed=20260823)
    r2 = resync.run_fuzz(rounds_per_kind=6, seed=20260823)
    assert r1 == r2
    assert r1["mutants"] >= 100, f"campaign too weak: {r1}"
    for kind in ("flip_opcode", "corrupt_length", "truncate", "break_terminator",
                 "zero_symbol_operand", "overrun_section"):
        assert r1["by_kind"].get(kind, 0) > 0, f"{kind} never fired"


def test_classify_hits_total_on_mutants():
    import random
    rng = random.Random(23)
    buf = resync.build_module()
    for _ in range(15):
        mut = rng.choice(resync.MUTATIONS)
        got = mut(buf, rng)
        if got is None:
            continue
        mbuf, lo, hi, kind = got
        classes = container.classify_hits(mbuf)
        assert all(c.status in ("parsed", "empty", "rejected") for c in classes)
        assert sum(1 for c in classes) == len(container.find_modules(mbuf))


def test_reject_trace_is_opt_in_and_off_by_default():
    """Default path must stay allocation-free (corpus sweeps parse 24k+ modules)."""
    import inspect
    sig = inspect.signature(container.sections)
    assert sig.parameters["reject_trace"].default is None
    buf = resync.build_module()
    assert container.sections(buf) == container.sections(buf, 0, len(buf))
    traced = []
    container.sections(buf, reject_trace=traced)
    assert traced  # and with a list passed, accounting happens


def main():
    fails = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except AssertionError as e:
                print("FAIL", name, repr(e)[:200])
                fails.append(name)
            except Exception as e:  # noqa: BLE001
                print("ERROR", name, repr(e)[:200])
                fails.append(name)
    print(len(fails), "failures")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
