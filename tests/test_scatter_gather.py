# ABOUTME: Pins the round-17 SCATTER/GATHER statement grammars against authored oracle streams.
# ABOUTME: Selector bytes 28/15/1b/c2 stay contextual beneath leads 5e/5f; other shapes fail loudly.

import pytest

from foxlift import lifter


def _source(stream, symbols=()):
    return lifter.statement_source(bytes.fromhex(stream), list(symbols))


def test_scatter_to_array_round17_stream():
    # s01_scatter_to (round17_streams.json): 'DIMENSION laRow[1]'+SCATTER TO laRow,
    # target statement 5e28f70000 with symbols [LAROW]
    assert _source("5e28f70000", ["LAROW"]) == "SCATTER TO LAROW"
    # a different symbol index resolves through the owning section's table
    assert _source("5e28f70c00",
                   ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
                    "LAITEMS"]) == "SCATTER TO LAITEMS"


def test_gather_from_array_round17_stream():
    # g01_gather_from (round17_streams.json): GATHER FROM laRow -> 5f15f70000
    assert _source("5f15f70000", ["LAROW"]) == "GATHER FROM LAROW"
    assert _source("5f15f70600", ["W1", "W2", "W3", "W4", "W5", "W6", "LAROW"]) == \
        "GATHER FROM LAROW"


def test_scatter_memvar_memo_round17_stream():
    # s02_scatter_memvar_memo (round17_streams.json): exact stream 5e1bc2, no symbols
    assert _source("5e1bc2") == "SCATTER MEMVAR MEMO"


def test_selectors_stay_contextual_beneath_their_leads():
    # 28/15/1b/c2 are clause selectors ONLY under their owning leads — this decoder
    # keeps them inline under 5e/5f, so the documented collisions (bare 67=VAL /
    # ea 67=SQLDISCONNECT class) can never see them as global tokens. The leads
    # themselves must not leak into expression or lvalue space.
    with pytest.raises(lifter.Unsupported):
        _source("54f7000010fcf7010028fd", ["X", "Y"])      # bare 28 inside an expr
    with pytest.raises(lifter.Unsupported):
        _source("54f7000010f701001bfd", ["X", "Y"])        # bare 1b inside an expr


@pytest.mark.parametrize("stream", [
    "5e",            # truncated lead
    "5ec2",          # MEMO without MEMVAR — cmd_sweep's bare spelling stays outside
                     # this lane's measured set (mandate: three round-17 forms only)
    "5e1b",          # MEMVAR without MEMO — unmeasured combination
    "5e1bc200",      # trailing byte after the measured MEMVAR MEMO shape
    "5e2800f70000",  # selector position carries a non-TO byte
    "5e28f7",        # symbol operand truncated
    "5e28f60000",    # TO form with an f6 name reference instead of f7 sym
])
def test_unmeasured_scatter_shapes_fail_loudly(stream):
    with pytest.raises(lifter.Unsupported):
        _source(stream)


@pytest.mark.parametrize("stream", [
    "5f",            # truncated lead
    "5fc2",          # cmd_sweep's bare GATHER MEMVAR spelling — outside the slice
    "5f1bc2",        # MEMVAR/MEMO clauses are measured under 5e only
    "5f1500f70000",  # selector position carries a non-FROM byte
    "5f15",          # symbol operand truncated
])
def test_unmeasured_gather_shapes_fail_loudly(stream):
    with pytest.raises(lifter.Unsupported):
        _source(stream)


def test_symbol_index_overflow_is_not_a_crash():
    with pytest.raises(lifter.Unsupported):
        _source("5e28f79900", ["LAROW"])   # index beyond the section table
