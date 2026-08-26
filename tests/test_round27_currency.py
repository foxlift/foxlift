#!/usr/bin/env python3
# VM-free tests for the round-27 currency constant (de).
#
# Wire shape: de <pfx> <type=04> <i64LE scaled x10^4>. Only the two COMPLETE
# measured triples bind (oracle b13/b14): prefix 08 + 1005000 = $100.50 and
# prefix 06 + 0 = $0. The prefix byte's meaning is OPEN (08 rode two source
# decimals, 06 rode none — two data points), so any other combination fails
# loudly instead of guessing a rendering. The dev population holds ZERO de
# statements, so conservatism costs nothing measurable.

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from foxlift import lifter


def _source(stream, symbols=()):
    return lifter.statement_source(bytes.fromhex(stream), list(symbols))


# ---------- positive: the two measured triples ---------------------------------

def test_currency_cents_oracle_b13():
    # qq = $100.50 -> de 08 04 c8550f00..., i64LE 1005000 = 100.50 x 10^4.
    assert _source("54f7000010fcde0804c8550f0000000000", ["QQ"]) == "QQ = $100.50"


def test_currency_zero_oracle_b14():
    # qq = $0 -> de 06 04 0000000000000000.
    assert _source("54f7000010fcde06040000000000000000", ["QQ"]) == "QQ = $0"


# ---------- negative: open prefixes, tags, values ------------------------------

def test_currency_open_prefix_value_rejected():
    # Prefix 07 was never observed; treating it conservatively means naming it.
    with pytest.raises(lifter.Unsupported, match="currency literal shape unmeasured"):
        _source("54f7000010fcde07040000000000000000", ["QQ"])


def test_currency_measured_prefix_wrong_value_rejected():
    # Even a measured prefix says nothing about other values: only complete
    # measured triples may render.
    payload = "04" + struct.pack("<q", 1005001).hex()
    with pytest.raises(lifter.Unsupported, match="currency literal shape unmeasured"):
        _source("54f7000010fcde08" + payload, ["QQ"])


def test_currency_bad_type_byte_rejected():
    with pytest.raises(lifter.Unsupported, match="currency literal type byte"):
        _source("54f7000010fcde08050000000000000000", ["QQ"])


def test_currency_truncated_rejected():
    with pytest.raises(lifter.Unsupported, match="currency literal truncated"):
        _source("54f7000010fcde0804c8550f00000000", ["QQ"])


# ---------- roundtrip: the scaling is x10^4 little-endian ----------------------

def test_currency_value_roundtrip_scaled_x10_4():
    assert struct.pack("<q", int(100.50 * 10 ** 4)).hex() == "c8550f0000000000"
