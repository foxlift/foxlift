#!/usr/bin/env python3
# VM-free tests for the round-27 currency constant (de).
#
# Wire shape: de <pfx> <type=04> <i64LE scaled x10^4>. Round 274 measured
# the prefix as the character count of the canonical 4-decimal rendering
# (point included, no '$', no sign). Emission drops trailing fractional
# zeros, so prefix 08 + 1005000 renders $100.5 and prefix 06 + 0 renders
# $0. A prefix that is wider than that rendering is a leading-zero
# spelling and stays refused. A bad type byte and a truncated literal stay
# refused. The scaled value is never negative in a measured row.

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
    # qq = $100.50 and qq = $100.5 share this wire. i64LE 1005000, width 8.
    # The measured spelling drops the trailing fractional zero.
    assert _source("54f7000010fcde0804c8550f0000000000", ["QQ"]) == "QQ = $100.5"


def test_currency_zero_oracle_b14():
    # qq = $0 -> de 06 04 0000000000000000.
    assert _source("54f7000010fcde06040000000000000000", ["QQ"]) == "QQ = $0"


# ---------- negative: open prefixes, tags, values ------------------------------

def test_currency_open_prefix_value_rejected():
    # Prefix 07 on scaled 0 is the leading-zero spelling ($00). Measured,
    # wider than "0.0000", and not carried.
    with pytest.raises(lifter.Unsupported, match="currency literal shape unmeasured"):
        _source("54f7000010fcde07040000000000000000", ["QQ"])


def test_currency_tail_digit_measured():
    # Prefix 08 + scaled 1005001 is the 4-decimal width of 100.5001.
    payload = "04" + struct.pack("<q", 1005001).hex()
    assert _source("54f7000010fcde08" + payload, ["QQ"]) == "QQ = $100.5001"


def test_currency_one_dollar_carrier():
    # The eight round-37 carriers: prefix 06 + scaled 10000, width of 1.0000.
    assert _source("54f7000010fcde06041027000000000000", ["QQ"]) == "QQ = $1"


def test_currency_foldmark_carrier():
    # round48_foldmark_fm_143_cur: prefix 08 + scaled 1432500.
    assert _source("54f7000010fcde0804b4db150000000000", ["QQ"]) == "QQ = $143.25"


def test_currency_bad_type_byte_rejected():
    with pytest.raises(lifter.Unsupported, match="currency literal type byte"):
        _source("54f7000010fcde08050000000000000000", ["QQ"])


def test_currency_truncated_rejected():
    with pytest.raises(lifter.Unsupported, match="currency literal truncated"):
        _source("54f7000010fcde0804c8550f00000000", ["QQ"])


# ---------- roundtrip: the scaling is x10^4 little-endian ----------------------

def test_currency_value_roundtrip_scaled_x10_4():
    assert struct.pack("<q", int(100.50 * 10 ** 4)).hex() == "c8550f0000000000"
