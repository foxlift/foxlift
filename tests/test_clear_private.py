# ABOUTME: Pins CLEAR and PRIVATE statement grammars against authored oracle streams.
# ABOUTME: Keeps clause bytes and name-list joins exact; malformed tails stay unsupported.

import pytest

from foxlift import lifter


def _source(stream, symbols=()):
    return lifter.statement_source(bytes.fromhex(stream), list(symbols))


def test_clear_events_and_dlls_forms():
    assert _source("0e") == "CLEAR"
    assert _source("0ed5") == "CLEAR EVENTS"
    assert _source("0e5602fb05004d594c4942") == "CLEAR DLLS MYLIB"
    assert _source("0e5602fb04004c49423107fb04004c494232") == \
        "CLEAR DLLS LIB1, LIB2"


def test_private_name_list_and_all_like_forms():
    assert _source("35f7000007f7010007f70200", ["PA", "PB", "PC"]) == \
        "PRIVATE PA, PB, PC"
    assert _source("350318fb040070725f2a", ["PRX"]) == "PRIVATE ALL LIKE pr_*"
    assert _source("37f7000007f70100", ["PC1", "PC2"]) == "PUBLIC PC1, PC2"


@pytest.mark.parametrize("stream", ["0ed500", "0e5602", "350318", "35f60000"])
def test_round16_statement_tails_fail_loudly(stream):
    with pytest.raises(lifter.Unsupported):
        _source(stream)
