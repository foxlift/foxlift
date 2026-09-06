# ABOUTME: The emitter's table of oracle-confirmed preimages for folded numeric literals.
# ABOUTME: A lookup, never a rule — a frame with no entry keeps the emitter's old spelling.

"""Source expressions that compile back to a stored constant-fold frame.

A constant fold throws its source away. `fa <w> <d> <double> cc` records the
value and the width the ARITHMETIC produced, and `f8|f9|e9 <w> <value>` records
an integer fold only by an opcode wider than the value needs. Round 48 measured
that no written TOKEN reaches either frame and capped both.

Round 81 measured what a fold's header actually is
(`probes/oracle_harvest/round81_foldwidth_batch.py`) and inverted it: for each
frame the corpora store, the shortest source expression that compiles to
exactly those bytes, confirmed on the oracle one row at a time
(`round81_cc_batch.py`, `round81_intfold_batch.py`). Those confirmations are
this table.

The table is a LOOKUP and nothing more. A frame that is not in it is not
guessed at — the emitter keeps the spelling it had, and the frame stays capped.
Every entry is keyed by the whole frame, value bits included, so an entry can
only ever answer for the exact bytes it was measured against.

Ties are broken the same way every time: shortest source first, then the
spelling carrying the fewest zeros written only to reach the header's width,
then alphabetical order.
"""

from __future__ import annotations

import struct

_PREC = {"+": 5, "-": 5, "*": 6, "/": 6, "^": 7}

# (width, decimals, marked, value bits) -> source expression.
# Round 81 law 1: every entry compiled on the oracle as `round81_cc_streams`
# and confirmed byte-for-byte against the frame it answers for.
TABLE: dict = {
    # fa 01 00 cc  0.00390625  x2
    (1, 0, True, "000000000000703f"): "1/256",
    # fa 01 00 cc  0.5  x5
    (1, 0, True, "000000000000e03f"): "1/2",
    # fa 01 00 cc  0.3  x6
    (1, 0, True, "333333333333d33f"): "3/10",
    # fa 01 00 cc  0.6  x3
    (1, 0, True, "333333333333e33f"): "3/5",
    # fa 01 00 cc  0.2857142857142857  x1
    (1, 0, True, "922449922449d23f"): "2/7",
    # fa 01 00 cc  0.5714285714285714  x1
    (1, 0, True, "922449922449e23f"): "4/7",
    # fa 01 00 cc  0.2  x2
    (1, 0, True, "9a9999999999c93f"): "1/5",
    # fa 01 00 cc  0.4  x1
    (1, 0, True, "9a9999999999d93f"): "2/5",
    # fa 01 00 cc  0.45  x1
    (1, 0, True, "cdccccccccccdc3f"): "9/20",
    # fa 02 00 cc  0.5  x2
    (2, 0, True, "000000000000e03f"): "01/2",
    # fa 02 00 cc  0.75  x1
    (2, 0, True, "000000000000e83f"): "03/4",
    # fa 02 00 cc  0.3  x1
    (2, 0, True, "333333333333d33f"): "12/40",
    # fa 02 00 cc  1.7  x4
    (2, 0, True, "333333333333fb3f"): "17/10",
    # fa 02 00 cc  1.3333333333333333  x2
    (2, 0, True, "555555555555f53f"): "12/9",
    # fa 02 00 cc  0.32  x1
    (2, 0, True, "7b14ae47e17ad43f"): "16/50",
    # fa 02 00 cc  0.0072  x4
    (2, 0, True, "92cb7f48bf7d7d3f"): "18/2500",
    # fa 02 00 cc  -0.2  x2
    (2, 0, True, "9a9999999999c9bf"): "-1/5",
    # fa 02 00 cc  1.6  x2
    (2, 0, True, "9a9999999999f93f"): "08/5",
    # fa 03 00 cc  5.833333333333333  x2
    (3, 0, True, "5555555555551740"): "035/6",
    # fa 03 00 cc  5.1  x2
    (3, 0, True, "6666666666661440"): "102/20",
    # fa 04 00 cc  0.95  x2
    (4, 0, True, "666666666666ee3f"): "0019/20",
    # fa 04 02 cc  0.925  x1
    (4, 2, True, "9a9999999999ed3f"): "1.85/2",
    # fa 05 00 cc  104.16666666666667  x65
    (5, 0, True, "abaaaaaaaa0a5a40"): "00625/6",
    # fa 05 01 cc  9.015748031496063  x3
    (5, 1, True, "0281402010082240"): "229/25.4",
    # fa 05 01 cc  18.031496062992126  x1
    (5, 1, True, "0281402010083240"): "229/12.7",
    # fa 05 01 cc  8.267716535433072  x1
    (5, 1, True, "2391482412892040"): "105/12.7",
    # fa 05 01 cc  16.535433070866144  x3
    (5, 1, True, "2391482412893040"): "210/12.7",
    # fa 05 01 cc  7.165354330708662  x1
    (5, 1, True, "2b954aa552a91c40"): "182/25.4",
    # fa 05 01 cc  4.330708661417323  x2
    (5, 1, True, "552a954aa5521140"): "110/25.4",
    # fa 05 01 cc  8.661417322834646  x1
    (5, 1, True, "552a954aa5522140"): "110/12.7",
    # fa 05 01 cc  11.692913385826772  x2
    (5, 1, True, "592c168bc5622740"): "297/25.4",
    # fa 05 01 cc  23.385826771653544  x3
    (5, 1, True, "592c168bc5623740"): "297/12.7",
    # fa 05 01 cc  6.377952755905512  x2
    (5, 1, True, "6130180c06831940"): "162/25.4",
    # fa 05 01 cc  12.755905511811024  x2
    (5, 1, True, "6130180c06832940"): "162/12.7",
    # fa 05 01 cc  13.89763779527559  x1
    (5, 1, True, "73b95c2e97cb2b40"): "353/25.4",
    # fa 05 01 cc  4.488188976377953  x2
    (5, 1, True, "7d3e9fcfe7f31140"): "114/25.4",
    # fa 05 01 cc  9.05511811023622  x1
    (5, 1, True, "87c3e170381c2240"): "115/12.7",
    # fa 05 01 cc  10.118110236220472  x1
    (5, 1, True, "8fc7e3f1783c2440"): "257/25.4",
    # fa 05 01 cc  8.46456692913386  x1
    (5, 1, True, "bcdd6eb7dbed2040"): "215/25.4",
    # fa 05 01 cc  33.110236220472444  x2
    (5, 1, True, "c4e170381c8e4040"): "841/25.4",
    # fa 05 01 cc  10.826771653543307  x1
    (5, 1, True, "ea743a9d4ea72540"): "275/25.4",
    # fa 05 01 cc  4.921259842519685  x1
    (5, 1, True, "ecf57abd5eaf1340"): "125/25.4",
    # fa 05 01 cc  9.84251968503937  x3
    (5, 1, True, "ecf57abd5eaf2340"): "125/12.7",
    # fa 05 01 cc  6.929133858267717  x2
    (5, 1, True, "ee76bbdd6eb71b40"): "176/25.4",
    # fa 05 01 cc  13.937007874015748  x1
    (5, 1, True, "f8fbfd7ebfdf2b40"): "177/12.7",
    # fa 05 02 cc  0.0028346456692913383  x2
    (5, 2, True, "b95740ceae38673f"): "01.44/508",
    # fa 06 01 cc  46.811023622047244  x1
    (6, 1, True, "fa7c3e9fcf674740"): "1189/25.4",
    # fa 06 02 cc  0.9995  x2
    (6, 2, True, "96438b6ce7fbef3f"): "139.93/140",
    # fa 08 04 cc  57.142857142857146  x2
    (8, 4, True, "2549922449924c40"): "100/1.7500",
    # fa 08 04 cc  25.974025974025974  x2
    (8, 4, True, "67e527c459f93940"): "100/3.8500",
    # fa 08 04 cc  71.42857142857143  x1
    (8, 4, True, "b76ddbb66ddb5140"): "100/1.4000",
    # fa 08 04 cc  47.61904761904762  x1
    (8, 4, True, "f43ccff33ccf4740"): "100/2.1000",
    # fa 09 00 cc  208.33333333333331  x2
    (9, 0, True, "aaaaaaaaaa0a6a40"): "000125/6*10",
    # fa 0a 00 cc  4.0  x3
    (10, 0, True, "0000000000001040"): "2^2",
    # fa 0a 00 cc  262144.0  x2
    (10, 0, True, "0000000000001041"): "4^9",
    # fa 0a 00 cc  16.0  x5
    (10, 0, True, "0000000000003040"): "2^4",
    # fa 0a 00 cc  1048576.0  x8
    (10, 0, True, "0000000000003041"): "16^5",
    # fa 0a 00 cc  32.0  x9
    (10, 0, True, "0000000000004040"): "2^5",
    # fa 0a 00 cc  64.0  x21
    (10, 0, True, "0000000000005040"): "2^6",
    # fa 0a 00 cc  256.0  x6
    (10, 0, True, "0000000000007040"): "2^8",
    # fa 0a 00 cc  16777216.0  x4
    (10, 0, True, "0000000000007041"): "8^8",
    # fa 0a 00 cc  1099511627776.0  x2
    (10, 0, True, "0000000000007042"): "2^40",
    # fa 0a 00 cc  1024.0  x2
    (10, 0, True, "0000000000009040"): "4^5",
    # fa 0a 00 cc  4096.0  x4
    (10, 0, True, "000000000000b040"): "4^6",
    # fa 0a 00 cc  1073741824.0  x2
    (10, 0, True, "000000000000d041"): "2^30",
    # fa 0a 00 cc  65536.0  x7
    (10, 0, True, "000000000000f040"): "4^8",
    # fa 0a 00 cc  100000000.0  x6
    (10, 0, True, "0000000084d79741"): "10^8",
    # fa 0a 00 cc  214748364.7  x2
    (10, 0, True, "666666999999a941"): "2147483647/10",
    # fa 0b 00 cc  65535.0  x1
    (11, 0, True, "00000000e0ffef40"): "4^8-1",
    # fa 0b 00 cc  16777215.0  x1
    (11, 0, True, "000000e0ffff6f41"): "8^8-1",
    # fa 0b 00 cc  2147483647.0  x2
    (11, 0, True, "0000c0ffffffdf41"): "2^31-1",
    # fa 0e 00 cc  1022976.0  x2
    (14, 0, True, "0000000000382f41"): "4^5*999",
    # fa 0e 00 cc  1047527424.0  x2
    (14, 0, True, "000000000038cf41"): "16^5*999",
}

# (opcode, width, value) -> source expression.
# Round 81 law 2: every entry compiled on the oracle as `round81_intfold_
# streams` and confirmed byte-for-byte against the frame it answers for.
INT_TABLE: dict = {
    # f9 04 00  128  x1
    ("f9", 4, 128): "16*8",
    # f9 04 00  132  x1
    ("f9", 4, 132): "2*66",
    # f9 04 00  135  x1
    ("f9", 4, 135): "15*9",
    # f9 04 00  136  x1
    ("f9", 4, 136): "17*8",
    # f9 04 00  138  x1
    ("f9", 4, 138): "2*69",
    # f9 04 00  194  x1
    ("f9", 4, 194): "2*97",
    # f9 04 00  195  x1
    ("f9", 4, 195): "3*65",
    # f9 04 00  201  x1
    ("f9", 4, 201): "3*67",
    # f9 04 00  254  x1
    ("f9", 4, 254): "0+254",
    # f9 05 00  132  x4
    ("f9", 5, 132): "1*132",
    # f9 05 00  135  x1
    ("f9", 5, 135): "1*135",
    # f9 05 00  160  x6
    ("f9", 5, 160): "1*160",
    # f9 0b 00  144  x1
    ("f9", 11, 144): "0000001*144",
}


def bits_of(value: float) -> str:
    return struct.pack("<d", float(value)).hex()


def for_float(width, decimals, marked, value):
    """The confirmed preimage of an `fa <w> <d> <double> [cc]` frame, or None."""
    if width is None:
        return None
    return TABLE.get((width, decimals, bool(marked), bits_of(value)))


def for_int(opcode, width, value):
    """The confirmed preimage of a widened integer frame, or None."""
    if width is None:
        return None
    return INT_TABLE.get((opcode, width, int(value)))


def precedence_of(source: str) -> int:
    """The precedence of a preimage's own top-level operator.

    The emitter's `_side` parenthesises a child whose precedence is below what
    its slot demands, so a synthesised expression has to report the operator it
    is rooted at — `2^6` may stand bare under a `/`, `20*08` may not. A leading
    unary minus is part of the first operand, not a top-level operator.
    """
    depth = 0
    best = 9
    prev = ""
    for i, ch in enumerate(source):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and ch in _PREC:
            if ch == "-" and (i == 0 or prev in _PREC):
                prev = ch
                continue
            best = min(best, _PREC[ch])
        prev = ch
    return best
