# ABOUTME: Cross-process mutex around the compile oracle, which is one Windows VM running one VFP.
# ABOUTME: Parallel lanes hold it while driving the oracle so their VFP invocations never overlap.

import os
import time
from contextlib import contextmanager
from pathlib import Path

LOCK = Path.home() / ".foxlift-oracle.lock"

# The guest gives each batch its own bench_{rid} workspace, so files never collide. What could
# collide is vfp9.exe itself. Measured 2026-08-23 against a serialized control: 50 methods across
# two concurrent batches compared CANONICALLY equal (compare.compare_compiled) to the same batches
# run one after another, with a negative control confirming the comparator still rejects genuinely
# different source. Wall clock 36.0s serial -> 20.1s concurrent, 1.80x.
#
# Note the instrument. .fxp is NOT byte-reproducible: two SERIAL compiles of identical source differ
# at 17 offsets (embedded timestamps), so raw byte-equality reports 100% mismatch and means nothing.
# Compare statement frames and symbol tables, never the container bytes.
#
# Raise SLOTS only by repeating that measurement at the new count, never by assumption.
SLOTS = 2


def _slot_paths():
    return [LOCK.with_name(LOCK.name + ".%d" % i) for i in range(SLOTS)]


@contextmanager
def hold(label: str = "", timeout: float = 3600.0, poll: float = 2.0):
    """Take one of SLOTS oracle slots. Wrap every VM-driving call in this.

    Raises TimeoutError rather than proceeding unlocked: a silent overlap would show up as a
    mystery compile failure in whichever lane lost the race, which is the worst way to find out.
    """
    import fcntl

    deadline = time.monotonic() + timeout
    handles = [open(p, "a+") for p in _slot_paths()]
    try:
        held = None
        while held is None:
            for fh in handles:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held = fh
                    break
                except BlockingIOError:
                    continue
            if held is None:
                if time.monotonic() > deadline:
                    busy = []
                    for fh in handles:
                        fh.seek(0)
                        busy.append(fh.read().strip())
                    raise TimeoutError("all %d oracle slots held too long by: %s"
                                       % (SLOTS, "; ".join(busy)))
                time.sleep(poll)
        try:
            held.seek(0)
            held.truncate()
            held.write(f"pid={os.getpid()} {label}\n")
            held.flush()
            yield
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
    finally:
        for fh in handles:
            fh.close()
