# ABOUTME: Materializes the authored g0x .fxp fixture binaries from their tracked .fxp.hex
# ABOUTME: siblings so checkouts that ship no VFP binaries (the public snapshot) still run.

from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

_created = []


def pytest_sessionstart(session):
    for hexfile in sorted(FIXTURES.glob("*.fxp.hex")):
        fxp = hexfile.with_suffix("")  # g01_assign.fxp.hex -> g01_assign.fxp
        if fxp.exists():
            continue
        fxp.write_bytes(bytes.fromhex(hexfile.read_text().strip()))
        _created.append(fxp)


def pytest_sessionfinish(session, exitstatus):
    for fxp in _created:
        try:
            fxp.unlink()
        except OSError:
            pass
    _created.clear()
