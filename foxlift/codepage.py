# ABOUTME: Explicit code-page policy for VFP-facing source bytes — Option A (docs/VERBATIM.md).
# ABOUTME: Internal str values are a lossless latin-1 byte carrier; cp936 is the display codec.

"""One explicit representation for emitted source bytes.

Measured ground (docs/VERBATIM.md): the affected corpus population stores CP936/GBK
source bytes in verbatim 0x01 statements and inside compiled fb/d9 string literals,
while DBF code-page marks are not uniformly trustworthy (three carriers declare
0x03/cp1252 over strict-GBK content). The policy here therefore never transcodes:

- ``CARRIER`` ("latin-1") is BIJECTIVE bytes <-> code points. Every str flowing through
  the lifter carries stored bytes losslessly; it is an internal transport, not a claim
  about semantics, and it must never reach disk through a default UTF-8 writer.
- ``prg_bytes()`` is THE one explicit byte-producing path for VFP-facing standalone or
  container .prg content: it re-materialises the carried bytes exactly.
- ``display_text()`` renders stored bytes for humans/tests under the measured content
  code page (CP936), strictly — mojibake stays visible instead of being laundered.
- ``cpid_for_source_bytes()`` derives writer-side metadata from what the bytes ARE:
  a wrong source declaration cannot override measured content, so generated project
  metadata must describe the emitted bytes, never copy a possibly-wrong input mark.
"""

CARRIER = "latin-1"        # bijective byte carrier; NOT a semantic decode
VFP_CODE_PAGE = 936        # CP936 / GBK — measured content page of the GBK population
DISPLAY_CODEC = "cp936"    # strict display rendering; failures stay loud

CPID_LATIN = 1252          # Windows ANSI project CPID for ASCII/Western content
CPID_GBK = 936             # project CPID describing strict-CP936 content


def prg_bytes(lines) -> bytes:
    """Materialise lifted source lines as the exact VFP-facing file bytes.

    One newline-joined LF layout, matching every existing emitter; each line's
    characters are carried back to their stored bytes via CARRIER. Callers must write
    the result with write_bytes (or an equivalent binary sink) — never write_text.
    """
    lines = list(lines)
    return b"\n".join(l.encode(CARRIER) for l in lines) + (b"\n" if lines else b"")


def display_text(raw: bytes) -> str:
    """Human/test-facing rendering of stored source bytes (strict CP936).

    Raises UnicodeDecodeError on non-conforming bytes on purpose: silent repair would
    hide exactly the corruption this module exists to prevent.
    """
    return raw.decode(DISPLAY_CODEC)


def cpid_for_source_bytes(raw: bytes) -> int:
    """Project-writer CPID describing these source bytes (measured-content rule).

    Strict-CP936 with at least one non-ASCII byte -> 936; anything else -> 1252. The
    mark describes the bytes we emit, never a declaration read next to them.
    """
    if not raw.isascii():
        try:
            raw.decode("cp936")
        except UnicodeDecodeError:
            return CPID_LATIN
        return CPID_GBK
    return CPID_LATIN
