# ABOUTME: The data language for a clause bank — one production row per clause, in wire order.
# ABOUTME: A bank is a list; a reader is a loop over the list; an emitter spells the same list back.

"""Describe a clause bank once, and let the reader and the emitter share it.

Every arm of `foxlift/lifter.py` states its grammar four times: in a comment,
in the reader, in the emitter, and again in the oracle matrix that measured it.
This module is the smallest thing that lets one description serve all four for
a bank whose clauses are *marked* — a byte announces the clause, an operand
follows in a shape the format already has a name for, and the clause spells one
or two source words.

    Clause  one production: the mark bytes, the operand shape, the word
    Bank    a scope-keyed list of clauses, in WIRE order
    Reader  a loop over that list against a statement's bytes

**Wire order is the list order; source order is a column.** VFP9 writes a
field's clauses in a fixed order that is not the order the source spells them:
`f1 I AUTOINC NOT NULL` and `f1 I NOT NULL AUTOINC` are the same bytes, with
the nullability ahead of the AUTOINC mark either way. The reader walks the list;
the emitter sorts by `order` and re-spells one canonical source.

**This is not a parser generator.** A clause the table cannot describe stays in
hand-written code with a comment saying why. The table says: which mark opens a
clause, what shape follows it, whether the clause is admitted at all in this
statement's verb, whether it is only offered behind another clause, whether it
makes the field carry its per-field closer, and what it spells.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ------------------------------------------------------------ operand shapes

NOTHING = "nothing"
"""The mark alone carries the clause — `c0` is FREE, `d6` is NULL."""

GROUP = "group"
"""`fc <expression> fd` — the format's parenthesised operand."""

INT = "int"
"""`fc <int8|int16 literal> fd` — a group narrowed to a plain integer."""

SYM = "sym"
"""`f7 <u16>` — a reference into the section's symbol table."""

STR = "str"
"""`fb|d9 <u16> <bytes>` — a literal carried on the wire."""

NAMED = "named"
"""An operand the bank names and the reader is handed, by `operand_name`."""

SHAPES = (NOTHING, GROUP, INT, SYM, STR, NAMED)


@dataclass(frozen=True)
class Clause:
    """One production of a clause bank.

    `marks` are the bytes that open the clause, in wire order; an empty
    `marks` means the operand's own lead byte is the discriminator, which is
    how an operand with alternative spellings (a name carried as a symbol, a
    string or a group) becomes one row per spelling.
    """

    key: str
    """The name the reader files the clause under, and the emitter spells."""

    scope: str
    """Which part of the statement offers this clause."""

    marks: tuple = ()
    """The bytes that open the clause. Empty: the operand's lead decides."""

    operand: str = NOTHING
    """One of `SHAPES`."""

    operand_name: str = ""
    """For `NAMED`: which of the reader's operand decoders to call."""

    word: str = ""
    """The source spelling, as a `%(key)s` format over the read values. Empty
    for a clause that carries no word (the per-field closer)."""

    order: int = 0
    """Position in the SOURCE spelling. The list's own order is the wire."""

    space: bool = True
    """Whether the word is separated from what precedes it."""

    closer: bool = False
    """Reading this clause makes the field carry its per-field closer."""

    after: tuple = ()
    """Offered only when one of these keys was already read."""

    required: bool = False
    """When offered, absence raises `refusal`."""

    verbs: tuple = ()
    """The statement verbs that admit the clause; empty admits every verb. A
    mark that matches under a verb the clause does not admit is a refusal, not
    a miss — the byte means something else there, and guessing spells a word
    the compiler would reject."""

    supersedes: tuple = ()
    """Keys whose word this clause's word replaces (the decimals spelling
    carries the width inside its own parentheses)."""

    refusal: str = ""
    """The loud label when the mark is there and the shape is not."""


@dataclass(frozen=True)
class Bank:
    """A named clause bank: its productions, in wire order."""

    name: str
    clauses: tuple
    required_scopes: dict = field(default_factory=dict)
    """scope -> the refusal raised when the scope matched no row at all."""

    def of(self, scope: str) -> tuple:
        return tuple(c for c in self.clauses if c.scope == scope)

    def closer_seen(self, values: dict) -> bool:
        """Did a clause that demands the per-field closer get read?"""
        return any(c.closer and c.key in values for c in self.clauses)

    def spell(self, values: dict, scope: str) -> str:
        """The clause words of one scope, in SOURCE order, as one string.

        One word per key: alternative spellings of the same clause (`d6` NULL
        and `0a d6` NOT NULL) are separate rows, and the value a bare mark
        stores IS its word, so the row that matched is the one that spells.
        """
        rows, seen = [], set()
        for c in sorted(self.of(scope), key=lambda c: c.order):
            if not c.word or c.key not in values or c.key in seen:
                continue
            seen.add(c.key)
            rows.append(c)
        dropped = {k for c in rows for k in c.supersedes}
        out = []
        for c in rows:
            if c.key in dropped:
                continue
            text = values[c.key] if c.operand == NOTHING else c.word % values
            out.append((" " if c.space else "") + text)
        return "".join(out)


class Reader:
    """A loop over one bank's clauses, against a statement's bytes.

    The operand decoders and the exception class come from the caller, so this
    module needs nothing from the lifter and the lifter keeps every byte-level
    decision it already had.
    """

    def __init__(self, bank: Bank, operands: dict, leads: dict, error):
        self.bank = bank
        self.operands = operands
        self.leads = leads
        self.error = error

    # ------------------------------------------------------------- matching

    def _lead_bytes(self, clause: Clause) -> tuple:
        if clause.operand == NAMED:
            return self.leads.get(clause.operand_name, ())
        return self.leads.get(clause.operand, ())

    def _matches(self, clause: Clause, buf, j: int, end: int) -> bool:
        k = j + len(clause.marks)
        if k > end or bytes(buf[j:k]) != bytes(clause.marks):
            return False
        leads = self._lead_bytes(clause)
        if not leads:
            return True
        return k < end and buf[k] in leads

    def _operand(self, clause: Clause, buf, j: int, end: int, syms):
        """The clause's operand. Each decoder raises its OWN loud label, so a
        refusal from inside an operand keeps the name it has always had."""
        if clause.operand == NOTHING:
            return clause.word or True, j
        return self.operands[clause.operand_name or clause.operand](
            buf, j, end, syms, clause)

    def _tail_refusal(self, clause: Clause, buf, j: int, end: int) -> str:
        return (clause.refusal % (buf[j] if j < end else 0)
                if "%" in clause.refusal else clause.refusal)

    # -------------------------------------------------------------- reading

    def read(self, scope: str, buf, j: int, end: int, syms,
             verb: str = "") -> tuple:
        """Every clause of one scope that the bytes at `j` spell, in wire order."""
        values: dict = {}
        for clause in self.bank.of(scope):
            if clause.key in values:
                continue                # an alternative spelling already read
            if clause.after and not any(k in values for k in clause.after):
                continue
            if not self._matches(clause, buf, j, end):
                if clause.required:
                    raise self.error(self._tail_refusal(clause, buf, j, end))
                continue
            if clause.verbs and verb not in clause.verbs:
                raise self.error(clause.refusal)
            value, j = self._operand(clause, buf, j + len(clause.marks), end,
                                     syms)
            values[clause.key] = value
        return values, j

    def read_one(self, scope: str, buf, j: int, end: int, syms) -> tuple:
        """The one row of a scope the bytes spell; nothing matching is a refusal."""
        for clause in self.bank.of(scope):
            if self._matches(clause, buf, j, end):
                return self._operand(clause, buf, j + len(clause.marks), end,
                                     syms)
        raise self.error(self.bank.required_scopes[scope])
