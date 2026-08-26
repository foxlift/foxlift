# ABOUTME: Declarative spec of the Visual FoxPro language surface, and the generator that emits it.
# ABOUTME: Each construct becomes one minimal compilable module so a byte-diff isolates its opcodes.

from dataclasses import dataclass
from pathlib import Path

# Every emitted file gets a fixed-width name (s0001.prg). The compiler embeds the source path in
# the FXP, so varying name lengths would shift every downstream byte and wreck minimal-pair diffs.
NAME_FMT = "s%04d"


@dataclass(frozen=True)
class Snippet:
    category: str
    label: str    # the construct under test, unique within the corpus
    source: str   # a complete, standalone-compilable VFP program


def _lines(*ls: str) -> str:
    return "\n".join(ls) + "\n"


# --- operators -------------------------------------------------------------------------------
# Operands are variables, not literals: VFP constant-folds, so `1+2` would compile to the folded
# value and never emit the ADD opcode we are trying to observe.
BINARY_OPS = [
    ("add", "+"), ("sub", "-"), ("mul", "*"), ("div", "/"), ("pow", "^"),
    ("expo", "**"), ("mod", "%"),
    ("eq", "="), ("exact_eq", "=="), ("ne", "!="), ("ne_alt", "<>"), ("ne_alt2", "#"),
    ("lt", "<"), ("gt", ">"), ("le", "<="), ("ge", ">="),
    ("contains", "$"),
    ("and", "AND"), ("or", "OR"),
]

UNARY_OPS = [("neg", "-"), ("pos", "+"), ("not", "NOT"), ("not_alt", "!")]

LITERALS = [
    ("int", "1"), ("int_big", "300"), ("int_huge", "1000000"),
    ("float", "1.5"), ("negative", "-7"),
    ("str_single", "'abc'"), ("str_double", '"abc"'), ("str_bracket", "[abc]"),
    ("str_empty", "''"),
    ("logical_true", ".T."), ("logical_false", ".F."),
    ("date", "{^2026-01-01}"), ("datetime", "{^2026-01-01 13:45:00}"),
    ("date_empty", "{}"),
    ("currency", "$12.34"),
    ("null", ".NULL."),
]

# --- built-in functions ----------------------------------------------------------------------
# (name, argument list) — minimal valid call forms. VFP's second function range is reached through
# an 0xEA escape prefix, so broad coverage here is what forces that range into the open.
FUNCTIONS = [
    # string
    ("UPPER", "'a'"), ("LOWER", "'A'"), ("PROPER", "'ab'"), ("LEN", "'ab'"),
    ("LEFT", "'abc',1"), ("RIGHT", "'abc',1"), ("SUBSTR", "'abc',1,2"),
    ("STUFF", "'abc',1,1,'z'"), ("STRTRAN", "'abc','a','z'"), ("CHRTRAN", "'abc','a','z'"),
    ("ALLTRIM", "' a '"), ("LTRIM", "' a'"), ("RTRIM", "'a '"), ("TRIM", "'a '"),
    ("PADL", "'a',3"), ("PADR", "'a',3"), ("PADC", "'a',3"),
    ("AT", "'a','abc'"), ("RAT", "'a','abc'"), ("ATC", "'a','abc'"),
    ("OCCURS", "'a','aa'"), ("REPLICATE", "'a',3"), ("SPACE", "3"),
    ("CHR", "65"), ("ASC", "'A'"), ("STR", "1"), ("VAL", "'1'"),
    ("TRANSFORM", "1"), ("STRCONV", "'a',1"), ("GETWORDCOUNT", "'a b'"),
    ("GETWORDNUM", "'a b',1"), ("STREXTRACT", "'abc','a','c'"), ("TEXTMERGE", "'a'"),
    ("LIKE", "'a*','abc'"), ("ISALPHA", "'a'"), ("ISDIGIT", "'1'"), ("ISLOWER", "'a'"),
    ("ISUPPER", "'A'"), ("INLIST", "1,1,2"), ("BETWEEN", "2,1,3"),
    # numeric
    ("ABS", "-1"), ("INT", "1.5"), ("ROUND", "1.55,1"), ("CEILING", "1.2"), ("FLOOR", "1.8"),
    ("MAX", "1,2"), ("MIN", "1,2"), ("MOD", "5,2"), ("SQRT", "4"), ("EXP", "1"), ("LOG", "1"),
    ("LOG10", "10"), ("SIGN", "-3"), ("RAND", ""), ("PI", ""),
    ("SIN", "1"), ("COS", "1"), ("TAN", "1"), ("ATAN", "1"), ("ASIN", "1"), ("ACOS", "1"),
    # date / time
    ("DATE", ""), ("TIME", ""), ("DATETIME", ""), ("DAY", "DATE()"), ("MONTH", "DATE()"),
    ("YEAR", "DATE()"), ("DOW", "DATE()"), ("CDOW", "DATE()"), ("CMONTH", "DATE()"),
    ("GOMONTH", "DATE(),1"), ("SECONDS", ""), ("HOUR", "DATETIME()"),
    ("MINUTE", "DATETIME()"), ("SEC", "DATETIME()"), ("TTOD", "DATETIME()"), ("DTOT", "DATE()"),
    ("DTOC", "DATE()"), ("DTOS", "DATE()"), ("CTOD", "'01/01/26'"),
    # type / conversion
    ("TYPE", "'x'"), ("VARTYPE", "1"), ("EMPTY", "''"), ("ISNULL", ".NULL."),
    ("NVL", "1,0"), ("IIF", ".T.,1,2"), ("EVALUATE", "'1'"),
    ("BITAND", "1,2"), ("BITOR", "1,2"), ("BITXOR", "1,2"), ("BITNOT", "1"),
    ("BITLSHIFT", "1,1"), ("BITRSHIFT", "2,1"), ("BITTEST", "1,0"),
    # tables / workareas
    ("RECNO", ""), ("RECCOUNT", ""), ("EOF", ""), ("BOF", ""), ("FOUND", ""),
    ("DELETED", ""), ("SELECT", "0"), ("ALIAS", ""), ("USED", "'x'"), ("FCOUNT", ""),
    ("FIELD", "1"), ("DBF", ""), ("CURSORGETPROP", "'Buffering'"), ("RECSIZE", ""),
    ("ORDER", ""), ("TAG", "1"), ("KEY", ""), ("SEEK", "1"), ("INDEXSEEK", "1"),
    # files / system
    ("FILE", "'x'"), ("FULLPATH", "'x'"), ("CURDIR", ""), ("SYS", "2015"),
    ("FOPEN", "'x'"), ("FCLOSE", "1"), ("FREAD", "1,1"), ("FWRITE", "1,'a'"),
    ("FILETOSTR", "'x'"), ("STRTOFILE", "'a','x'"), ("ADDBS", "'x'"),
    ("JUSTPATH", "'a\\b'"), ("JUSTFNAME", "'a\\b'"), ("JUSTEXT", "'a.b'"),
    ("JUSTSTEM", "'a.b'"), ("FORCEEXT", "'a.b','c'"), ("FORCEPATH", "'a','b'"),
    ("DIRECTORY", "'x'"), ("ERASE", "'x'"),
    # arrays / misc
    ("ALEN", "arr"), ("ASCAN", "arr,1"), ("ASUBSCRIPT", "arr,1,1"), ("AINS", "arr,1"),
    ("ADEL", "arr,1"), ("ASORT", "arr"), ("ACOPY", "arr,arr2"), ("ALINES", "arr,'a'"),
    ("PARAMETERS", ""), ("PCOUNT", ""), ("PROGRAM", ""), ("LINENO", ""),
    ("MESSAGE", ""), ("ERROR", ""), ("VERSION", ""), ("OS", ""), ("ID", ""),
    ("CREATEOBJECT", "'Custom'"), ("NEWOBJECT", "'Custom'"), ("PEMSTATUS", "obj,'x',5"),
    ("GETPEM", "obj,'x'"), ("AMEMBERS", "arr,obj"), ("OBJTOCLIENT", "obj,1"),
]

# --- statements and control flow ---------------------------------------------------------------
STATEMENTS = [
    ("assign", "x = 1"),
    ("assign_store", "STORE 1 TO x"),
    ("assign_store_multi", "STORE 1 TO x, y"),
    ("call_bare", "= UPPER('a')"),
    ("print", "? 'a'"),
    ("print_same_line", "?? 'a'"),
    ("print_multi", "? 'a', 'b'"),
    ("local", "LOCAL x"),
    ("local_typed", "LOCAL x AS Integer"),
    ("local_multi", "LOCAL x, y, z"),
    ("private", "PRIVATE x"),
    ("public", "PUBLIC x"),
    ("dimension", "DIMENSION arr(3)"),
    ("dimension_2d", "DIMENSION arr(3,2)"),
    ("declare", "DECLARE arr(3)"),
    ("release", "RELEASE x"),
    ("set_on", "SET TALK ON"),
    ("set_off", "SET TALK OFF"),
    ("set_exact", "SET EXACT ON"),
    ("set_century", "SET CENTURY ON"),
    ("set_deleted", "SET DELETED ON"),
]

BLOCKS = [
    ("if", _lines("IF x > 1", "  ? 'a'", "ENDIF")),
    ("if_else", _lines("IF x > 1", "  ? 'a'", "ELSE", "  ? 'b'", "ENDIF")),
    ("if_nested", _lines("IF x > 1", "  IF y > 1", "    ? 'a'", "  ENDIF", "ENDIF")),
    ("do_case", _lines("DO CASE", "CASE x = 1", "  ? 'a'", "CASE x = 2", "  ? 'b'",
                       "OTHERWISE", "  ? 'c'", "ENDCASE")),
    ("do_while", _lines("DO WHILE x < 3", "  x = x + 1", "ENDDO")),
    ("do_while_exit", _lines("DO WHILE .T.", "  EXIT", "ENDDO")),
    ("do_while_loop", _lines("DO WHILE x < 3", "  x = x + 1", "  LOOP", "ENDDO")),
    ("for_next", _lines("FOR i = 1 TO 10", "  ? i", "NEXT")),
    ("for_step", _lines("FOR i = 1 TO 10 STEP 2", "  ? i", "ENDFOR")),
    ("for_each", _lines("FOR EACH o IN arr", "  ? o", "ENDFOR")),
    ("scan", _lines("SCAN", "  ? RECNO()", "ENDSCAN")),
    ("scan_for", _lines("SCAN FOR x = 1", "  ? RECNO()", "ENDSCAN")),
    ("with", _lines("WITH obj", "  .Name = 'a'", "ENDWITH")),
    ("try_catch", _lines("TRY", "  x = 1", "CATCH TO oErr", "  ? oErr.Message", "ENDTRY")),
    ("try_finally", _lines("TRY", "  x = 1", "CATCH", "FINALLY", "  ? 'f'", "ENDTRY")),
    ("text_endtext", _lines("TEXT TO cVar NOSHOW", "hello", "ENDTEXT")),
    ("procedure", _lines("? 'main'", "PROCEDURE foo", "  ? 'a'", "ENDPROC")),
    ("procedure_params", _lines("? 'main'", "PROCEDURE foo", "  LPARAMETERS a, b",
                                "  ? a", "ENDPROC")),
    ("function_return", _lines("? 'main'", "FUNCTION foo", "  RETURN 1", "ENDFUNC")),
    ("do_proc", _lines("DO foo", "PROCEDURE foo", "  ? 'a'", "ENDPROC")),
    ("do_proc_with", _lines("DO foo WITH 1, 2", "PROCEDURE foo",
                            "  LPARAMETERS a, b", "ENDPROC")),
    ("define_class", _lines("? 'main'", "DEFINE CLASS foo AS Custom", "  Name = 'x'",
                            "  PROCEDURE bar", "    ? THIS.Name", "  ENDPROC", "ENDDEFINE")),
    ("define_class_prop", _lines("? 'main'", "DEFINE CLASS foo AS Custom",
                                 "  PROTECTED n", "  n = 0", "ENDDEFINE")),
]

# --- data / SQL ---------------------------------------------------------------------------------
DATA_STATEMENTS = [
    ("create_cursor", "CREATE CURSOR c (f1 I, f2 C(10))"),
    ("select_sql", "SELECT * FROM c INTO CURSOR d"),
    ("select_where", "SELECT f1 FROM c WHERE f1 = 1 INTO CURSOR d"),
    ("select_join", "SELECT a.f1 FROM c a INNER JOIN c b ON a.f1 = b.f1 INTO CURSOR d"),
    ("select_group", "SELECT f1, COUNT(*) FROM c GROUP BY f1 INTO CURSOR d"),
    ("select_order", "SELECT f1 FROM c ORDER BY f1 INTO CURSOR d"),
    ("insert_values", "INSERT INTO c (f1) VALUES (1)"),
    ("update_sql", "UPDATE c SET f1 = 2 WHERE f1 = 1"),
    ("delete_sql", "DELETE FROM c WHERE f1 = 1"),
    ("use", "USE c"),
    ("use_alias", "USE c ALIAS x"),
    ("select_area", "SELECT c"),
    ("go_top", "GO TOP"),
    ("go_bottom", "GO BOTTOM"),
    ("skip", "SKIP"),
    ("append_blank", "APPEND BLANK"),
    ("replace", "REPLACE f1 WITH 1"),
    ("delete_rec", "DELETE"),
    ("recall", "RECALL"),
    ("locate", "LOCATE FOR f1 = 1"),
    ("continue", "CONTINUE"),
    ("index_on", "INDEX ON f1 TAG t1"),
    ("set_order", "SET ORDER TO t1"),
    ("seek_cmd", "SEEK 1"),
    ("count_to", "COUNT TO n"),
    ("sum_to", "SUM f1 TO n"),
    ("zap", "ZAP"),
    ("pack", "PACK"),
]

# Statements needing an open cursor get one; the prologue is constant so diffs stay clean.
_DATA_PROLOGUE = "CREATE CURSOR c (f1 I, f2 C(10))\n"
_NEEDS_CURSOR = {s[0] for s in DATA_STATEMENTS} - {"create_cursor"}


def build() -> list[Snippet]:
    """Enumerate the full corpus. Order is stable so snippet ids stay put across runs."""
    out: list[Snippet] = []

    # A null program: the baseline every minimal-pair diff subtracts.
    out.append(Snippet("baseline", "null", "? 'z'\n"))

    for name, op in BINARY_OPS:
        out.append(Snippet("operator", f"binop_{name}", f"x = y {op} z\n"))
    for name, op in UNARY_OPS:
        sep = " " if op.isalpha() else ""
        out.append(Snippet("operator", f"unop_{name}", f"x = {op}{sep}y\n"))
    for name, lit in LITERALS:
        out.append(Snippet("literal", f"lit_{name}", f"x = {lit}\n"))
    for name, src in STATEMENTS:
        out.append(Snippet("statement", f"stmt_{name}", src + "\n"))
    for name, src in BLOCKS:
        out.append(Snippet("block", f"block_{name}", src))
    for fn, args in FUNCTIONS:
        out.append(Snippet("function", f"fn_{fn}", f"x = {fn}({args})\n"))
    for name, src in DATA_STATEMENTS:
        prologue = _DATA_PROLOGUE if name in _NEEDS_CURSOR else ""
        out.append(Snippet("data", f"data_{name}", prologue + src + "\n"))

    return out


def emit(dest: Path) -> list[tuple[str, Snippet]]:
    """Write the corpus to dest as fixed-width-named .prg files. Returns [(stem, snippet)]."""
    dest.mkdir(parents=True, exist_ok=True)
    for stale in dest.glob("*.prg"):
        stale.unlink()

    pairs = []
    for i, sn in enumerate(build(), start=1):
        stem = NAME_FMT % i
        (dest / f"{stem}.prg").write_text(sn.source, encoding="ascii")
        pairs.append((stem, sn))
    return pairs
