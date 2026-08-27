# VFP9 bytecode token reference — oracle-measured

ABOUTME: Authoritative consolidated table of every bytecode token confirmed by OUR VFP9
ABOUTME: compile oracle (probes/oracle_harvest/ + probes/flagcamp/). Each entry carries its
ABOUTME: emitting snippet or campaign. Published-map hypotheses were used only as candidates
ABOUTME: and confirmed here before inclusion. ReFox never consulted.

## Statement-position tokens (lead bytes)

| lead | construct | stream shape |
|-----|-----------|-------------|
| 02 | `? expr[, expr…]` | `02 f8 <count> fc expr fd [07 fc expr fd]…` |
| 03 | `??` | same shape, lead 03 |
| 04 | `@ r,c SAY expr` / `@ r,c GET x VALID …` | `04 fc … fd [07 fc … fd] c4 …` |
| 06 | `+` in statement position | contextual with expression |
| 12 | `COUNT TO var` | `12 28 f7 <sym>` |
| 14 | FORM clause (DO FORM) | inside DO frame |
| 18 | `DO proc` / DO WHILE opener / DO FORM | `18 f7 <sym>` · `18 2b fc cond fd f9 05 <u16>` · `18 14 fb <name> [4a f7 be][53]` (NAME/LINKED, NOREAD) |
| 1b | ELSE | `1b f9 05 <u16→ENDIF>` |
| 1c | ENDCASE | bare |
| 1d | ENDDO | bare |
| 1e | ENDIF | bare |
| 1f | ENDTEXT | bare |
| 21 | EXIT | bare |
| 23 29 | GO TOP | two-byte statement |
| 25 | IF | `25 fc cond fd f9 05 <u16→ENDIF>` |
| 2d | LOCATE FOR | `2d 13 fc cond fd …` (13=FOR clause) |
| 32 | OTHERWISE | `32 f9 05 <u16>` |
| 34 | PARAMETERS stmt | `34 f7 <sym>` |
| 35 | PRIVATE | `35 f7 <sym>` |
| 37 | PUBLIC | `37 f7 <sym>` |
| 38 | QUIT | bare |
| 42 | RETURN | bare |
| 46 | SELECT workarea | `46 f8 <wa>` or `46 f7 <sym>` |
| 48 | SKIP | bare; `48 fc expr` for SKIP n |
| 4a | STORE expr TO var | `4a fc expr fd 28 f7 <var>` |
| 4b | SUM expr TO var | `4b 28 …` |
| 51 | USE table | `51 [c2 SHARED][be NOUPDATE] fb <name> [bc AGAIN][02 f7 <sym> ALIAS]` |
| 54 | assignment | `54 <lvalue> 10 fc expr fd` |
| 55 | symbol-table lead | `55 u16count entries…` (NOT end-of-procedure) |
| 5e | SCATTER MEMVAR BLANK | `5e 08 c2` |
| 5f | GATHER MEMVAR | `5f c2` |
| 6f | SELECT-SQL (simple) | `6f 15 <FROM> [c7] [<cols fc..fd 07-joined>] [c6 fc WHERE fd] [c3 fc ORDER fd] bc bd fb<cursor>` |
| 70 | UPDATE-SQL | `70 fb <tbl> ca <col> 10 fc v fd c6 fc cond fd` |
| 72 | INSERT-SQL | `72 bc fb <tbl> 02 <cols> 03 c5 02 fc vals fd 03` — statement LEAD; no certified expression-position identity (round-27: authored ADD is 06, the six PATHS suspects are chained-call grammar, and the wider census leaves one >16KB unclassifiable stream once e2/payload operands are accounted) |
| 73 | DEFINE family | keyword byte selects: WINDOW=`73 2c f7 sym …`, POPUP=`73 c6 f7 sym` |
| 84 | FOR | `84 <lvalue> fd 28 fc end fd f9 05 <u16→ENDFOR>` |
| 85 | ENDFOR | bare |
| 96 | ADD statement | `96 31 fb <table>` (ADD TABLE) · `96 2e f7 <obj> 51 f7 <class>` (ADD OBJECT, class-def) — IMPLEMENTS is b9, measured in both OLEPUBLIC and plain spellings |
| 99 | bare call / member invocation | `99 fc …` or `99 f4<obj> f7<member>` |
| a6 | WITH opener | `a6 fc <obj> fd f9 05 <u16→ENDWITH>` (jump word measured round-27; sysvar/path targets take e1 chains with a terminal property read) |
| a7 | ENDWITH | bare |
| ac | NODEFAULT | bare |
| ae | LOCAL | `ae f5 0d f7 <sym>` or `ae f7 <sym>`; array declarator adds `fc expr fd (07 fc expr fd)* <closer>` per name — closer 03 = source `( … )`, 16 = source `[ … ]` (population census; both recompile byte-equal only if spelled back as emitted) |
| b0 | CD | `b0 fc expr` |
| b9 | ADD OBJECT / IMPLEMENTS | class-def context (IMPLEMENTS emitted b9-led in cmd_sweep OLEPUBLIC form) |
| ba | TRY opener | `ba f9 05 <u16>` |
| bb | CATCH clause | `bb [28 f7 <var>] [d2 fc cond fd] f9 05 <u16>` (28=TO var, d2=WHEN) |
| bc | FINALLY | `bc f9 05 <u16>` |
| bd | THROW expr | `bd` bare or `bd fc <expr> fd` inside TRY — TEXT never emits bd (TEXT/TEXT TO = `4d … 1f`; TO-clause `28 f7 var ce`) |
| be | ENDTRY | bare |

### Command leads from the full sweep (CMD_SWEEP.md is authoritative per command)

One ALANGUAGE name each, all oracle-emitted by probes/oracle_harvest/cmd_sweep.py:
43 RUN/! · 79 `???` · 05 ACCEPT · 74 ACTIVATE(26=SCREEN) · 07 ASSIST ·
08 AVERAGE · 9b BEGIN / 9d END TRANSACTION · 93 BLANK · 09 BROWSE · 8f BUILD PROJECT ·
7d CALCULATE · 0a CALL · 0b CANCEL · 0d CHANGE · 0e CLEAR · 0f CLOSE TABLES ·
83 COMPILE · 10 CONTINUE · 11 COPY FILE · 13 CREATE · 75 DEACTIVATE WINDOW ·
b3 DEBUG · aa DEBUGOUT · 7c DECLARE DLL · 14 DELETE(+12 FILE) · 15 DIMENSION ·
16 DIR/DIRECTORY · 17 DISPLAY · bf DOCK WINDOW · b7 DOEVENTS · 6a DROP TABLE ·
19 EDIT · 1a EJECT · 20 ERASE · a8 ERROR · 56 EXPORT · 90 EXTERNAL ARRAY ·
22 FIND · 5b FLUSH · 5f GATHER MEMVAR · 82 GETEXPR · 23 29/36 GO/GOTO TOP/BOTTOM ·
24 HELP · 87 HIDE WINDOW · 9f HIDDEN(class) · 57 IMPORT · 26 INDEX ON..TAG(ca) ·
27 INPUT · 69 ALTER TABLE · 29 JOIN WITH(d1) · 5c KEYBOARD(d3,3b) · 2a LABEL FORM(14) ·
2b LIST · 2c LOAD · 59 LOGOUT · b1 MD/MKDIR · 5d MENU BAR · 2f MODIFY COMMAND(bc,3a) ·
ad MOUSE CLICK(c3,05) · 7a MOVE WINDOW TO · ac NODEFAULT · 31 ON ERROR(10 selector) ·
95 OPEN DATABASE(c2) · 33 PACK · 81 PLAY MACRO(1a) · 8a/8b PUSH/POP KEY(17) ·
39 READ · 3a RECALL · 35 REGIONAL (=PRIVATE shape) · 3b REINDEX · 3c RELEASE ·
97 REMOVE TABLE(31) · 3d RENAME x TO y · 3f REPORT FORM(14) · 94 RESET ·
40 RESTORE FROM(15) · 41 RESUME · 58 RETRY · b2 RD/RMDIR · 9c ROLLBACK ·
44 SAVE TO(28) · 7e/7f SCAN/ENDSCAN · 60 SCROLL · 45 SEEK · 80 SHOW WINDOW ·
89 SIZE WINDOW TO · 49 SORT ON(20)..TO · 4c SUSPEND · 4d TEXT body block (+1f) ·
4e TOTAL ON..TO · 4f TYPE · 5a UNLOCK · 53 ZAP · 8c ZOOM WINDOW

Measured-empty (no bytecode exists): `*`, NOTE, #INCLUDE/#IFDEF/#IF/#ELIF/#IFNDEF.
Compiler-rejected in every form tried: FREE LIBRARY, UNDEFINE, VALIDATE.

## Expression tokens (RPN)

| byte | meaning |
|------|---------|
| 04 | multiply `*` |
| 06 | add `+` |
| 07 | list separator (comma) |
| 0a | NOT |
| 0d | `<` |
| 0e | `<=` |
| 0f | `!=` / `#` |
| 10 | `=` |
| 11 | `>=` |
| 12 | `>` |
| 14 | `==` (exact match); also FORM clause (contextual) |
| 15 | FROM clause (SQL) |
| 16 | IN clause; also array-index operator (contextual) |
| 18 | @by-reference marker in call args |
| 28 | TO clause |
| 2b | WHILE clause |
| 2e+1f | setting OFF suffix (with SET lead 47) |
| 2e+20 | setting ON suffix |
| 43 | parameter-group open (args collected by scan-back to closer) |
| d1 | ISNULL() closer / WITH keyword (REPLACE) — context-dependent |
| d9 | double-quoted string literal + u16 len |
| e1 <u8> | system-OBJECT path opener (39=_SCREEN, 43=_VFP): f4 hops follow; TERMINAL member call closes the 43 group with f6\<method\>, a call with a following member rides e5\<method\> mid-chain; lvalue INTO the path keeps e139 inside the 54-target; dotted context only — bare `_SCREEN` is ed 39, `_SCREEN(3)` a plain symbol call. Round-27 |
| e5 <u16> | method-call opener mid-chain (a member access follows the call). Round-27 |
| ed <u8> | bare system-variable READ: _cliptext=1d, _SCREEN=39. Rounds 21/27 |
| e9 | int32 literal (digit-count prefix) |
| ea xx | extended-function escape → builtin id xx |
| f4 | alias-path component |
| f5 ss | sub-scripted ref: ss=01–0A workarea letters A–J, 0d=memvar `m.`, others UNMEASURED |
| f6 <u16> | method-call tail: closes the call group when the call is TERMINAL; args precede the receiver run, variable args carry ByVal 00. Round-27 |
| f7 | variable/terminal ref + u16 symbol index |
| f8 | int8 literal (digit-count prefix) |
| f9 | int16 literal (digit-count prefix) |
| fa | float64 literal (two prefixes: total digits, fraction digits) |
| fb | single-quoted string literal + u16 len |
| fc | expression-group open |
| fd | expression-group close |
| fe | end-of-statement terminator |

## Function ids — two disjoint namespaces

### Bare group-closers (byte follows arguments inside 43-groups)

FILE 30 · GETENV 35 · LEN 3e · MAX 44 · MIN 46 · RECNO 4e · REPLICATE 51 ·
RIGHT 52 · RTRIM 56 · SPACE 58 · STR 5a · SUBSTR 5c · TRANSFORM 5f · TRIM 60 ·
**CHR 20** · UPPER 66 · VAL 67 · ALLTRIM 9b · CHRTRAN 9d · EMPTY a1 ·
PROPER bc · CTOD 23 · DATE 24 · ALIAS 1b · LTRIM 41 · DELETED 27 · DBF 26 ·
EOF 2b · BOF 1e · FOUND 34 · COL 22 · ROW 55 · VARREAD 87 · IIF 36

### EA-escape functions (`ea xx` prefix)
39 CPCONVERT · 4e CREATEOBJECT · **5e RGB** · **62 AMEMBERS** · 67 SQLDISCONNECT ·
**68 PEMSTATUS** · 69 SQLEXEC · **6a SQLGETPROP · 6b SQLMORERESULTS · 6c SQLSETPROP ·
6d SQLTABLES** · 78 MESSAGEBOX · 86 DATETIME · 87 REQUERY · **81 TTOC** ·
94 TABLEREVERT · 9f SQLSTRINGCONNECT · a1 DODEFAULT · cb STRTOFILE · cc FILETOSTR ·
ce DEFAULTEXT · d0 FORCEEXT · d2 JUSTDRIVE · d3 JUSTEXT · d6 JUSTSTEM ·
ee GETWORDNUM · ed GETWORDCOUNT · ef IMESTATUS · f0 STREXTRACT · f5 TEXTMERGE ·
**64 SQLCANCEL · 65 SQLCOLUMNS · 7b SQLCOMMIT · 7c SQLROLLBACK · c5 SQLPREPARE**

**ea19 is NOT a function**: it is a marker emitted between group-open and its
arguments on by-reference calls — arrays first (AMEMBERS, ADIR, AINSTANCE), then
object-by-ref (ADOCKSTATE, AEVENTS, ASQLHANDLES); the callee is the trailing closer.

### X1A-escape functions (`1a xx` prefix) — third builtin bank

Same structure as ea-escapes, disjoint id space. All 24 confirmed by fresh snippets
(build/x1abank/, HARVEST.md round-11):

00 DISPLAYPATH · 01 CURSORTOXML · 02 XMLTOCURSOR · 03 GETINTERFACE · 04 BINDEVENT ·
05 RAISEEVENT · 06 ADOCKSTATE · 07 GETCURSORADAPTER · 08 UNBINDEVENTS · 09 AEVENTS ·
0a ADDPROPERTY · 0b REMOVEPROPERTY · 0c EVL · 0e ICASE · 0f CAST (e4 = AS-type
marker before closer) · 10 ASQLHANDLES · 11 SETRESULTSET · 12 GETRESULTSET ·
13 CLEARRESULTSET · 14 SQLIDLE · 16 GETAUTOINCVALUE · 17 MAKETRANSACTABLE ·
18 ISTRANSACTABLE · 19 ISPEN

Measured aliases (byte-identical streams; canonical name first):
CDX≡MDX bare 7f · FCOUNT≡FLDCOUNT bare 2e · CNTBAR≡BARCOUNT ea 05 · WOUTPUT≡WINDOW bare bf.

**Namespace collisions are real**: bare 67=VAL vs ea 67=SQLDISCONNECT;
bare 87=VARREAD vs ea 87=REQUERY; bare 3e=LEN vs REPLACE lead; bare 52=RIGHT
vs WAIT lead; bare 1e=BOF vs ENDIF lead. Position/state must select the table.

## SET-command ids (lead 47 = SET)

TALK 32 · ESCAPE 15 · SAFETY 2e · EXACT 16 · DELETED 0f · CENTURY 05 ·
CONSOLE 0a · NOTIFY 5a · OPTIMIZE 61 · FIXED 1b · HEADING 1e · NEAR 46 ·
UNIQUE 36 · CARRY 03 · CONFIRM 09 · EXCLUSIVE 17 · MULTILOCKS 5f ·
RESOURCE 54 · LOGERRORS 57 · TRBETWEEN 65 · HELP 1f · STATUS 30 ·
POINT 3b · SEPARATOR 3c · ALTERNATE 01 · DEVICE 11 · FILTER 1a ·
INDEX 21 · ORDER 28 · PATH 29 · DEFAULT 0e · PROCEDURE 2b ·
**LIBRARY 62 (+ADDITIVE trailing 01)** · DATASESSION 80

Suffixes: 1f=OFF, 20=ON; value settings take 28(TO)+expression.

## Clause bytes — one contextual namespace (do NOT fold into statement leads)

Measured across families (CMD_SWEEP.md clause section has every citing pair):
12 FILE · 13 FOR · 14 FORM · 15 FROM · 16 IN · 20 ON · 25 SAVE · 28 TO ·
29 TOP · 2b WHILE · 2c WINDOW · 38 BY · 3a NOWAIT · 3c DESCENDING ·
01 ADDITIVE · 03 ALL · 32 LABEL(ON KEY) · 53 NOREAD · 64 POSITION · c7 XLS ·
ca TAG/SET · be DELIMITED/LINKED-slot · cc STRUCTURE · d6 NORMAL ·
d1 WITH (REPLACE / JOIN / APPEND DELIMITED WITH) · d4 TYPE (APPEND/EXPORT/IMPORT) ·
c6 WHERE (SELECT-SQL / UPDATE-SQL)

ON-family event selectors after lead 31: ERROR 10 · ESCAPE bd · KEY 17 (+32 LABEL) ·
READERROR c8 · SHUTDOWN cd. Reset forms use lead 7b (`7b 10 fb 0000`).

**ea19 rule**: emitted between group-open and arguments iff an ARRAY is passed by
reference to a builtin (ADIR ea15, AMEMBERS ea62, AINSTANCE ea a5 measured; GETFILE
shows no marker). The trailing closer is still the callee.

## Literal encoding

| type | encoding | example |
|---|---|---|
| int8 | `f8 <digits> <val>` | `f8 01 07` = 7; `f8 02 14` = 20 |
| int16 | `f9 <digits> <lo> <hi>` | `f9 03 2c 01` = 300; `f9 02 fb ff` = −5 |
| int32 | `e9 <digits> <4B LE>` | `e9 07 40 42 0f 00` = 1000000 |
| float64 | `fa <tot_digits> <frac_digits> <8B IEEE754>` | `fa 03 01 …` = 1.5 |
| str_dq | `d9 <u16 len> <bytes>` | double-quoted source |
| str_sq | `fb <u16 len> <bytes>` | single-quoted source |
| binary | `ff 01 <u16 len LE> <raw bytes>` | `ff 01 02 00 efbb` = `0hEFBB`; odd nibbles pad high-first; empty `0h` = len 0. Round-27 |
| date | `ee <8B>` | `{}`/`{:}`/`{//}` all = ee + zero payload; `{^2024-01-31}` = ee 000000805ac54241. Round-27 |
| datetime | `e6 <8B>` | `{^2024-01-31 12:34:56}` = e6 6bed1ac35ac54241. Round-27 |
| currency | `de <08/06 open> 04 <8B i64LE scaled x10^4>` | `$100.50` = de 08 04 c8550f0000000000; byte-2 open (08/06). Round-27 |

Digits prefix = decimal character count of the value's source representation.

## Line-info block

Per-line words follow the final symbol table:
    word = (on-disk statement byte count) << 4 | marker(=1)
Verified delta=0 on 58/60 our-fxp probes and 380/380 YiFeiERP modules.
Low nibble = constant marker on our compiles; cross-repo values 0–6 are
matching artifacts (suspected). Block preceded by an 8–34 word header
(structure open).

## Outer APP container

Header: magic fe f2 ff 20 + ver byte(0x02) + opaque words; pool pointers
BASE-RELATIVE at +9(pool_end)/+13(pool_start), +17 pool byte-length.
Record array after pool terminator, stride 25:
[u8 seq][u32 start][u32 end][u32 col_x=dir-name-pool-offset][u32 col_y=name-pool-offset]
[u64 pad]. col_y binds each record to its primary name by REFERENCE.
Ranges chain and tile [header_end .. pool_start).
Compiled payloads do NOT carry module magic inside containers.
