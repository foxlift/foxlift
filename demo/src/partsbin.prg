* ABOUTME: PartsBin - a tiny stockroom report over an in-memory cursor.
* ABOUTME: Authored for the FoxLift round-trip demo; original work, safe to redistribute.

* A cursor stands in for the stockroom table so the demo runs with no files on disk.
CREATE CURSOR parts (sku C(8), descr C(30), qty I, price N(8,2))
INSERT INTO parts VALUES ('AX-0048', 'Hex bolt M6', 500, 0.50)
INSERT INTO parts VALUES ('BR-0112', 'Ball bearing 608', 24, 3.75)
INSERT INTO parts VALUES ('CM-0007', 'Cam follower', 3, 18.20)

LOCAL lnSlot, lcBand, lnRestock, lnI
lnRestock = 0048
DIMENSION laRow[4]
DIMENSION laBand(3)
laBand[1] = 'LOW'
laBand(2) = 'OK'
laBand[3] = 'FULL'

* Top up the first part through SCATTER/GATHER.
GO TOP
SCATTER TO laRow
laRow[3] = laRow[3] + lnRestock
GATHER FROM laRow

DO CASE
CASE parts.qty < 10
	lnSlot = 1
CASE parts.qty < 100
	lnSlot = 2
OTHERWISE
	lnSlot = 3
ENDCASE
lcBand = laBand(lnSlot)

GO TOP
FOR lnI = 1 TO 3
	? PADR(parts.sku, 10) + PADR(parts.descr, 20) + TRANSFORM(parts.qty)
	SKIP
ENDFOR
? 'First bin is ' + lcBand
