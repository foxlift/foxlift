* ABOUTME: CounterForm - builds a runtime form, calls two Win32 APIs, fills a TEXT template.
* ABOUTME: Authored for the FoxLift round-trip demo; original work, safe to redistribute.

DECLARE INTEGER GetTickCount IN kernel32
DECLARE INTEGER GetCursorPos IN user32 STRING @ lpPoint

LOCAL loForm, lcPoint, lnStarted, lnElapsed, lcNote, lnOk
lnStarted = GetTickCount()

* The pointer position comes back through an @ by-reference buffer.
lcPoint = SPACE(8)
lnOk = GetCursorPos(@lcPoint)

loForm = CREATEOBJECT('Form')
loForm.Caption = 'PartsBin Counter'
loForm.AddObject('lblTitle', 'Label')
loForm.lblTitle.Caption = 'Ready to count'
loForm.lblTitle.Visible = .T.
IF lnOk = 0
	loForm.lblTitle.Caption = 'Pointer unavailable'
ENDIF

TEXT TO lcNote NOSHOW
PartsBin counted your stockroom.
Coffee first, labels later.
ENDTEXT

lnElapsed = GetTickCount() - lnStarted
WAIT WINDOW 'Session took ' + TRANSFORM(lnElapsed) + ' ms' NOWAIT NOCLEAR
loForm.Show()
WAIT WINDOW lcNote TIMEOUT 2
