MCS = mcs
SRC = SocksDSharp.cs
EXE = socksd.exe
LOADER = socksd.ps1

REFS = -r:System.dll -r:System.Core.dll
FLAGS = -optimize+ -target:exe -sdk:4.5

all: exe loader

exe: $(EXE)

$(EXE): $(SRC)
	$(MCS) $(FLAGS) $(REFS) -out:$(EXE) $(SRC)

loader: $(LOADER)

$(LOADER): $(EXE)
	@echo '[*] Generating reflective loader...'
	@printf '%s\n' \
	  '# socksd reflective loader' \
	  '# Usage: powershell -ep bypass -f socksd.ps1 -Port 1080' \
	  '# Usage: Invoke-SocksD -Port 1080 -User admin -Pass secret' \
	  '' \
	  'function Invoke-SocksD {' \
	  '    param(' \
	  '        [string]$$IP,' \
	  '        [int]$$Port,' \
	  '        [string]$$User,' \
	  '        [string]$$Pass,' \
	  '        [switch]$$Bind,' \
	  '        [switch]$$AuthOnce,' \
	  '        [switch]$$Quiet,' \
	  '        [switch]$$Help' \
	  '    )' \
	  '    $$a = @()' \
	  '    if ($$IP)       { $$a += "-i", $$IP }' \
	  '    if ($$Port)     { $$a += "-p", [string]$$Port }' \
	  '    if ($$User)     { $$a += "-u", $$User }' \
	  '    if ($$Pass)     { $$a += "-P", $$Pass }' \
	  '    if ($$Bind)     { $$a += "-b" }' \
	  '    if ($$AuthOnce) { $$a += "-1" }' \
	  '    if ($$Quiet)    { $$a += "-q" }' \
	  '    if ($$Help)     { $$a += "-h" }' \
	  > $(LOADER)
	@echo '    $$b64 = @"' >> $(LOADER)
	@base64 -w 0 $(EXE) >> $(LOADER)
	@printf '\n%s\n' \
	  '"@' \
	  '    $$bytes = [Convert]::FromBase64String($$b64)' \
	  '    $$asm = [Reflection.Assembly]::Load($$bytes)' \
	  '    $$asm.EntryPoint.Invoke($$null, @(,([string[]]$$a)))' \
	  '}' \
	  '' \
	  'if ($$MyInvocation.InvocationName -ne ".") {' \
	  '    Invoke-SocksD @PSBoundParameters' \
	  '}' \
	  >> $(LOADER)
	@echo '[+] $(LOADER) generated'

clean:
	rm -f $(EXE) $(LOADER)

.PHONY: all exe loader clean
