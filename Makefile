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
	@echo '# socksd reflective loader' > $(LOADER)
	@echo '# Usage: powershell -ep bypass -f socksd.ps1 [args]' >> $(LOADER)
	@echo '# Usage: Invoke-SocksD [args]' >> $(LOADER)
	@echo '' >> $(LOADER)
	@echo 'function Invoke-SocksD {' >> $(LOADER)
	@echo '    $$b64 = @"' >> $(LOADER)
	@base64 -w 0 $(EXE) >> $(LOADER)
	@echo '' >> $(LOADER)
	@echo '"@' >> $(LOADER)
	@echo '    $$bytes = [Convert]::FromBase64String($$b64)' >> $(LOADER)
	@echo '    $$asm = [Reflection.Assembly]::Load($$bytes)' >> $(LOADER)
	@echo '    $$asm.EntryPoint.Invoke($$null, @(,([string[]]$$args)))' >> $(LOADER)
	@echo '}' >> $(LOADER)
	@echo '' >> $(LOADER)
	@echo 'if ($$MyInvocation.InvocationName -ne ".") {' >> $(LOADER)
	@echo '    Invoke-SocksD @args' >> $(LOADER)
	@echo '}' >> $(LOADER)
	@echo '[+] $(LOADER) generated'

clean:
	rm -f $(EXE) $(LOADER)

.PHONY: all exe loader clean
