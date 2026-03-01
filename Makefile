MCS = mcs
SRC = src/SocksDSharp.cs
TPL = src/loader.ps1.template
EXE = dist/socksd.exe
LOADER = dist/socksd.ps1

WINBOX = winbox
WIN_IP = 192.168.122.197
TEST_PORT = 1080

REFS = -r:System.dll -r:System.Core.dll
FLAGS = -optimize+ -unsafe+ -target:exe -sdk:4.5

all: exe loader

exe: $(EXE)

$(EXE): $(SRC)
	@mkdir -p dist
	$(MCS) $(FLAGS) $(REFS) -out:$(EXE) $(SRC)

loader: $(LOADER)

$(LOADER): $(EXE) $(TPL)
	@mkdir -p dist
	@echo '[*] Generating reflective loader...'
	@sed 's|@@BASE64@@|'"$$(base64 -w 0 $(EXE))"'|' $(TPL) > $(LOADER)
	@echo '[+] $(LOADER) generated'

deploy: all
	@command -v $(WINBOX) >/dev/null 2>&1 || { echo '[-] winbox not found'; exit 1; }
	@echo '[*] Killing leftover socksd processes...'
	@$(WINBOX) exec 'taskkill /F /IM socksd.exe' >/dev/null 2>&1 || true
	@$(WINBOX) exec 'taskkill /F /IM powershell.exe' >/dev/null 2>&1 || true
	@echo '[*] Purging old files from VM...'
	@$(WINBOX) exec 'del /F /Q Z:\tools\socksd.exe Z:\tools\socksd.ps1' >/dev/null 2>&1 || true
	@sleep 2
	@$(WINBOX) exec 'dir Z:\tools\socksd.exe' >/dev/null 2>&1 && { echo '[-] socksd.exe still present after delete'; exit 1; }; true
	@$(WINBOX) exec 'dir Z:\tools\socksd.ps1' >/dev/null 2>&1 && { echo '[-] socksd.ps1 still present after delete'; exit 1; }; true
	@echo '[+] Old files removed'
	@$(WINBOX) tools add $(EXE) $(LOADER)
	@sleep 2
	@$(WINBOX) exec 'dir Z:\tools\socksd.exe' >/dev/null 2>&1 || { echo '[-] socksd.exe not found after upload'; exit 1; }
	@$(WINBOX) exec 'dir Z:\tools\socksd.ps1' >/dev/null 2>&1 || { echo '[-] socksd.ps1 not found after upload'; exit 1; }
	@echo '[+] Fresh files deployed'

test: deploy
	@echo '[*] Testing EXE (outbound)...'
	@JOB_EXE=$$($(WINBOX) exec --bg 'Z:\tools\socksd.exe -p $(TEST_PORT)' | grep -oP 'PID \K\d+'); \
	  sleep 2; \
	  RESULT=$$(curl -s --max-time 10 --socks5-hostname $(WIN_IP):$(TEST_PORT) http://ifconfig.me); \
	  if [ -n "$$RESULT" ]; then echo "[+] EXE outbound OK ($$RESULT)"; else $(WINBOX) exec "taskkill /F /PID $$JOB_EXE" >/dev/null 2>&1; echo '[-] EXE outbound FAILED'; exit 1; fi; \
	  echo '[*] Testing EXE (loopback 127.0.0.1:5985)...'; \
	  STATUS=$$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --socks5-hostname $(WIN_IP):$(TEST_PORT) http://127.0.0.1:5985); \
	  $(WINBOX) exec "taskkill /F /PID $$JOB_EXE" >/dev/null 2>&1; \
	  if [ -n "$$STATUS" ] && [ "$$STATUS" != "000" ]; then echo "[+] EXE loopback OK (HTTP $$STATUS)"; else echo '[-] EXE loopback FAILED'; exit 1; fi
	@echo '[*] Testing PS1...'
	@JOB_PS1=$$($(WINBOX) exec --bg 'powershell -ep bypass -f Z:\tools\socksd.ps1 -p $(TEST_PORT)' | grep -oP 'PID \K\d+'); \
	  sleep 2; \
	  RESULT=$$(curl -s --max-time 10 --socks5-hostname $(WIN_IP):$(TEST_PORT) http://ifconfig.me); \
	  $(WINBOX) exec "taskkill /F /PID $$JOB_PS1" >/dev/null 2>&1; \
	  if [ -n "$$RESULT" ]; then echo "[+] PS1 OK ($$RESULT)"; else echo '[-] PS1 FAILED'; exit 1; fi
	@echo '[+] All tests passed'

clean:
	rm -rf dist

.PHONY: all exe loader clean deploy test
