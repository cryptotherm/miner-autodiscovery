# Cryptotherm Miner Auto-Discovery

> **⚠ Deprecated for the test bench (2026-08-18).** Bench discovery is owned by
> the `miner-testbench` server's autoscan loop (racks on `192.168.2-6.x`);
> this tool scans `10.0.0.x`, which the bench must not touch (inference/control
> nodes). Keep this tool only if the separate platform/CTOps fleet needs its
> own discovery agent — otherwise archive the repo.
>
> **⚠ Rotate the platform token.** A live `xk_…` bearer token was committed to
> this **public** repository (in `autodiscovery.py` and `autodiscovery.conf`).
> It has been removed from the code, but it lives on in git history — rotate it
> on the platform. Configuration now comes from `autodiscovery.conf` /
> `CT_*` environment variables only.

Automatically detects new miners on the network, runs a full diagnostic, registers them in the platform API, and prints a CT tracking label on the QL-810W.

## How it works

1. Scans `10.0.0.1-254` on port 4028 (cgminer API) every 30 seconds
2. When a **new** miner is found (not in state cache):
   - Queries cgminer API for version, summary, pools
   - Pulls fan RPMs and chain/ASIC data from web admin
   - Waits up to 10 min if still warming up
   - Runs fault detection (dead fans, partial ASIC, pool dead)
   - Assigns a CT tracking ID (`CT-YYYY-NNN`)
   - Registers in platform API at `http://20.125.62.35:8080`
   - Pushes telemetry
   - **Prints a label** on the QL-810W at `10.0.0.119`

## Fault Detection

| Fault Code | Trigger | Action |
|------------|---------|--------|
| `FAN-INLET-FAIL` | Any fan = 0 RPM | Print fault sticker, FAIL |
| `ASIC-CHAIN{N}-PARTIAL` | Missing ASICs on a chain | Print fault sticker, FAIL |
| `POOL-DEAD` | Pool status Dead after 5+ min | Print fault sticker, FAIL |

## Install

### CTHome (Linux)
```bash
sudo bash install-linux.sh
```

### MacBook / Mac Pro (macOS)
```bash
bash install-mac.sh
```

### Alienware (Windows)
```batch
# Run as Administrator
install-windows.bat
```

## Config

Edit `autodiscovery.conf`:
- `platform_api` — platform API URL
- `platform_token` — auth token
- `printer_ip` — QL-810W IP (currently `10.0.0.119`)
- `subnet` — network to scan (currently `10.0.0`)
- `scan_interval` — seconds between sweeps (default 30)

## State

Discovered miners are cached in `/var/lib/ct-autodiscovery/discovered_miners.json`
(falling back to `~/.ct-autodiscovery/`, then `/tmp`). Delete the file to
re-discover. State used to live only in `/tmp`, which is cleared on reboot —
that caused every miner to be re-registered and re-labelled after each restart.

Miners that are still warming up are recorded as `PENDING` and re-checked on
subsequent sweeps (the loop no longer blocks for 10 minutes per warming miner);
a final verdict is forced after 20 minutes.

## Known limitations (left as-is — bench duty moved to miner-testbench)

- Identity is fingerprinted on `ip:mac`, so a DHCP address change re-registers
  the unit (the testbench keys purely on MAC)
- The label-printing path generates a Python script and pipes it over SSH with
  hardcoded host details — use the testbench's print proxy instead
- `arp`-based MAC lookup misses hosts on other L2 segments

## Requirements

```
pip install requests brother_ql qrcode pillow
```
