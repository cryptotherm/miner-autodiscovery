# Cryptotherm Miner Auto-Discovery

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

Edit `autodiscovery.conf` (now actually loaded by the script; hardcoded
values are only fallbacks):
- `platform_api` — platform API URL
- `platform_token` — auth token
- `printer_ip` — QL-810W IP (currently `10.0.0.119`)
- `subnet` — network to scan (currently `10.0.0`)
- `scan_interval` — seconds between sweeps (default 30)
- `known_pools` — pool URL substrings we operate; unknown pools are flagged
  for tagging in the platform GUI
- `approved_firmware` — firmware families allowed on outgoing units
  (default `stock, braiins, luxos`); anything else (e.g. Vnish) is flagged
  `needs_reflash`

## Firmware

Autodiscovery detects the firmware family on every unit (stock / Braiins OS /
LuxOS / Vnish) and reports it in registration + telemetry and on the printed
label. See [FIRMWARE.md](FIRMWARE.md) for the model/firmware compatibility
matrix (S21 family, WhatsMiner M5x/M6x) and download sources.

## State

Discovered miners are cached in `/tmp/ct_discovered_miners.json` — delete to re-discover.

## Requirements

```
pip install requests brother_ql qrcode pillow
```
