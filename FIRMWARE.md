# Firmware Compatibility & Update Reference

Reference for the CT test bench: which firmware goes on which miner, where to
get it, and how autodiscovery classifies what it finds. Last reviewed:
2026-08-29.

## Bench policy

- **Approved outgoing firmware:** stock (Bitmain/MicroBT), Braiins OS+, LuxOS.
  Configured in `autodiscovery.conf` → `approved_firmware`.
- **Incoming units with Vnish** (or anything not approved): autodiscovery
  flags `needs_reflash=true` in telemetry and prints it on the label. Wipe and
  install stock / Braiins / LuxOS per batch preference before shipping.
- Firmware images are **model- and control-board-specific**. Never flash an
  S19 image onto an S21; never flash a Xilinx/Zynq image onto an Amlogic or
  Cvitek board. Check the control board before batch flashing.

## Latest-generation models on the bench

### Bitmain S21 family (SHA-256)

| Model | Nameplate | Notes |
|---|---|---|
| S21 | ~200 TH/s | air |
| S21e | ~195 TH/s | air |
| S21+ | ~216 TH/s | air; A3HB70702/A3HB70703 hashboards |
| S21 Pro | ~234 TH/s | air |
| S21 Pro+ | — | newest; support added in Braiins OS 26.07 / recent LuxOS (A3HB70606 boards) |
| S21 XP | ~270 TH/s | air; also Hyd/Imm variants |
| T21 | ~190 TH/s | air |

Hydro (Hyd.) and immersion (Imm.) variants exist for most of these; they need
their own firmware images.

### MicroBT WhatsMiner M5x/M6x (SHA-256)

| Model | Nameplate | Cooling |
|---|---|---|
| M56 / M56S | 194 / 212 TH/s | hydro |
| M60 / M60S | 172 / 186 TH/s | air |
| M66 | 276 TH/s | hydro |
| M66S | 298 TH/s | hydro |
| M66S+ | 318 TH/s | hydro |
| M66S++ | 348 TH/s | hydro |

## Firmware sources (download on the shop network)

**Stock:**
- Bitmain: firmware section of bitmain.com support (per-model, per-board
  images). Mirrors with official images: [Zeus Mining download center](https://www.zeusbtc.com/firmware-download/antminer-firmware/),
  [hashrate.farm firmware hub](https://www.hashrate.farm/mining-hub/firmwares),
  [7miners stock recovery images](https://7miners.net/en/bitmain-stock-firmware/)
- MicroBT: [official WhatsMiner site/shop](https://shop.whatsminer.com) — use
  the WhatsMinerTool for batch updates; firmware is distributed per-model
  through their support channel.

**Braiins OS+** — [braiins.com/os-firmware](https://braiins.com/os-firmware),
images at [downloads.braiins.com/braiins-os](https://downloads.braiins.com/braiins-os/),
batch install/remote management via [Braiins Toolbox](https://downloads.braiins.com/braiins-toolbox/).
- Supports S19 family (incl. S19k Pro, S19j Pro, S19 XP), S21, S21+, S21 Pro,
  S21 Pro+ (as of 26.07), S21 XP, T21, plus Hyd./Imm. variants, across
  Zynq/Xilinx, Amlogic, BeagleBone and Cvitek control boards.
- WhatsMiners: Toolbox can manage/configure stock-firmware WhatsMiners, but
  Braiins OS itself does not run on M5x/M6x — keep those on MicroBT stock.
- What's new: [academy.braiins.com/braiins-os/whats-new](https://academy.braiins.com/braiins-os/whats-new)

**LuxOS (Luxor)** — [docs.luxor.tech/firmware/compatibility](https://docs.luxor.tech/firmware/compatibility)
(authoritative list), [changelog](https://docs.luxor.tech/firmware/changelog).
- S19 and S21 generations only (air + hydro): S19/S19 Pro (Xilinx boards),
  S19j Pro, S19 XP; S21 series incl. recent S21+ (A3HB70702/70703) and
  S21 Pro+ (A3HB70606) additions. No S9/S17 support, no WhatsMiner support.

**Vnish** — [vnish.com](https://vnish.com) — S19/S21/T21 images exist
([vnish S21/T21 page](https://vnish.us/vnish-21/)). **Not approved for
outgoing units here** — detected and flagged for reflash.

Good cross-vendor how-to (stock / Braiins / Vnish / LuxOS, every model &
method): [D-Central Antminer firmware update guide](https://d-central.tech/antminer-firmware-update-guide/).

## How autodiscovery classifies firmware

`detect_firmware()` inspects the cgminer/btminer `version` API response:

| Family | Signature |
|---|---|
| `braiins` | `BOSminer`/`Braiins` fields in version JSON |
| `luxos` | `LUXminer` in version JSON |
| `vnish` | `vnish` anywhere in version/web info (Vnish appends itself to `Type`) |
| `stock` | `BMMiner`/`CGMiner` (Bitmain) or `BTMiner` (MicroBT) |
| `unknown` | none of the above (flagged for reflash) |

Note: newer Bitmain stock firmware (2023+) ships with the cgminer TCP API
restricted on some models; those units are still discovered by port 4028 but
may need web-API auth (`root`/`root` default; set the bench password in
`get_web_info` if changed) for serials and stats.

## Auto-reflash pipeline (platform work, not this repo)

The wipe-and-flash workflow (detect Vnish → wipe → install stock/Braiins/LuxOS
per batch toggle) needs the platform backend: batch settings UI, image
storage, and per-model flash drivers (Bitmain SD/web flash, Braiins Toolbox
CLI, WhatsMinerTool). This repo now supplies the trigger signals
(`firmware_type`, `needs_reflash`, `pool_known`) in registration and
telemetry payloads.
