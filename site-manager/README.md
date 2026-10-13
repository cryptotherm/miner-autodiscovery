# Cryptotherm Mine Manager

Site-management daemon for a live mining colony. It **monitors, diagnoses,
flags, reports, notifies, and (optionally, with guardrails) operates** the
whole fleet.

This is **not** the bench/repair tool (`../autodiscovery.py`). There is **no
label printing, QR, or ticket/scan workflow** here — this watches miners that
are already deployed and keeps them running.

## What it does

- **Monitor** — every cycle, sweeps the site subnet and polls *all* miners
  (hashrate, shares, fans, ASIC chains, pool status, temperature).
- **Diagnose** — classifies each miner: `OK`, `WARMUP`, `WARN`, `HUNG`,
  `FAULT`, `OFFLINE`, with an issue code (`FAN-FAIL`, `OVERHEAT`,
  `ASIC-CHAINn-PARTIAL`, `POOL-DEAD`, `NO-HASH`, `TEMP-HIGH`, `LOW-HASH`,
  `UNREACHABLE`).
- **Flag & notify** — edge-triggered alerts (once when an issue appears, once
  when it clears) to a webhook (Slack/Discord/generic) and/or email, filtered
  by severity.
- **Report** — periodic fleet health report (text + JSON) to `reports/`,
  optionally delivered to the notify channels.
- **Operate (guarded)** — auto-reboots *hung* miners only, with cooldown +
  daily cap. Manual `restart` and `set-pool` subcommands for operators.

## Safety model (read this)

Defaults are deliberately timid — first run **observes and touches nothing**:

| Control | Default | Effect |
|---------|---------|--------|
| `dry_run` | `true` | No command is ever sent; the log shows what it *would* do |
| `auto_restart` | `false` | Even off dry-run, no auto-reboots until you enable it |
| dead-fan rule | always | A miner with any 0-RPM fan is **never** auto-restarted (thermal safety) — flagged only |
| restart cooldown / cap | 30 min / 3 per day | Per-miner limits so it can't reboot-loop a miner |
| `allow_pool_changes` | `false` | Pool changes are refused outright |

### Pool changes are never automatic

The monitor loop **cannot** change a pool. Pool changes happen only via the
manual `set-pool` command, and only if **all** of these hold:

1. `operations.allow_pool_changes = true`
2. the target URL is listed in `operations.approved_pools`
3. you retype the miner's IP at the prompt (unless `--yes`)
4. `dry_run = false`

Every reboot / pool change is appended to `mine-manager-audit.log`.

## Install

Runs on **Windows** (your sites) or Linux. Put it on an always-on box on the
miner LAN.

### Windows (site default)

```powershell
# elevated PowerShell, from the site-manager folder
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install-site-manager.ps1        # installs Python deps + a boot scheduled task
# then edit C:\CT\mine-manager\mine-manager.conf  (subnet, notify, thresholds)
& python C:\CT\mine-manager\mine-manager.py status   # sanity check
Start-ScheduledTask -TaskName 'CT Mine Manager'
Get-Content C:\CT\mine-manager\mine-manager.out.log -Wait
```

Secrets go in **machine** environment variables (not the repo):
`setx /M CT_MINER_PASS ...`, `CT_SMTP_PASS`, `CT_SERVER_TOKEN`, `CT_PLATFORM_TOKEN`.

### Linux

```bash
cd site-manager
cp mine-manager.conf.example mine-manager.conf   # EDIT: subnet, notify, thresholds
sudo bash install-site-manager.sh                # systemd service (does not auto-start)
sudo systemctl start ct-mine-manager
journalctl -u ct-mine-manager -f
```

Secrets go in the service environment (see the unit file).

## Per-miner history (MAC-keyed)

Every sweep writes a time-series **sample** per miner to a local SQLite DB
(`storage.db`), keyed by **MAC address** (stable identity across IP changes),
plus an `events` log (issue open/clear, reboots, pool changes). Each sample
captures hashrate, ideal, temp, **power (watts)**, shares, state, and issue —
the full history the server/dashboard and the billing model need.

```bash
python3 mine-manager.py history AA:BB:CC:DD:EE:FF      # recent samples for a miner
```

Set `storage.server_push_url` to also forward every sweep to a central server
(e.g. Cole's dashboard backend), so history is queryable server-side rather
than only on each site box. Off by default; it does **not** stand up a new
server — point it at the existing one.

## Billing (power per client)

Assign each miner to a client, then bill by integrating power over time:

```bash
python3 mine-manager.py assign AA:BB:CC:DD:EE:FF --client "Acme" --rated-watts 3010
python3 mine-manager.py bill --from 2026-09-01 --to 2026-10-01     # kWh + $ per client
python3 mine-manager.py bill --json                                # machine-readable
```

Power is **measured** when the miner's API reports watts, otherwise **estimated**
from a rough nameplate table. `estimate_power()` in `mine-manager.py` is the
**drop-in hook for Graeson's ML power model** — replace it and every sample +
bill uses the ML estimate automatically. `billing.rate_per_kwh` sets the price.

## Remote management

The site box joins Tailscale (via the onboarding USB kit), so you manage it
remotely by SSHing in and running any subcommand (`status`, `restart <ip>`,
`bill`, etc.). For dashboard-driven control, `server_push_url` feeds the
server; a control API can be added once Cole's dashboard contract is known.

## Run it by hand

```bash
python3 mine-manager.py status                 # one-shot fleet snapshot
python3 mine-manager.py report                 # generate a report now
python3 mine-manager.py restart 10.0.0.42      # manual reboot (respects dry_run)
python3 mine-manager.py set-pool 10.0.0.42 --url stratum+tcp://... --user WORKER --yes
```

## Config

See `mine-manager.conf.example` — every setting is documented inline. Copy it
to `mine-manager.conf` (git-ignored) and edit per site. The most important
first edits: `[site] subnet`, `[notify] webhook_url`, and the `[thresholds]`.

## Notes / limitations

- Auto-restart uses Antminer `reboot.cgi` by default (`restart_method = web`),
  or the cgminer API (`restart_method = cgminer`).
- `set-pool` uses cgminer privileged `addpool`/`switchpool`, which require the
  miner's API to allow writes. On stock firmware with a read-only API you may
  need to change pools through the web admin instead — the command will log a
  failure rather than silently "succeed".
- Temperature is best-effort across firmware variants; verify the field
  mapping against your fleet before relying on `OVERHEAT`/`TEMP-HIGH`.
