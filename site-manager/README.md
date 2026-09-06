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

On an always-on Linux box at the site (Pi / mini-PC / NUC), on the miner LAN:

```bash
cd site-manager
cp mine-manager.conf.example mine-manager.conf   # then EDIT: subnet, notify, thresholds
sudo bash install-site-manager.sh                # installs a systemd service (does not auto-start)
sudo systemctl start ct-mine-manager
journalctl -u ct-mine-manager -f
```

Put secrets in the service environment, never in the repo:
`CT_MINER_PASS`, `CT_SMTP_PASS`, `CT_PLATFORM_TOKEN` (see the unit file).

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
