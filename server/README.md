# Cryptotherm Collector + Dashboard

Central server that ties the sites together: every site's Mine Manager pushes
its sweeps here, so **per-miner history lives in one place**, viewable on a
live **dashboard**, with **billing** and **guarded remote restart**.

Zero external dependencies — Python stdlib only. Runs anywhere `python3` runs
(put it on an always-on box like cthome, on the tailnet).

This is our own standalone dashboard/server. It's intentionally simple so
**Cole's dashboard and Graeson's ML model can replace or augment it later** —
agents push a documented JSON payload to `/ingest`, so pointing them at a
different backend is a one-line config change.

## Run

```bash
cd server
cp collector.conf.example collector.conf     # edit host/port/rate
export CT_SERVER_TOKEN="$(openssl rand -hex 24)"   # shared write token
python3 collector.py                          # http://<host>:8090/
```

Or install as a service: `sudo bash install-collector.sh` (systemd).

Then on each site's Mine Manager, set:

```ini
[storage]
server_push_url       = http://<collector-host>:8090/ingest
server_push_token_env = CT_SERVER_TOKEN
```
and export the **same** `CT_SERVER_TOKEN` there.

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/ingest` | ✅ | agents push `{site, ts, miners:[…]}`; response carries any queued commands |
| GET | `/` | — | live dashboard (fleet + billing tabs) |
| GET | `/api/fleet` | — | current state of every miner |
| GET | `/api/miner/<mac>/history?limit=N` | — | time-series for one miner |
| GET | `/api/billing?from=&to=` | — | kWh + cost per client |
| POST | `/api/assign` | ✅ | `{mac, client, rated_watts}` |
| POST | `/api/command` | ✅ | `{site, mac, ip, type:"restart"}` → queued for the agent |
| GET | `/health` | — | liveness |

Write endpoints require `Authorization: Bearer <CT_SERVER_TOKEN>`. Read
endpoints are open for the trusted (Tailscale/LAN) network — bind `host` to the
Tailscale IP if you want them private too. **If no token is set, writes are
open** (dev only) and the server warns at startup.

## Remote restart (guarded, end-to-end)

1. Dashboard/operator → `POST /api/command {type:"restart", …}` — server queues it.
2. Next time that site's agent pushes to `/ingest`, the server hands back the
   command in the response.
3. The agent runs it **only if** `operations.accept_remote_commands=true`, and
   still honors `dry_run`, the restart cooldown, and the per-day cap. Only
   `restart` is ever honored remotely — **pool changes are never remote** (they
   stay manual + allowlisted on the site box).

## Data model

- `miners` — one row per MAC (stable identity): site, ip, model, serial,
  client, rated_watts, last state/issue/hashrate/temp/power, first/last seen.
- `samples` — full time-series (hashrate, ideal, temp, power, source, state, issue).
- `commands` — queued remote actions with delivery status.

## Billing

Same integration as the site tool: energy per miner = power integrated over
real sample time-deltas (gaps capped by `max_gap_seconds` so downtime isn't
billed), grouped by the client each miner is assigned to, times
`rate_per_kwh`. Assign miners with `POST /api/assign` (or on the site box:
`mine-manager.py assign <mac> --client X`).
