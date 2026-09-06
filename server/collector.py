#!/usr/bin/env python3
"""
Cryptotherm Collector + Dashboard
=================================
Central server that receives sweeps from every site's Mine Manager, keeps a
per-miner history (keyed by MAC) in one place, serves a live dashboard, and
answers billing/history queries. Zero external dependencies — Python stdlib
only, so it runs anywhere python3 does.

Endpoints
  POST /ingest            (auth) agents push {site, ts, miners:[...]} here
  GET  /                        the live dashboard (HTML)
  GET  /api/fleet               current state of every known miner (JSON)
  GET  /api/miner/<mac>/history recent samples for one miner (JSON)
  GET  /api/billing?from=&to=   kWh + cost per client (JSON)
  POST /api/assign        (auth) {mac, client, rated_watts}
  POST /api/command       (auth) {mac|ip, site, type:"restart"} — queued, guarded
  GET  /health

Config: collector.conf (see collector.conf.example). The write endpoints
require a bearer token (CT_SERVER_TOKEN); reads are open for the trusted
(Tailscale/LAN) network. Point each site's storage.server_push_url at
http://<this-host>:<port>/ingest and share the token as CT_SERVER_TOKEN.
"""

import configparser
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DEFAULTS = {
    "server":  {"host": "0.0.0.0", "port": "8090", "db": "./collector.db",
                "token_env": "CT_SERVER_TOKEN"},
    "billing": {"rate_per_kwh": "0.10", "max_gap_seconds": "180"},
}

_LOCAL = threading.local()


def load_config(path):
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read_dict(DEFAULTS)
    if path and os.path.exists(path):
        cfg.read(path)
    return cfg


def db(cfg) -> sqlite3.Connection:
    conn = getattr(_LOCAL, "conn", None)
    if conn is None:
        conn = sqlite3.connect(cfg.get("server", "db"), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS miners (
                mac TEXT PRIMARY KEY, site TEXT, ip TEXT, model TEXT, serial TEXT,
                client TEXT, rated_watts REAL, first_seen TEXT, last_seen TEXT,
                last_state TEXT, last_issue TEXT, last_hashrate REAL,
                last_temp REAL, last_power REAL
            );
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, site TEXT, ts TEXT,
                hashrate REAL, ideal REAL, temp_max REAL, power_watts REAL,
                power_source TEXT, state TEXT, issue TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_samples_mac_ts ON samples(mac, ts);
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT, mac TEXT, ip TEXT,
                type TEXT, status TEXT, created TEXT, delivered TEXT
            );
            """
        )
        conn.commit()
        _LOCAL.conn = conn
    return conn


def ingest(cfg, payload):
    conn = db(cfg)
    site = payload.get("site", "unknown")
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    for m in payload.get("miners", []):
        mac = m.get("mac") or f"ip:{m.get('ip','?')}"
        if mac == "00:00:00:00:00:00":
            mac = f"ip:{m.get('ip','?')}"
        cur.execute("SELECT mac FROM miners WHERE mac=?", (mac,))
        if cur.fetchone():
            cur.execute(
                "UPDATE miners SET site=?, ip=?, model=COALESCE(NULLIF(?,''),model), "
                "serial=COALESCE(NULLIF(?,''),serial), last_seen=?, last_state=?, "
                "last_issue=?, last_hashrate=?, last_temp=?, last_power=? WHERE mac=?",
                (site, m.get("ip", ""), m.get("model", ""), m.get("serial", ""), now,
                 m.get("state", ""), m.get("issue"), m.get("hashrate", 0),
                 m.get("temp_max", 0), m.get("power_watts", 0), mac))
        else:
            cur.execute(
                "INSERT INTO miners(mac,site,ip,model,serial,first_seen,last_seen,"
                "last_state,last_issue,last_hashrate,last_temp,last_power) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (mac, site, m.get("ip", ""), m.get("model", ""), m.get("serial", ""), now, now,
                 m.get("state", ""), m.get("issue"), m.get("hashrate", 0),
                 m.get("temp_max", 0), m.get("power_watts", 0)))
        cur.execute(
            "INSERT INTO samples(mac,site,ts,hashrate,ideal,temp_max,power_watts,"
            "power_source,state,issue) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (mac, site, m.get("ts", now), m.get("hashrate", 0), m.get("ideal", 0),
             m.get("temp_max", 0), m.get("power_watts", 0), m.get("power_source", ""),
             m.get("state", ""), m.get("issue")))
    conn.commit()
    # return any pending restart commands for this site (at-most-once delivery)
    pend = cur.execute(
        "SELECT id,mac,ip,type FROM commands WHERE site=? AND status='pending'", (site,)).fetchall()
    out = []
    for row in pend:
        out.append({"id": row["id"], "mac": row["mac"], "ip": row["ip"], "type": row["type"]})
        cur.execute("UPDATE commands SET status='delivered', delivered=? WHERE id=?", (now, row["id"]))
    conn.commit()
    return {"ok": True, "commands": out}


def fleet(cfg):
    conn = db(cfg)
    rows = conn.execute(
        "SELECT mac,site,ip,model,serial,client,last_seen,last_state,last_issue,"
        "last_hashrate,last_temp,last_power FROM miners ORDER BY site,ip").fetchall()
    return {"miners": [dict(r) for r in rows], "generated": datetime.now(timezone.utc).isoformat()}


def miner_history(cfg, mac, limit=200):
    conn = db(cfg)
    rows = conn.execute(
        "SELECT ts,hashrate,temp_max,power_watts,power_source,state,issue FROM samples "
        "WHERE mac=? ORDER BY ts DESC LIMIT ?", (mac, limit)).fetchall()
    info = conn.execute("SELECT * FROM miners WHERE mac=?", (mac,)).fetchone()
    return {"miner": dict(info) if info else None, "samples": [dict(r) for r in rows]}


def billing(cfg, dt_from, dt_to):
    conn = db(cfg)
    rate = cfg.getfloat("billing", "rate_per_kwh")
    max_gap = cfg.getint("billing", "max_gap_seconds")
    client_of = {r["mac"]: (r["client"] or "unassigned") for r in conn.execute("SELECT mac,client FROM miners")}
    macs = [r["mac"] for r in conn.execute(
        "SELECT DISTINCT mac FROM samples WHERE ts>=? AND ts<?", (dt_from, dt_to))]
    clients, per_miner = {}, {}
    for mac in macs:
        rows = conn.execute("SELECT ts,power_watts FROM samples WHERE mac=? AND ts>=? AND ts<? ORDER BY ts",
                            (mac, dt_from, dt_to)).fetchall()
        kwh, prev = 0.0, None
        for r in rows:
            try:
                t = datetime.fromisoformat(r["ts"])
            except ValueError:
                continue
            if prev and r["power_watts"]:
                dt_s = min((t - prev).total_seconds(), max_gap)
                if dt_s > 0:
                    kwh += (r["power_watts"] * dt_s / 3600.0) / 1000.0
            prev = t
        c = client_of.get(mac, "unassigned")
        per_miner[mac] = {"client": c, "kwh": round(kwh, 3), "cost": round(kwh * rate, 2)}
        cc = clients.setdefault(c, {"kwh": 0.0, "miners": 0})
        cc["kwh"] += kwh
        cc["miners"] += 1
    for cc in clients.values():
        cc["kwh"] = round(cc["kwh"], 3)
        cc["cost"] = round(cc["kwh"] * rate, 2)
    return {"from": dt_from, "to": dt_to, "rate_per_kwh": rate, "clients": clients, "per_miner": per_miner}


def assign(cfg, mac, client, rated_watts):
    conn = db(cfg)
    cur = conn.cursor()
    if not cur.execute("SELECT mac FROM miners WHERE mac=?", (mac,)).fetchone():
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("INSERT INTO miners(mac,first_seen,last_seen) VALUES(?,?,?)", (mac, now, now))
    cur.execute("UPDATE miners SET client=COALESCE(?,client), rated_watts=COALESCE(?,rated_watts) WHERE mac=?",
                (client, rated_watts, mac))
    conn.commit()
    return {"ok": True, "mac": mac, "client": client}


def queue_command(cfg, site, mac, ip, ctype):
    if ctype != "restart":
        return {"ok": False, "error": "only 'restart' is allowed via remote command"}
    conn = db(cfg)
    conn.execute("INSERT INTO commands(site,mac,ip,type,status,created) VALUES(?,?,?,?,?,?)",
                 (site, mac, ip, ctype, "pending", datetime.now(timezone.utc).isoformat()))
    conn.commit()
    return {"ok": True, "queued": ctype, "mac": mac, "ip": ip, "site": site}


# ── HTTP ──────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    cfg = None  # set in main()

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        token = os.environ.get(self.cfg.get("server", "token_env"), "")
        if not token:
            return True  # no token configured => open (dev only)
        return self.headers.get("Authorization", "") == f"Bearer {token}"

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def log_message(self, *a):  # quieter
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/":
                self._send(200, DASHBOARD_HTML.encode(), "text/html; charset=utf-8")
            elif u.path == "/health":
                self._send(200, {"ok": True})
            elif u.path == "/api/fleet":
                self._send(200, fleet(self.cfg))
            elif u.path.startswith("/api/miner/") and u.path.endswith("/history"):
                mac = u.path[len("/api/miner/"):-len("/history")]
                self._send(200, miner_history(self.cfg, mac, int(q.get("limit", ["200"])[0])))
            elif u.path == "/api/billing":
                dt_from = q.get("from", ["0000"])[0]
                dt_to = q.get("to", [datetime.now(timezone.utc).isoformat()])[0]
                self._send(200, billing(self.cfg, dt_from, dt_to))
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            b = self._body()
            if u.path == "/ingest":
                self._send(200, ingest(self.cfg, b))
            elif u.path == "/api/assign":
                self._send(200, assign(self.cfg, b.get("mac"), b.get("client"), b.get("rated_watts")))
            elif u.path == "/api/command":
                self._send(200, queue_command(self.cfg, b.get("site", ""), b.get("mac", ""),
                                              b.get("ip", ""), b.get("type", "")))
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": str(e)})


DASHBOARD_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cryptotherm Ops</title><style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--mut:#666;--line:#e3e6ea;--ok:#137333;--warn:#b06000;--crit:#c5221f}
@media(prefers-color-scheme:dark){:root{--bg:#0f1113;--card:#181b1e;--fg:#e8eaed;--mut:#9aa0a6;--line:#2a2e33;--ok:#81c995;--warn:#fdd663;--crit:#f28b82}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0}.muted{color:var(--mut)}.wrap{padding:14px 18px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.card .n{font-size:22px;font-weight:600}.card .l{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:12px;color:var(--mut);font-weight:600}tr:last-child td{border-bottom:none}
.pill{padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.OK{color:var(--ok)}.WARN,.WARMUP{color:var(--warn)}.HUNG,.FAULT,.OFFLINE{color:var(--crit)}
.tabbtn{background:none;border:1px solid var(--line);color:var(--fg);padding:6px 12px;border-radius:8px;cursor:pointer;margin-right:6px}
.tabbtn.on{background:var(--fg);color:var(--bg)}
.overflow{overflow-x:auto}input,button{font:inherit}
</style></head><body>
<header><h1>⚡ Cryptotherm Ops</h1><span class="muted" id="sub">loading…</span>
<span style="margin-left:auto"><button class="tabbtn on" id="tf" onclick="tab('fleet')">Fleet</button>
<button class="tabbtn" id="tb" onclick="tab('billing')">Billing</button></span></header>
<div class="wrap">
<div id="fleet">
  <div class="cards" id="stat"></div>
  <div class="overflow"><table id="tbl"><thead><tr>
    <th>Site</th><th>IP</th><th>MAC</th><th>Model</th><th>Client</th><th>State</th>
    <th>Issue</th><th>TH/s</th><th>Temp</th><th>Watts</th><th>Last seen</th></tr></thead>
    <tbody id="rows"></tbody></table></div>
</div>
<div id="billing" hidden>
  <div style="margin-bottom:10px">From <input type="date" id="bf"> To <input type="date" id="bt">
  <button class="tabbtn" onclick="loadBill()">Run</button></div>
  <div class="overflow"><table><thead><tr><th>Client</th><th>Miners</th><th>kWh</th><th>Cost</th></tr></thead>
  <tbody id="brows"></tbody></table></div>
</div>
</div>
<script>
function ago(t){if(!t)return'—';let s=(Date.now()-new Date(t))/1000;if(s<90)return Math.round(s)+'s';
if(s<5400)return Math.round(s/60)+'m';return Math.round(s/3600)+'h';}
function esc(x){return(x==null?'':(''+x)).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
async function loadFleet(){let d=await(await fetch('/api/fleet')).json();let m=d.miners||[];
 let up=m.filter(x=>x.last_state&&x.last_state!=='OFFLINE').length;
 let iss=m.filter(x=>x.last_issue).length;let th=m.reduce((a,x)=>a+(x.last_hashrate||0),0)/1000;
 let kw=m.reduce((a,x)=>a+(x.last_power||0),0)/1000;
 document.getElementById('stat').innerHTML=
  card(m.length,'miners')+card(up,'reporting')+card(iss,'issues')+card(th.toFixed(1),'TH/s')+card(kw.toFixed(1),'kW draw');
 document.getElementById('rows').innerHTML=m.map(x=>`<tr>
  <td>${esc(x.site)}</td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td><td>${esc(x.model)}</td>
  <td>${esc(x.client||'—')}</td><td class="${esc(x.last_state)}"><b>${esc(x.last_state||'?')}</b></td>
  <td class="${esc(x.last_state)}">${esc(x.last_issue||'—')}</td>
  <td>${((x.last_hashrate||0)/1000).toFixed(1)}</td><td>${Math.round(x.last_temp||0)}</td>
  <td>${Math.round(x.last_power||0)}</td><td class="muted">${ago(x.last_seen)}</td></tr>`).join('');
 document.getElementById('sub').textContent=new Date().toLocaleTimeString()+' · '+m.length+' miners';}
function card(n,l){return`<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`;}
async function loadBill(){let f=document.getElementById('bf').value||'0000';
 let t=document.getElementById('bt').value; t=t?t+'T23:59:59':new Date().toISOString();
 let d=await(await fetch('/api/billing?from='+encodeURIComponent(f)+'&to='+encodeURIComponent(t))).json();
 let c=d.clients||{};document.getElementById('brows').innerHTML=Object.keys(c).sort((a,b)=>c[b].kwh-c[a].kwh)
  .map(k=>`<tr><td>${esc(k)}</td><td>${c[k].miners}</td><td>${c[k].kwh.toFixed(2)}</td><td>$${c[k].cost.toFixed(2)}</td></tr>`).join('')
  ||'<tr><td colspan=4 class="muted">no data in range</td></tr>';}
function tab(n){document.getElementById('fleet').hidden=n!=='fleet';document.getElementById('billing').hidden=n!=='billing';
 document.getElementById('tf').classList.toggle('on',n==='fleet');document.getElementById('tb').classList.toggle('on',n==='billing');
 if(n==='billing')loadBill();}
loadFleet();setInterval(loadFleet,15000);
</script></body></html>"""


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Cryptotherm Collector + Dashboard")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "collector.conf"))
    args = ap.parse_args()
    cfg = load_config(args.config)
    Handler.cfg = cfg
    host = cfg.get("server", "host")
    port = cfg.getint("server", "port")
    if not os.environ.get(cfg.get("server", "token_env"), ""):
        print(f"WARNING: no {cfg.get('server','token_env')} set — write endpoints are OPEN. Set it for production.")
    print(f"Cryptotherm Collector on http://{host}:{port}  (db={cfg.get('server','db')})")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
