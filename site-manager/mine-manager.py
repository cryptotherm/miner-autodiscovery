#!/usr/bin/env python3
"""
Cryptotherm Mine Manager
========================
Site-management daemon for a live mining colony: continuously monitor,
diagnose, flag, report, notify, and (optionally, with guardrails) operate
the whole fleet.

This is NOT the bench/repair tool — there is no label printing, QR, or
ticket/scan workflow here. It reuses the cgminer queries and fault logic
from autodiscovery.py and adds fleet polling, edge-triggered alerts,
scheduled reports, and *safe* remediation.

Safety model (see mine-manager.conf):
  - dry_run defaults ON — observe only, never send a command.
  - auto_restart defaults OFF; when on, only HUNG miners are rebooted,
    with a cooldown + daily cap, and NEVER a miner with a dead fan.
  - Pool changes are never automatic. Manual CLI only, gated by an allow
    flag + an approved-pools allowlist + IP re-type + --yes, and audited.

Usage:
    python3 mine-manager.py run            # the daemon (default)
    python3 mine-manager.py status         # one-shot fleet snapshot to stdout
    python3 mine-manager.py report         # generate + print a report now
    python3 mine-manager.py restart <ip>   # manual reboot of one miner
    python3 mine-manager.py set-pool <ip> --url <stratum> --user <w> [--pass <p>] --yes

Requires: python3, requests.
"""

import argparse
import concurrent.futures
import configparser
import json
import logging
import os
import platform
import smtplib
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone, date
from email.mime.text import MIMEText

import requests
from requests.auth import HTTPDigestAuth

# ── CONFIG LOADING ────────────────────────────────────────────────────────────
DEFAULTS = {
    "site":       {"name": "Site", "subnet": "10.0.0", "scan_interval": "60", "cgminer_port": "4028"},
    "auth":       {"miner_user": "root", "miner_pass": "root"},
    "operations": {"dry_run": "true", "auto_restart": "false", "restart_method": "web",
                   "restart_cooldown_min": "30", "restart_max_per_day": "3",
                   "allow_pool_changes": "false", "approved_pools": ""},
    "thresholds": {"warmup_min": "15", "dead_after_min": "15", "temp_warn_c": "80", "temp_crit_c": "95"},
    "notify":     {"webhook_url": "", "min_severity": "warning", "email_to": "",
                   "smtp_host": "", "smtp_port": "587", "smtp_user": "", "smtp_pass_env": "CT_SMTP_PASS"},
    "reports":    {"enabled": "true", "interval_hours": "6", "dir": "./reports", "deliver": "false"},
    "storage":    {"db": "./mine-manager.db", "server_push_url": "", "server_push_token_env": "CT_SERVER_TOKEN"},
    "billing":    {"rate_per_kwh": "0.10"},
    "platform":   {"enabled": "false", "api": "", "token_env": "CT_PLATFORM_TOKEN"},
}

# Approximate nameplate wattage by model substring. These are ROUGH — they are
# only a fallback when a miner reports no power and no ML estimate is available.
# Graeson's ML power model is the intended replacement (see estimate_power()).
RATED_WATTS = {
    "S19k Pro": 2760, "S19 XP": 3010, "S19j Pro": 3050, "S19": 3250,
    "L7": 3425, "S21": 3500, "T21": 3610, "WhatsMiner": 3400, "M30": 3400, "M50": 3300,
}


def load_config(path: str) -> configparser.ConfigParser:
    # inline_comment_prefixes lets the example config keep its inline "# ..."
    # notes; configparser only strips them when preceded by whitespace, so
    # URLs containing '#' are left intact.
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read_dict(DEFAULTS)
    if path and os.path.exists(path):
        cfg.read(path)
    else:
        logging.warning("No config file at %s — using safe defaults (dry_run on).", path)
    return cfg


# ── LOGGING ───────────────────────────────────────────────────────────────────
def setup_logging():
    handlers = [logging.StreamHandler()]
    for p in ("/var/log/ct_mine_manager.log", os.path.expanduser("~/ct_mine_manager.log")):
        try:
            handlers.append(logging.FileHandler(p, mode="a"))
            break
        except OSError:
            continue
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


log = logging.getLogger("ct_mine_manager")

# ── KNOWN MINER SIGNATURES ────────────────────────────────────────────────────
MINER_MODELS = {
    "Antminer S19k Pro":  {"algo": "SHA-256", "ideal_ths": 120, "fans": 4},
    "Antminer S19 XP":    {"algo": "SHA-256", "ideal_ths": 141, "fans": 4},
    "Antminer L7":        {"algo": "Scrypt",  "ideal_ghs": 9.16, "fans": 4},
    "MicroBT WhatsMiner": {"algo": "SHA-256", "ideal_ths": 103, "fans": 2},
}

# ── NETWORK / CGMINER HELPERS (shared shape with autodiscovery.py) ─────────────
def scan_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=1):
            return True
    except OSError:
        return False


def query_cgminer(ip: str, command: str, port: int, parameter: str | None = None) -> dict | None:
    """Send a cgminer API command; return parsed JSON or None."""
    try:
        req = {"command": command}
        if parameter is not None:
            req["parameter"] = parameter
        with socket.create_connection((ip, port), timeout=3) as s:
            s.sendall((json.dumps(req) + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"\x00"):
                    data = data.rstrip(b"\x00")
                    break
        return json.loads(data.decode("utf-8", errors="ignore"))
    except Exception as e:  # noqa: BLE001 - network best-effort
        log.debug("cgminer %s/%s failed: %s", ip, command, e)
        return None


def get_mac(ip: str) -> str:
    """MAC from the ARP table. Cross-platform (Windows 'arp -a' uses dashes)."""
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
            for tok in r.stdout.replace("-", ":").split():
                if tok.count(":") == 5 and len(tok) == 17:
                    return tok.upper()
        else:
            r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
            for tok in r.stdout.split():
                if tok.count(":") == 5 and len(tok) == 17:
                    return tok.upper()
    except Exception:  # noqa: BLE001
        pass
    return "00:00:00:00:00:00"


def get_ident(ip: str, auth: HTTPDigestAuth) -> dict:
    """Stable identity (MAC + serial + model) from the Antminer web API."""
    out = {}
    try:
        r = requests.get(f"http://{ip}/cgi-bin/get_system_info.cgi", auth=auth, timeout=3)
        if r.ok:
            d = r.json()
            if d.get("macaddr"):
                out["mac"] = str(d["macaddr"]).upper()
            if d.get("serinum"):
                out["serial"] = d["serinum"]
            if d.get("minertype"):
                out["model"] = d["minertype"]
    except Exception:  # noqa: BLE001
        pass
    return out


def estimate_power(model: str, hashrate: float, ideal: float, measured: float) -> tuple[float, str]:
    """Return (watts, source). measured > 0 wins. Otherwise a rough nameplate
    estimate scaled by load. THIS IS THE HOOK for Graeson's ML power model —
    drop the trained estimator in here and return ('<value>', 'ml')."""
    if measured and measured > 0:
        return float(measured), "measured"
    rated = 0
    for key, w in RATED_WATTS.items():
        if key.lower() in (model or "").lower():
            rated = w
            break
    if not rated:
        return 0.0, "unknown"
    if ideal and hashrate and ideal > 0:
        return round(rated * min(1.15, max(0.0, hashrate / ideal)), 1), "estimated"
    return float(rated), "estimated"


def _find_power(d: dict) -> float:
    """Best-effort watts from a cgminer summary/stats dict across firmwares."""
    if not isinstance(d, dict):
        return 0.0
    for k, v in d.items():
        kl = k.lower()
        if ("power" in kl or "watt" in kl) and "rate" not in kl and "efficiency" not in kl:
            try:
                w = float(v)
                if 50 < w < 20000:  # plausible single-miner wattage
                    return w
            except (TypeError, ValueError):
                continue
    return 0.0


def get_stats(ip: str, auth: HTTPDigestAuth) -> dict:
    try:
        r = requests.get(f"http://{ip}/cgi-bin/stats.cgi", auth=auth, timeout=5)
        if r.ok:
            return r.json().get("STATS", [{}])[0]
    except Exception:  # noqa: BLE001
        pass
    return {}


def extract_max_temp(stats: dict, chains: list) -> float:
    """Best-effort hottest reading across chain temp fields."""
    temps = []
    for c in chains if isinstance(chains, list) else []:
        if not isinstance(c, dict):
            continue
        for k, v in c.items():
            if isinstance(v, (int, float)) and k.lower().startswith("temp") and 0 < v < 200:
                temps.append(float(v))
        # WhatsMiner style
        for k in ("Temperature", "temp_max"):
            v = c.get(k)
            if isinstance(v, (int, float)) and 0 < v < 200:
                temps.append(float(v))
    for k in ("temp_max", "temp1", "temp2"):
        v = stats.get(k)
        if isinstance(v, (int, float)) and 0 < v < 200:
            temps.append(float(v))
    return max(temps) if temps else 0.0


# ── DIAGNOSIS (monitor + classify, no printing) ───────────────────────────────
SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}


def diagnose(ip: str, cfg: configparser.ConfigParser, auth: HTTPDigestAuth) -> dict:
    """Poll one miner and classify its health. Pure read — never operates."""
    port = cfg.getint("site", "cgminer_port")
    warmup_min = cfg.getint("thresholds", "warmup_min")
    dead_after = cfg.getint("thresholds", "dead_after_min")
    temp_warn = cfg.getfloat("thresholds", "temp_warn_c")
    temp_crit = cfg.getfloat("thresholds", "temp_crit_c")

    r = {
        "ip": ip, "ts": datetime.now(timezone.utc).isoformat(),
        "mac": "00:00:00:00:00:00", "serial": "",
        "reachable": False, "model": "Unknown", "hashrate": 0.0, "ideal": 0.0,
        "accepted": 0, "rejected": 0, "elapsed": 0, "fans": [], "temp_max": 0.0,
        "power_watts": 0.0, "power_source": "unknown",
        "pool": "", "worker": "", "pool_status": "",
        "state": "UNKNOWN", "severity": "info", "issue": None, "detail": "",
        "restartable": False,
    }
    r["mac"] = get_mac(ip)

    ver = query_cgminer(ip, "version", port)
    if not ver:
        # Was reachable on the port scan but cgminer isn't answering, or dropped.
        r["state"] = "OFFLINE"
        r["severity"] = "critical"
        r["issue"] = "UNREACHABLE"
        r["detail"] = "cgminer API not responding"
        return r
    r["reachable"] = True
    r["model"] = ver.get("VERSION", [{}])[0].get("Type", "Unknown")

    measured_power = 0.0
    summ = query_cgminer(ip, "summary", port)
    if summ:
        s = summ.get("SUMMARY", [{}])[0]
        r["hashrate"] = float(s.get("GHS 5s", s.get("MHS 5s", 0)) or 0)
        r["accepted"] = int(s.get("Accepted", 0) or 0)
        r["rejected"] = int(s.get("Rejected", 0) or 0)
        r["elapsed"] = int(s.get("Elapsed", 0) or 0)
        r["ideal"] = float(s.get("rate_ideal", 0) or 0)
        measured_power = _find_power(s)

    pools = query_cgminer(ip, "pools", port)
    if pools:
        active = pools.get("POOLS", [])
        p0 = next((p for p in active if str(p.get("Priority", p.get("POOL", "99"))) == "0"), active[0] if active else {})
        r["pool"] = p0.get("URL", "")
        r["worker"] = p0.get("User", "")
        r["pool_status"] = p0.get("Status", "")

    stats = get_stats(ip, auth)
    if stats:
        r["fans"] = stats.get("fan", []) or []
    chains = stats.get("chain", []) if stats else []
    devs = query_cgminer(ip, "devs", port)
    if devs and "DEVS" in devs and not chains:
        chains = devs.get("DEVS", [])
    r["temp_max"] = extract_max_temp(stats, chains)
    if not measured_power and stats:
        measured_power = _find_power(stats)

    # stable identity + power (measured if reported, else estimated/ML hook)
    ident = get_ident(ip, auth)
    if ident.get("mac"):
        r["mac"] = ident["mac"]
    if ident.get("serial"):
        r["serial"] = ident["serial"]
    if ident.get("model"):
        r["model"] = ident["model"]
    r["power_watts"], r["power_source"] = estimate_power(r["model"], r["hashrate"], r["ideal"], measured_power)

    elapsed_min = r["elapsed"] / 60
    dead_fans = [i + 1 for i, rpm in enumerate(r["fans"]) if rpm == 0]

    # ── classification (highest-severity issue wins) ──────────────────────────
    if dead_fans:
        r.update(state="FAULT", severity="critical", issue="FAN-FAIL", restartable=False,
                 detail=f"Fan(s) {dead_fans} at 0 RPM — thermal risk; NOT auto-restarting")
    elif r["temp_max"] >= temp_crit:
        r.update(state="FAULT", severity="critical", issue="OVERHEAT", restartable=False,
                 detail=f"Max temp {r['temp_max']:.0f}C >= critical {temp_crit:.0f}C")
    elif _partial_chain(chains):
        cid, found, total = _partial_chain(chains)
        r.update(state="FAULT", severity="warning", issue=f"ASIC-CHAIN{cid}-PARTIAL", restartable=False,
                 detail=f"Chain {cid}: {found}/{total} ASICs — hardware, restart won't fix")
    elif r["pool_status"] in ("Dead", "Deed", "") and elapsed_min > 5:
        r.update(state="FAULT", severity="warning", issue="POOL-DEAD", restartable=True,
                 detail=f"Pool not connected (status={r['pool_status'] or 'unknown'})")
    elif r["hashrate"] <= 0 and elapsed_min >= dead_after:
        r.update(state="HUNG", severity="critical", issue="NO-HASH", restartable=True,
                 detail=f"~0 hashrate for {elapsed_min:.0f} min while reachable")
    elif r["temp_max"] >= temp_warn:
        r.update(state="WARN", severity="warning", issue="TEMP-HIGH", restartable=False,
                 detail=f"Max temp {r['temp_max']:.0f}C >= warn {temp_warn:.0f}C")
    elif r["ideal"] and r["hashrate"] and r["hashrate"] < 0.75 * r["ideal"] and elapsed_min > warmup_min:
        r.update(state="WARN", severity="warning", issue="LOW-HASH", restartable=True,
                 detail=f"Hashrate {r['hashrate']:.0f} < 75% of ideal {r['ideal']:.0f}")
    elif r["hashrate"] <= 0 and elapsed_min < warmup_min:
        r.update(state="WARMUP", severity="info", issue=None, detail=f"Warming up ({elapsed_min:.0f} min)")
    else:
        r.update(state="OK", severity="info", issue=None, detail="Healthy")

    return r


def _partial_chain(chains):
    """Return (chain_id, found, total) if a chain is missing ASICs, else None."""
    for c in chains if isinstance(chains, list) else []:
        if not isinstance(c, dict):
            continue
        if "asic" in c and isinstance(c["asic"], str):
            total = int(c.get("asic_num", 0) or 0)
            bad = c["asic"].count("x")
            if total and bad:
                return (c.get("index", c.get("ASC", "?")), total - bad, total)
        elif "Effective Chips" in c:
            total = int(c.get("Effective Chips", 0) or 0)
            declared = int(c.get("Chips", total) or total)
            if total and declared and total < declared:
                return (c.get("index", c.get("ASC", "?")), total, declared)
    return None


# ── OPERATIONS (guarded) ──────────────────────────────────────────────────────
def reboot_miner(ip: str, cfg: configparser.ConfigParser, auth: HTTPDigestAuth, reason: str) -> bool:
    """Reboot one miner. Respects dry_run. Returns True if a command was sent."""
    if cfg.getboolean("operations", "dry_run"):
        log.info("[DRY-RUN] would reboot %s (%s)", ip, reason)
        return False
    method = cfg.get("operations", "restart_method").lower()
    port = cfg.getint("site", "cgminer_port")
    log.warning("REBOOTING %s via %s (%s)", ip, method, reason)
    _audit(cfg, "reboot", ip, {"method": method, "reason": reason})
    try:
        if method == "cgminer":
            query_cgminer(ip, "restart", port)
        else:  # web reboot.cgi (Antminer)
            requests.get(f"http://{ip}/cgi-bin/reboot.cgi", auth=auth, timeout=8)
        return True
    except Exception as e:  # noqa: BLE001
        log.error("reboot %s failed: %s", ip, e)
        return False


def set_pool(ip: str, url: str, user: str, password: str, cfg: configparser.ConfigParser,
             auth: HTTPDigestAuth, assume_yes: bool) -> bool:
    """Change a miner's primary pool — MANUAL, heavily guarded. Never called by the loop."""
    if not cfg.getboolean("operations", "allow_pool_changes"):
        log.error("Pool changes are disabled (operations.allow_pool_changes=false). Refusing.")
        return False
    approved = [p.strip() for p in cfg.get("operations", "approved_pools").split(",") if p.strip()]
    if url not in approved:
        log.error("Target pool %s is not in approved_pools. Refusing. Approved: %s", url, approved or "(none)")
        return False
    # Human confirmation: retype the IP.
    if not assume_yes:
        typed = input(f"About to change pool on {ip} -> {url} (worker {user}).\n"
                      f"Retype the miner IP to confirm: ").strip()
        if typed != ip:
            log.error("IP mismatch — aborted. No change made.")
            return False
    else:
        log.warning("--yes supplied: skipping interactive confirmation for %s", ip)

    if cfg.getboolean("operations", "dry_run"):
        log.info("[DRY-RUN] would set pool on %s -> %s (%s)", ip, url, user)
        _audit(cfg, "set-pool-dryrun", ip, {"url": url, "user": user})
        return False

    port = cfg.getint("site", "cgminer_port")
    log.warning("CHANGING POOL on %s -> %s", ip, url)
    _audit(cfg, "set-pool", ip, {"url": url, "user": user})
    try:
        # cgminer privileged: add + switch. Requires the miner API to allow writes.
        query_cgminer(ip, "addpool", port, parameter=f"{url},{user},{password}")
        pools = query_cgminer(ip, "pools", port) or {}
        new_id = None
        for p in pools.get("POOLS", []):
            if p.get("URL") == url:
                new_id = p.get("POOL", p.get("ID"))
                break
        if new_id is not None:
            query_cgminer(ip, "switchpool", port, parameter=str(new_id))
        log.warning("Pool change sent to %s. Verify on the miner.", ip)
        return True
    except Exception as e:  # noqa: BLE001
        log.error("set_pool %s failed: %s", ip, e)
        return False


def _audit(cfg: configparser.ConfigParser, action: str, ip: str, extra: dict):
    line = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, "ip": ip, **extra}
    try:
        with open("mine-manager-audit.log", "a") as f:
            f.write(json.dumps(line) + "\n")
    except OSError:
        pass


# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
def notify(cfg: configparser.ConfigParser, severity: str, title: str, body: str):
    log.info("NOTIFY[%s] %s", severity.upper(), title)
    floor = cfg.get("notify", "min_severity", fallback="warning")
    if SEV_ORDER.get(severity, 0) < SEV_ORDER.get(floor, 1):
        return
    site = cfg.get("site", "name")
    text = f"[{site}] {title}\n{body}"

    hook = cfg.get("notify", "webhook_url", fallback="").strip()
    if hook:
        try:
            requests.post(hook, json={"text": text}, timeout=8)
        except Exception as e:  # noqa: BLE001
            log.error("webhook notify failed: %s", e)

    to = cfg.get("notify", "email_to", fallback="").strip()
    host = cfg.get("notify", "smtp_host", fallback="").strip()
    if to and host:
        try:
            msg = MIMEText(text)
            msg["Subject"] = f"[{site}] {severity.upper()}: {title}"
            msg["From"] = cfg.get("notify", "smtp_user", fallback="mine-manager@localhost")
            msg["To"] = to
            with smtplib.SMTP(host, cfg.getint("notify", "smtp_port"), timeout=15) as smtp:
                smtp.starttls()
                user = cfg.get("notify", "smtp_user", fallback="")
                pw = os.environ.get(cfg.get("notify", "smtp_pass_env", fallback="CT_SMTP_PASS"), "")
                if user and pw:
                    smtp.login(user, pw)
                smtp.send_message(msg)
        except Exception as e:  # noqa: BLE001
            log.error("email notify failed: %s", e)


# ── REPORTS ───────────────────────────────────────────────────────────────────
def build_report(fleet: list[dict], cfg: configparser.ConfigParser) -> tuple[str, dict]:
    site = cfg.get("site", "name")
    total = len(fleet)
    up = sum(1 for m in fleet if m["reachable"])
    hashing = sum(1 for m in fleet if m["hashrate"] > 0)
    total_hash = sum(m["hashrate"] for m in fleet)
    issues = [m for m in fleet if m["issue"]]
    by_issue: dict[str, int] = {}
    for m in issues:
        by_issue[m["issue"]] = by_issue.get(m["issue"], 0) + 1

    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"Cryptotherm Mine Manager — {site}",
        f"Generated: {now}",
        "=" * 52,
        f"Miners found      : {total}",
        f"Reachable         : {up}",
        f"Hashing           : {hashing}",
        f"Total hashrate    : {total_hash/1000:.2f} TH/s (raw {total_hash:.0f})",
        f"Open issues       : {len(issues)}",
    ]
    if by_issue:
        lines.append("Issues by type    :")
        for k, v in sorted(by_issue.items(), key=lambda kv: -kv[1]):
            lines.append(f"   {k:<24} {v}")
    if issues:
        lines.append("-" * 52)
        lines.append("Details:")
        for m in sorted(issues, key=lambda x: -SEV_ORDER.get(x["severity"], 0)):
            lines.append(f"  {m['ip']:<15} {m['severity'].upper():<8} {m['issue']:<20} {m['detail']}")
    text = "\n".join(lines)
    data = {"site": site, "ts": now, "total": total, "reachable": up, "hashing": hashing,
            "total_hashrate": total_hash, "issues": issues, "by_issue": by_issue}
    return text, data


def write_report(text: str, data: dict, cfg: configparser.ConfigParser):
    d = cfg.get("reports", "dir", fallback="./reports")
    try:
        os.makedirs(d, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        with open(os.path.join(d, f"report-{stamp}.txt"), "w") as f:
            f.write(text)
        with open(os.path.join(d, f"report-{stamp}.json"), "w") as f:
            json.dump(data, f, indent=2)
        with open(os.path.join(d, "latest.json"), "w") as f:
            json.dump(data, f, indent=2)
        log.info("Report written to %s", d)
    except OSError as e:
        log.error("write report failed: %s", e)
    if cfg.getboolean("reports", "deliver", fallback=False):
        notify(cfg, "info", "Fleet report", text)


# ── PLATFORM TELEMETRY (optional) ─────────────────────────────────────────────
def push_platform(m: dict, cfg: configparser.ConfigParser):
    if not cfg.getboolean("platform", "enabled", fallback=False):
        return
    api = cfg.get("platform", "api", fallback="").strip()
    token = os.environ.get(cfg.get("platform", "token_env", fallback="CT_PLATFORM_TOKEN"), "")
    if not api or not token:
        return
    try:
        requests.post(
            f"{api}/telemetry",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"ip": m["ip"], "hashrate": m["hashrate"], "state": m["state"],
                  "issue": m["issue"], "temp_max": m["temp_max"], "accepted": m["accepted"]},
            timeout=5,
        )
    except Exception as e:  # noqa: BLE001
        log.debug("platform push failed for %s: %s", m["ip"], e)


# ── HISTORY STORAGE (SQLite, MAC-keyed) ───────────────────────────────────────
def db_connect(cfg: configparser.ConfigParser) -> sqlite3.Connection:
    path = cfg.get("storage", "db", fallback="./mine-manager.db")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS miners (
            mac TEXT PRIMARY KEY,
            serial TEXT, model TEXT, ip TEXT,
            client TEXT, rated_watts REAL,
            first_seen TEXT, last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT, ts TEXT, ip TEXT,
            hashrate REAL, ideal REAL, accepted INTEGER, rejected INTEGER,
            elapsed INTEGER, temp_max REAL,
            power_watts REAL, power_source TEXT,
            state TEXT, issue TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_samples_mac_ts ON samples(mac, ts);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT, ts TEXT, type TEXT, detail TEXT
        );
        """
    )
    conn.commit()
    return conn


def persist(conn: sqlite3.Connection, fleet: list[dict]):
    """Upsert miner identity and append one time-series sample per miner."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    for m in fleet:
        mac = m.get("mac") or "00:00:00:00:00:00"
        if mac == "00:00:00:00:00:00":
            # No stable identity — key on IP so we still capture something.
            mac = f"ip:{m['ip']}"
        cur.execute("SELECT mac FROM miners WHERE mac=?", (mac,))
        if cur.fetchone():
            cur.execute(
                "UPDATE miners SET serial=COALESCE(NULLIF(?,''),serial), "
                "model=COALESCE(NULLIF(?,''),model), ip=?, last_seen=? WHERE mac=?",
                (m.get("serial", ""), m.get("model", ""), m["ip"], now, mac),
            )
        else:
            cur.execute(
                "INSERT INTO miners(mac,serial,model,ip,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                (mac, m.get("serial", ""), m.get("model", ""), m["ip"], now, now),
            )
        cur.execute(
            "INSERT INTO samples(mac,ts,ip,hashrate,ideal,accepted,rejected,elapsed,"
            "temp_max,power_watts,power_source,state,issue) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mac, m["ts"], m["ip"], m["hashrate"], m["ideal"], m["accepted"], m["rejected"],
             m["elapsed"], m["temp_max"], m["power_watts"], m["power_source"], m["state"], m["issue"]),
        )
    conn.commit()


def log_event_db(conn: sqlite3.Connection, mac: str, etype: str, detail: str):
    try:
        conn.execute("INSERT INTO events(mac,ts,type,detail) VALUES(?,?,?,?)",
                     (mac, datetime.now(timezone.utc).isoformat(), etype, detail))
        conn.commit()
    except sqlite3.Error:
        pass


def push_server(fleet: list[dict], cfg: configparser.ConfigParser):
    """Optionally forward each sweep to a central server (e.g. Cole's dashboard
    backend). Configure storage.server_push_url; off by default. Best-effort."""
    url = cfg.get("storage", "server_push_url", fallback="").strip()
    if not url:
        return
    token = os.environ.get(cfg.get("storage", "server_push_token_env", fallback="CT_SERVER_TOKEN"), "")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        requests.post(url, headers=headers,
                      json={"site": cfg.get("site", "name"), "ts": datetime.now(timezone.utc).isoformat(),
                            "miners": fleet}, timeout=10)
    except Exception as e:  # noqa: BLE001
        log.debug("server push failed: %s", e)


def compute_billing(conn: sqlite3.Connection, cfg: configparser.ConfigParser,
                    dt_from: str, dt_to: str) -> dict:
    """Energy (kWh) and cost per client by integrating power over the samples in
    [from, to). Uses real per-miner time deltas, capping gaps so downtime does
    not over-bill."""
    rate = cfg.getfloat("billing", "rate_per_kwh", fallback=0.10)
    max_gap_s = cfg.getint("site", "scan_interval") * 3  # a gap larger than this = miner was off
    cur = conn.cursor()
    clients: dict[str, dict] = {}
    per_miner: dict[str, dict] = {}
    cur.execute("SELECT mac, COALESCE(client,'unassigned') FROM miners")
    client_of = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("SELECT DISTINCT mac FROM samples WHERE ts>=? AND ts<?", (dt_from, dt_to))
    macs = [r[0] for r in cur.fetchall()]
    for mac in macs:
        cur.execute("SELECT ts, power_watts FROM samples WHERE mac=? AND ts>=? AND ts<? ORDER BY ts",
                    (mac, dt_from, dt_to))
        rows = cur.fetchall()
        kwh = 0.0
        prev_t = None
        for ts, watts in rows:
            try:
                t = datetime.fromisoformat(ts)
            except ValueError:
                continue
            if prev_t is not None and watts:
                dt_s = min((t - prev_t).total_seconds(), max_gap_s)
                if dt_s > 0:
                    kwh += (watts * dt_s / 3600.0) / 1000.0
            prev_t = t
        client = client_of.get(mac, "unassigned")
        per_miner[mac] = {"client": client, "kwh": round(kwh, 3), "cost": round(kwh * rate, 2)}
        c = clients.setdefault(client, {"kwh": 0.0, "miners": 0})
        c["kwh"] += kwh
        c["miners"] += 1
    for c in clients.values():
        c["kwh"] = round(c["kwh"], 3)
        c["cost"] = round(c["kwh"] * rate, 2)
    return {"from": dt_from, "to": dt_to, "rate_per_kwh": rate,
            "clients": clients, "per_miner": per_miner}


# ── STATE (edge-triggered alerts + restart accounting) ────────────────────────
STATE_FILE = "mine-manager-state.json"


def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state: dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except OSError:
        pass


def can_restart(ip: str, state: dict, cfg: configparser.ConfigParser) -> bool:
    st = state.get(ip, {})
    today = date.today().isoformat()
    if st.get("restart_day") != today:
        st["restart_day"] = today
        st["restart_count"] = 0
    if st.get("restart_count", 0) >= cfg.getint("operations", "restart_max_per_day"):
        log.info("%s hit daily restart cap — skipping", ip)
        return False
    last = st.get("last_restart")
    if last:
        age_min = (time.time() - last) / 60
        if age_min < cfg.getint("operations", "restart_cooldown_min"):
            log.info("%s in restart cooldown (%.0f min) — skipping", ip, age_min)
            return False
    state[ip] = st
    return True


def record_restart(ip: str, state: dict):
    st = state.setdefault(ip, {})
    st["last_restart"] = time.time()
    st["restart_count"] = st.get("restart_count", 0) + 1


# ── FLEET SWEEP ───────────────────────────────────────────────────────────────
def sweep(cfg: configparser.ConfigParser, auth: HTTPDigestAuth) -> list[dict]:
    subnet = cfg.get("site", "subnet")
    port = cfg.getint("site", "cgminer_port")
    ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(scan_port, f"{subnet}.{i}", port): i for i in range(1, 255)}
        for fut in concurrent.futures.as_completed(futs):
            if fut.result():
                ips.append(f"{subnet}.{futs[fut]}")
    ips.sort(key=lambda x: int(x.split(".")[-1]))
    log.info("Sweep: %d miner(s) responding on :%d", len(ips), port)
    fleet = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for m in ex.map(lambda ip: diagnose(ip, cfg, auth), ips):
            fleet.append(m)
    return fleet


def handle_alerts_and_ops(fleet: list[dict], state: dict, cfg: configparser.ConfigParser,
                          auth: HTTPDigestAuth, conn: sqlite3.Connection | None = None):
    auto = cfg.getboolean("operations", "auto_restart")
    open_issues = {k: v for k, v in state.get("_issues", {}).items()}  # ip -> issue

    for m in fleet:
        ip = m["ip"]
        prev = open_issues.get(ip)
        # edge-triggered: new or changed issue
        if m["issue"] and m["issue"] != prev:
            notify(cfg, m["severity"], f"{ip}: {m['issue']}", m["detail"])
            if conn:
                log_event_db(conn, m.get("mac", ip), "issue_open", f"{m['issue']}: {m['detail']}")
            open_issues[ip] = m["issue"]
        # cleared
        elif not m["issue"] and prev:
            notify(cfg, "info", f"{ip}: RESOLVED ({prev})", "Miner is healthy again.")
            if conn:
                log_event_db(conn, m.get("mac", ip), "issue_clear", prev)
            open_issues.pop(ip, None)

        push_platform(m, cfg)

        # auto-restart: only hung/restartable, only if enabled, never dead-fan
        if auto and m["restartable"] and m["issue"] in ("NO-HASH", "UNREACHABLE"):
            if can_restart(ip, state, cfg):
                if reboot_miner(ip, cfg, auth, reason=m["issue"]):
                    record_restart(ip, state)
                    if conn:
                        log_event_db(conn, m.get("mac", ip), "reboot", f"auto: {m['issue']}")
                    notify(cfg, "warning", f"{ip}: auto-restarted", f"Reason: {m['issue']} — {m['detail']}")

    state["_issues"] = open_issues
    save_state(state)


# ── ENTRY POINTS ──────────────────────────────────────────────────────────────
def cmd_run(cfg, auth):
    log.info("=" * 60)
    log.info("Cryptotherm Mine Manager — site '%s'", cfg.get("site", "name"))
    log.info("Subnet %s.0/24 | interval %ss | dry_run=%s | auto_restart=%s",
             cfg.get("site", "subnet"), cfg.get("site", "scan_interval"),
             cfg.get("operations", "dry_run"), cfg.get("operations", "auto_restart"))
    log.info("=" * 60)
    state = load_state()
    conn = db_connect(cfg)
    interval = cfg.getint("site", "scan_interval")
    report_every = cfg.getint("reports", "interval_hours") * 3600
    last_report = 0.0
    while True:
        try:
            fleet = sweep(cfg, auth)
            persist(conn, fleet)
            push_server(fleet, cfg)
            handle_alerts_and_ops(fleet, state, cfg, auth, conn)
            if cfg.getboolean("reports", "enabled") and (time.time() - last_report) >= report_every:
                text, data = build_report(fleet, cfg)
                write_report(text, data, cfg)
                last_report = time.time()
        except KeyboardInterrupt:
            log.info("Shutting down.")
            break
        except Exception as e:  # noqa: BLE001
            log.error("sweep error: %s", e, exc_info=True)
        time.sleep(interval)


def cmd_status(cfg, auth):
    fleet = sweep(cfg, auth)
    text, _ = build_report(fleet, cfg)
    print(text)


def cmd_report(cfg, auth):
    fleet = sweep(cfg, auth)
    text, data = build_report(fleet, cfg)
    write_report(text, data, cfg)
    print(text)


def cmd_restart(cfg, auth, ip):
    ok = reboot_miner(ip, cfg, auth, reason="manual CLI")
    print("reboot sent" if ok else "no command sent (dry_run or error) — check log")


def cmd_set_pool(cfg, auth, args):
    ok = set_pool(args.ip, args.url, args.user, args.password or "", cfg, auth, args.yes)
    print("pool change sent" if ok else "refused / no change — check log")


def cmd_assign(cfg, args):
    """Associate a miner (by MAC) with a client, for billing."""
    conn = db_connect(cfg)
    cur = conn.cursor()
    cur.execute("SELECT mac FROM miners WHERE mac=?", (args.mac,))
    if not cur.fetchone():
        # allow pre-registering a miner we haven't swept yet
        cur.execute("INSERT INTO miners(mac,first_seen,last_seen) VALUES(?,?,?)",
                    (args.mac, datetime.now(timezone.utc).isoformat(),
                     datetime.now(timezone.utc).isoformat()))
    cur.execute("UPDATE miners SET client=COALESCE(?,client), rated_watts=COALESCE(?,rated_watts) WHERE mac=?",
                (args.client, args.rated_watts, args.mac))
    conn.commit()
    row = cur.execute("SELECT mac,client,rated_watts,model FROM miners WHERE mac=?", (args.mac,)).fetchone()
    print(f"assigned: mac={row[0]} client={row[1]} rated_watts={row[2]} model={row[3]}")


def cmd_bill(cfg, args):
    conn = db_connect(cfg)
    dt_from = args.dt_from or "0000"
    dt_to = args.dt_to or datetime.now(timezone.utc).isoformat()
    result = compute_billing(conn, cfg, dt_from, dt_to)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Billing {result['from']} .. {result['to']}  @ ${result['rate_per_kwh']}/kWh")
    print("=" * 52)
    print(f"{'CLIENT':<22}{'MINERS':>8}{'kWh':>12}{'COST':>10}")
    for client, c in sorted(result["clients"].items(), key=lambda kv: -kv[1]["kwh"]):
        print(f"{client:<22}{c['miners']:>8}{c['kwh']:>12.2f}{'$'+format(c['cost'],'.2f'):>10}")


def cmd_history(cfg, args):
    conn = db_connect(cfg)
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT ts,ip,hashrate,temp_max,power_watts,power_source,state,issue "
        "FROM samples WHERE mac=? ORDER BY ts DESC LIMIT ?", (args.mac, args.limit)).fetchall()
    if not rows:
        print(f"no history for {args.mac}")
        return
    info = cur.execute("SELECT model,serial,client,first_seen FROM miners WHERE mac=?", (args.mac,)).fetchone()
    if info:
        print(f"{args.mac}  model={info[0]} serial={info[1]} client={info[2]} since={info[3]}")
    print(f"{'TS':<28}{'IP':<16}{'HASH':>9}{'TEMP':>6}{'WATT':>8} SRC        STATE/ISSUE")
    for ts, ip, hr, temp, w, src, state, issue in rows:
        print(f"{ts:<28}{ip:<16}{hr:>9.0f}{temp:>6.0f}{w:>8.0f} {src:<10} {state}/{issue or '-'}")


def main():
    setup_logging()
    ap = argparse.ArgumentParser(description="Cryptotherm Mine Manager")
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "mine-manager.conf"))
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run")
    sub.add_parser("status")
    sub.add_parser("report")
    pr = sub.add_parser("restart"); pr.add_argument("ip")
    sp = sub.add_parser("set-pool")
    sp.add_argument("ip")
    sp.add_argument("--url", required=True)
    sp.add_argument("--user", required=True)
    sp.add_argument("--pass", dest="password", default="")
    sp.add_argument("--yes", action="store_true", help="skip interactive IP-retype confirmation")
    asg = sub.add_parser("assign", help="map a miner MAC to a client (for billing)")
    asg.add_argument("mac")
    asg.add_argument("--client", default=None)
    asg.add_argument("--rated-watts", dest="rated_watts", type=float, default=None)
    bl = sub.add_parser("bill", help="energy + cost per client over a period")
    bl.add_argument("--from", dest="dt_from", default=None, help="ISO start, e.g. 2026-09-01")
    bl.add_argument("--to", dest="dt_to", default=None, help="ISO end (default: now)")
    bl.add_argument("--json", action="store_true")
    hi = sub.add_parser("history", help="recent samples for one miner MAC")
    hi.add_argument("mac")
    hi.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    cfg = load_config(args.config)
    auth = HTTPDigestAuth(cfg.get("auth", "miner_user"),
                          os.environ.get("CT_MINER_PASS", cfg.get("auth", "miner_pass")))

    cmd = args.cmd or "run"
    if cmd == "run":
        cmd_run(cfg, auth)
    elif cmd == "status":
        cmd_status(cfg, auth)
    elif cmd == "report":
        cmd_report(cfg, auth)
    elif cmd == "restart":
        cmd_restart(cfg, auth, args.ip)
    elif cmd == "set-pool":
        cmd_set_pool(cfg, auth, args)
    elif cmd == "assign":
        cmd_assign(cfg, args)
    elif cmd == "bill":
        cmd_bill(cfg, args)
    elif cmd == "history":
        cmd_history(cfg, args)


if __name__ == "__main__":
    main()
