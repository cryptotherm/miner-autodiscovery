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
import smtplib
import socket
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
    "platform":   {"enabled": "false", "api": "", "token_env": "CT_PLATFORM_TOKEN"},
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
    try:
        r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
        for part in r.stdout.split():
            if ":" in part and len(part) == 17:
                return part.upper()
    except Exception:  # noqa: BLE001
        pass
    return "00:00:00:00:00:00"


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
        "reachable": False, "model": "Unknown", "hashrate": 0.0, "ideal": 0.0,
        "accepted": 0, "rejected": 0, "elapsed": 0, "fans": [], "temp_max": 0.0,
        "pool": "", "worker": "", "pool_status": "",
        "state": "UNKNOWN", "severity": "info", "issue": None, "detail": "",
        "restartable": False,
    }

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

    summ = query_cgminer(ip, "summary", port)
    if summ:
        s = summ.get("SUMMARY", [{}])[0]
        r["hashrate"] = float(s.get("GHS 5s", s.get("MHS 5s", 0)) or 0)
        r["accepted"] = int(s.get("Accepted", 0) or 0)
        r["rejected"] = int(s.get("Rejected", 0) or 0)
        r["elapsed"] = int(s.get("Elapsed", 0) or 0)
        r["ideal"] = float(s.get("rate_ideal", 0) or 0)

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


def handle_alerts_and_ops(fleet: list[dict], state: dict, cfg: configparser.ConfigParser, auth: HTTPDigestAuth):
    auto = cfg.getboolean("operations", "auto_restart")
    open_issues = {k: v for k, v in state.get("_issues", {}).items()}  # ip -> issue

    for m in fleet:
        ip = m["ip"]
        prev = open_issues.get(ip)
        # edge-triggered: new or changed issue
        if m["issue"] and m["issue"] != prev:
            notify(cfg, m["severity"], f"{ip}: {m['issue']}", m["detail"])
            open_issues[ip] = m["issue"]
        # cleared
        elif not m["issue"] and prev:
            notify(cfg, "info", f"{ip}: RESOLVED ({prev})", "Miner is healthy again.")
            open_issues.pop(ip, None)

        push_platform(m, cfg)

        # auto-restart: only hung/restartable, only if enabled, never dead-fan
        if auto and m["restartable"] and m["issue"] in ("NO-HASH", "UNREACHABLE"):
            if can_restart(ip, state, cfg):
                if reboot_miner(ip, cfg, auth, reason=m["issue"]):
                    record_restart(ip, state)
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
    interval = cfg.getint("site", "scan_interval")
    report_every = cfg.getint("reports", "interval_hours") * 3600
    last_report = 0.0
    while True:
        try:
            fleet = sweep(cfg, auth)
            handle_alerts_and_ops(fleet, state, cfg, auth)
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


if __name__ == "__main__":
    main()
