#!/usr/bin/env python3
"""
Cryptotherm Miner Auto-Discovery & Diagnostic System
Watches for new miners on the network, runs diagnostics, prints CT labels.

Deploy on: CTHome, Alienware, Mac (any machine with network access)
Requires: python3, brother_ql (on print host), requests
"""

import json, time, subprocess, socket, logging, os, sys, hashlib
import configparser
import requests
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────────────────────────
# Values come from autodiscovery.conf (same dir or /etc/ct/), falling back to
# the defaults below so the script still runs standalone.
_cfg = configparser.ConfigParser()
_cfg.read([
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "autodiscovery.conf"),
    "/etc/ct/autodiscovery.conf",
])

def _conf(section, key, default):
    try:
        return _cfg.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default

PLATFORM_API   = _conf("discovery", "platform_api", "http://20.125.62.35:8080").rstrip("/")
PLATFORM_TOKEN = _conf("discovery", "platform_token", os.environ.get("CT_PLATFORM_TOKEN", ""))
PRINTER_IP     = _conf("discovery", "printer_ip", "10.0.0.119")      # QL-810W WiFi
PRINT_HOST     = _conf("print", "print_host", "10.0.0.248")          # CTHome — where brother_ql runs
SUBNET         = _conf("discovery", "subnet", "10.0.0")
SCAN_INTERVAL  = int(_conf("discovery", "scan_interval", 30))        # seconds between sweeps
CGMINER_PORT   = 4028
CGMINER_TIMEOUT = 3
STATE_FILE     = "/tmp/ct_discovered_miners.json"
LOG_FILE       = _conf("logging", "log_file", "/var/log/ct_autodiscovery.log")

WARMUP_WAIT_MIN     = int(_conf("thresholds", "warmup_wait_min", 10))
FAIL_NO_HASH_MIN    = int(_conf("thresholds", "fail_if_no_hash_after_min", 20))

# Pools we operate — a primary pool whose URL matches none of these substrings
# gets flagged so the platform GUI can prompt "tag to in-testing / a site?".
KNOWN_POOLS = [p.strip().lower() for p in
               _conf("discovery", "known_pools", "").split(",") if p.strip()]

# Firmware families we allow on outgoing units. Anything else (e.g. vnish on
# incoming bench units) is flagged needs_reflash so the platform can queue a
# wipe + stock/Braiins/LuxOS install.
APPROVED_FIRMWARE = [f.strip().lower() for f in
                     _conf("discovery", "approved_firmware",
                           "stock,braiins,luxos").split(",") if f.strip()]

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, mode='a') if os.access('/var/log', os.W_OK)
        else logging.StreamHandler()
    ]
)
log = logging.getLogger("ct_autodiscovery")

HEADERS = {"Authorization": f"Bearer {PLATFORM_TOKEN}", "Content-Type": "application/json"}

# ── KNOWN MINER SIGNATURES ──────────────────────────────────────────────────
# Longest-prefix match against the model string reported by the miner.
# ideal_ths is the stock nameplate — used as a sanity reference, not a gate.
MINER_MODELS = {
    # Bitmain S19 family
    "Antminer S19k Pro": {"algo": "SHA-256", "ideal_ths": 120, "fans": 4, "chains": 3, "asics_per_chain": 77},
    "Antminer S19j Pro+":{"algo": "SHA-256", "ideal_ths": 122, "fans": 4, "chains": 3, "asics_per_chain": 120},
    "Antminer S19j Pro": {"algo": "SHA-256", "ideal_ths": 104, "fans": 4, "chains": 3, "asics_per_chain": 126},
    "Antminer S19 XP":   {"algo": "SHA-256", "ideal_ths": 141, "fans": 4, "chains": 3, "asics_per_chain": 110},
    "Antminer S19 Pro":  {"algo": "SHA-256", "ideal_ths": 110, "fans": 4, "chains": 3, "asics_per_chain": 114},
    "Antminer S19":      {"algo": "SHA-256", "ideal_ths": 95,  "fans": 4, "chains": 3, "asics_per_chain": 76},
    # Bitmain S21/T21 family (2024-2026)
    "Antminer S21 XP":   {"algo": "SHA-256", "ideal_ths": 270, "fans": 4, "chains": 3, "asics_per_chain": 216},
    "Antminer S21 Pro":  {"algo": "SHA-256", "ideal_ths": 234, "fans": 4, "chains": 3, "asics_per_chain": 216},
    "Antminer S21+":     {"algo": "SHA-256", "ideal_ths": 216, "fans": 4, "chains": 3, "asics_per_chain": 216},
    "Antminer S21e":     {"algo": "SHA-256", "ideal_ths": 195, "fans": 4, "chains": 3, "asics_per_chain": 216},
    "Antminer S21":      {"algo": "SHA-256", "ideal_ths": 200, "fans": 4, "chains": 3, "asics_per_chain": 216},
    "Antminer T21":      {"algo": "SHA-256", "ideal_ths": 190, "fans": 4, "chains": 3, "asics_per_chain": 216},
    # Bitmain other algos
    "Antminer L7":       {"algo": "Scrypt",  "ideal_ghs": 9.16,"fans": 4, "chains": 1, "asics_per_chain": 0},
    "Antminer L9":       {"algo": "Scrypt",  "ideal_ghs": 16,  "fans": 4, "chains": 1, "asics_per_chain": 0},
    # MicroBT WhatsMiner (M3x/M5x/M6x) — model strings look like "M66S+VK30" etc.
    "WhatsMiner M66S++": {"algo": "SHA-256", "ideal_ths": 348, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M66S+":  {"algo": "SHA-256", "ideal_ths": 318, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M66S":   {"algo": "SHA-256", "ideal_ths": 298, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M66":    {"algo": "SHA-256", "ideal_ths": 276, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M56S":   {"algo": "SHA-256", "ideal_ths": 212, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M56":    {"algo": "SHA-256", "ideal_ths": 194, "fans": 0, "chains": 3, "asics_per_chain": 0},  # hydro
    "WhatsMiner M60S":   {"algo": "SHA-256", "ideal_ths": 186, "fans": 2, "chains": 3, "asics_per_chain": 0},
    "WhatsMiner M60":    {"algo": "SHA-256", "ideal_ths": 172, "fans": 2, "chains": 3, "asics_per_chain": 0},
    "WhatsMiner M50S":   {"algo": "SHA-256", "ideal_ths": 126, "fans": 2, "chains": 3, "asics_per_chain": 0},
    "WhatsMiner M50":    {"algo": "SHA-256", "ideal_ths": 114, "fans": 2, "chains": 3, "asics_per_chain": 135},
    "WhatsMiner M30S":   {"algo": "SHA-256", "ideal_ths": 100, "fans": 2, "chains": 3, "asics_per_chain": 148},
    "MicroBT WhatsMiner":{"algo": "SHA-256", "ideal_ths": 103, "fans": 2, "chains": 3, "asics_per_chain": 156},
}

def match_model(model_str: str) -> dict:
    """Longest-prefix match of a reported model string against MINER_MODELS."""
    m = (model_str or "").strip()
    best = None
    for name in MINER_MODELS:
        if m.lower().startswith(name.lower()) or name.lower() in m.lower():
            if best is None or len(name) > len(best):
                best = name
    return {"match": best, **MINER_MODELS.get(best, {})} if best else {}

# ── NETWORK DISCOVERY ───────────────────────────────────────────────────────
def scan_cgminer_port(ip: str) -> bool:
    """Check if cgminer API is responding on port 4028."""
    try:
        with socket.create_connection((ip, CGMINER_PORT), timeout=1):
            return True
    except:
        return False

def query_cgminer(ip: str, command: str) -> dict | None:
    """Send a cgminer API command and return parsed JSON."""
    try:
        with socket.create_connection((ip, CGMINER_PORT), timeout=CGMINER_TIMEOUT) as s:
            s.sendall((json.dumps({"command": command}) + "\n").encode())
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
    except Exception as e:
        log.debug(f"cgminer query {ip}/{command} failed: {e}")
        return None

def get_mac(ip: str) -> str:
    """Get MAC address from ARP table."""
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
        for part in result.stdout.split():
            if ":" in part and len(part) == 17:
                return part.upper()
    except:
        pass
    return "00:00:00:00:00:00"

def get_web_info(ip: str) -> dict:
    """Get serial, firmware, model from Antminer web API."""
    info = {}
    try:
        r = requests.get(f"http://{ip}/cgi-bin/get_system_info.cgi",
                        auth=requests.auth.HTTPDigestAuth("root", "root"),
                        timeout=3)
        if r.status_code == 200:
            d = r.json()
            info["serial"] = d.get("serinum", "")
            info["model"] = d.get("minertype", "")
            info["mac"] = d.get("macaddr", "")
    except:
        pass
    return info

def get_stats(ip: str) -> dict:
    """Get detailed chain/fan stats from Antminer web API."""
    try:
        r = requests.get(f"http://{ip}/cgi-bin/stats.cgi",
                        auth=requests.auth.HTTPDigestAuth("root", "root"),
                        timeout=5)
        if r.status_code == 200:
            return r.json().get("STATS", [{}])[0]
    except:
        pass
    return {}

# ── FIRMWARE DETECTION ──────────────────────────────────────────────────────
def detect_firmware(ver: dict | None, web: dict | None = None) -> tuple[str, str]:
    """
    Classify the firmware family running on a miner from its cgminer/btminer
    `version` response (plus web info when available).

    Returns (family, version_string) where family is one of:
      stock | braiins | luxos | vnish | unknown
    """
    if not ver:
        return "unknown", ""
    v = ver.get("VERSION", [{}])[0]
    blob = (json.dumps(ver) + json.dumps(web or {})).lower()

    if "bosminer" in blob or "braiins" in blob or "bos+" in blob:
        return "braiins", str(v.get("BOSminer", v.get("BOSer", v.get("bosminer", ""))))
    if "luxminer" in blob or "luxos" in blob:
        return "luxos", str(v.get("LUXminer", ""))
    if "vnish" in blob:
        # Vnish typically appends itself to Type, e.g. "Antminer S19 (Vnish 1.2.6)"
        return "vnish", str(v.get("Type", ""))
    if "btminer" in blob or "whatsminer" in blob:
        return "stock", str(v.get("BTMiner", v.get("API", "")))       # MicroBT stock
    if "bmminer" in blob or "cgminer" in blob or "antminer" in blob:
        return "stock", str(v.get("BMMiner", v.get("CGMiner", "")))   # Bitmain stock
    return "unknown", str(v.get("Type", ""))

# ── DIAGNOSTICS ─────────────────────────────────────────────────────────────
def run_diagnostics(ip: str) -> dict:
    """Full diagnostic run on a newly discovered miner."""
    log.info(f"Running diagnostics on {ip}...")
    result = {
        "ip": ip,
        "mac": get_mac(ip),
        "timestamp": datetime.now().isoformat(),
        "test_result": "PENDING",
        "fault_code": None,
        "fault_title": None,
        "model": "Unknown",
        "serial": "",
        "hashrate_5s": 0,
        "hashrate_ideal": 0,
        "accepted": 0,
        "elapsed": 0,
        "fans": [],
        "chains": [],
        "symptoms": [],
        "fix_steps": [],
        "health": 50,
    }

    # Get version/model
    ver = query_cgminer(ip, "version")
    if ver:
        v = ver.get("VERSION", [{}])[0]
        result["model"] = v.get("Type", "Unknown")
        result["firmware"] = v.get("BMMiner", "?")

    # Get web info (serial, etc)
    web = get_web_info(ip)
    if web.get("serial"): result["serial"] = web["serial"]
    if web.get("model"):  result["model"]  = web["model"]
    if web.get("mac"):    result["mac"]    = web["mac"]

    # Firmware family (stock / braiins / luxos / vnish / unknown)
    fw_family, fw_version = detect_firmware(ver, web)
    result["firmware_type"]    = fw_family
    result["firmware_version"] = fw_version
    result["needs_reflash"]    = fw_family not in APPROVED_FIRMWARE
    if result["needs_reflash"]:
        result["symptoms"].append(
            f"Firmware '{fw_family}' not approved — wipe & reflash "
            f"({'/'.join(APPROVED_FIRMWARE)}) before shipping")

    # Model signature match (S21 family, WhatsMiner M5x/M6x, etc.)
    sig = match_model(result["model"])
    if sig:
        result["model_match"]  = sig.get("match")
        result["ideal_ths_spec"] = sig.get("ideal_ths", 0)

    # Get summary
    summ = query_cgminer(ip, "summary")
    if summ:
        s = summ.get("SUMMARY", [{}])[0]
        result["hashrate_5s"]   = s.get("GHS 5s", s.get("MHS 5s", 0))
        result["accepted"]      = s.get("Accepted", 0)
        result["elapsed"]       = s.get("Elapsed", 0)
        result["hashrate_ideal"] = s.get("rate_ideal", 0)

    # Get pools
    pools = query_cgminer(ip, "pools")
    if pools:
        p0 = next((p for p in pools.get("POOLS",[]) if p.get("Priority",p.get("POOL",99))==0), {})
        result["pool"]   = p0.get("URL", "")
        result["worker"] = p0.get("User", "")
        result["pool_status"] = p0.get("Status", "")

    # Pool recognition — unknown pool means the unit arrived with a customer /
    # previous-owner config. Flag it so the GUI can prompt: tag to in-testing
    # pool or a site, and remember the choice for the batch.
    pool_url = (result.get("pool") or "").lower()
    result["pool_known"] = (not KNOWN_POOLS) or any(k in pool_url for k in KNOWN_POOLS)
    if pool_url and not result["pool_known"]:
        result["symptoms"].append(f"Unrecognized pool: {result['pool']} — needs tagging (in-testing or site)")

    # Get stats (fans + chains) — Antminer HTTP
    stats = get_stats(ip)
    if stats:
        result["fans"]   = stats.get("fan", [])
        result["chains"] = stats.get("chain", [])
        result["fan_num"] = stats.get("fan_num", 0)
        result["chain_num"] = stats.get("chain_num", 0)
        # Check summary status
        summ2_r = requests.get(f"http://{ip}/cgi-bin/summary.cgi",
                               auth=requests.auth.HTTPDigestAuth("root","root"), timeout=3)
        if summ2_r.ok:
            for st in summ2_r.json().get("SUMMARY",[{}])[0].get("status",[]):
                if st.get("status") == "e":
                    result["symptoms"].append(f"{st['type'].upper()}: {st['msg']}")

    # WhatsMiner devs
    devs = query_cgminer(ip, "devs")
    if devs and "DEVS" in devs:
        result["chains"] = devs.get("DEVS", [])
        result["chain_num"] = len(result["chains"])

    # ── FAULT DETECTION ─────────────────────────────────────────────────────
    fans = result.get("fans", [])
    chains = result.get("chains", [])
    elapsed_min = result["elapsed"] / 60

    # Fan check
    dead_fans = [i+1 for i,rpm in enumerate(fans) if rpm == 0]
    if dead_fans:
        result["symptoms"].insert(0, f"Fan(s) {dead_fans} = 0 RPM [DEAD]")
        result["fault_code"]  = "FAN-INLET-FAIL"
        result["fault_title"] = f"Fan(s) {dead_fans} dead — thermal protection active"
        result["fix_steps"] = [
            "Power OFF completely",
            f"Inspect Fan(s) {dead_fans} — check connectors and blades",
            "Replace failed fan(s) (4-pin PWM 12V)",
            "Power ON — verify all fans spin",
            "Confirm hashrate climbs within 10 min",
            "Reprint CT label as PASS",
        ]
        result["test_result"] = "FAIL"
        result["health"] = 25

    # ASIC chain check
    elif chains and isinstance(chains[0], dict):
        for c in chains:
            bad = 0
            total = 0
            if "asic" in c:  # Antminer format
                bad = c["asic"].count("x") if isinstance(c["asic"], str) else 0
                total = c.get("asic_num", 77)
            elif "Effective Chips" in c:  # WhatsMiner format
                total = c.get("Effective Chips", 156)
                bad = 0
            rate = c.get("rate_real", c.get("MHS 5s", 0))
            if bad > 0 or (total > 0 and rate == 0 and elapsed_min > 15):
                chain_id = c.get("index", c.get("ASC", "?"))
                sn = c.get("sn", c.get("PCB SN", "?"))
                result["symptoms"].insert(0, f"Chain {chain_id}: {total-bad}/{total} ASICs, rate={rate:.0f}")
                result["fault_code"]  = f"ASIC-CHAIN{chain_id}-PARTIAL"
                result["fault_title"] = f"Chain {chain_id}: {total-bad}/{total} ASICs found"
                result["fix_steps"] = [
                    "Power OFF completely — wait 60s",
                    f"Remove hashboard {chain_id} (Chain index {chain_id})",
                    "Inspect board for burnt chips, cracked solder, corrosion",
                    "Check ribbon cable — reseat connector",
                    f"Need {total}/{total} ASICs — replace board if count stays low",
                    "Run 30 min burn-in, confirm stable hashrate",
                    "Reprint CT label as PASS",
                ]
                result["test_result"] = "FAIL"
                result["health"] = 20
                break

    # Pool check
    elif result.get("pool_status") in ("Deed", "Dead", "") and elapsed_min > 5:
        result["symptoms"].append(f"Pool status: {result.get('pool_status','?')} — not connected")
        result["fault_code"]  = "POOL-DEAD"
        result["fault_title"] = "Pool not connecting — check stratum config"
        result["fix_steps"] = [
            "Verify pool URL and worker name in miner config",
            "Check firewall — test port: nc -zv <pool_host> <port>",
            "Log into miner web admin and update pool settings",
            "Reboot miner after pool config change",
        ]
        result["test_result"] = "FAIL"
        result["health"] = 30

    # PASS check — hashing with accepted shares
    elif result["accepted"] > 0 and result["hashrate_5s"] > 0:
        result["test_result"] = "PASS"
        result["health"] = min(98, 60 + int(result["accepted"] / 100))
        result["symptoms"] = []

    # Still warming up
    elif elapsed_min < 15 and not result["fault_code"]:
        result["test_result"] = "PENDING"
        result["health"] = 50
        result["symptoms"].append(f"Warming up — {elapsed_min:.0f} min elapsed")

    # Hashing but no accepted yet
    elif result["hashrate_5s"] > 0:
        result["test_result"] = "PASS"
        result["health"] = 70

    log.info(f"  {ip}: {result['model']} | {result['test_result']} | {result.get('fault_code','OK')}")
    return result

# ── PLATFORM API ─────────────────────────────────────────────────────────────
def get_or_create_miner(diag: dict) -> tuple[str, str]:
    """Register miner in platform API, return (miner_id, ct_id)."""
    # Check if already exists
    r = requests.get(f"{PLATFORM_API}/miners", headers=HEADERS, timeout=5)
    miners = r.json().get("miners", r.json() if isinstance(r.json(), list) else [])

    # Match by durable identity first — IPs on the bench are DHCP and get
    # reused between units, which used to hand a new miner the previous
    # unit's CT ID (and print the wrong label). Serial > MAC > IP.
    serial = (diag.get("serial") or "").strip()
    mac    = (diag.get("mac") or "").strip().upper()
    existing = None
    if serial:
        existing = next((m for m in miners if (m.get("serial") or "").strip() == serial), None)
    if not existing and mac and mac != "00:00:00:00:00:00":
        existing = next((m for m in miners if (m.get("mac") or "").strip().upper() == mac), None)
    if not existing:
        ip_match = next((m for m in miners if m.get("ip_address") == diag["ip"]), None)
        # Only trust an IP match when identities don't contradict it.
        if ip_match:
            m_serial = (ip_match.get("serial") or "").strip()
            m_mac    = (ip_match.get("mac") or "").strip().upper()
            serial_conflict = bool(serial and m_serial and m_serial != serial)
            mac_conflict    = bool(mac and mac != "00:00:00:00:00:00"
                                   and m_mac and m_mac != mac)
            if serial_conflict or mac_conflict:
                log.warning(f"  IP {diag['ip']} matches {ip_match.get('name')} but "
                            f"serial/MAC differ — treating as a NEW miner (IP reuse)")
            else:
                existing = ip_match
    if existing:
        return existing["id"], existing.get("name", "CT-????")

    # Assign next CT ID
    ct_nums = []
    for m in miners:
        n = m.get("name", "")
        if n.startswith("CT-2026-"):
            try: ct_nums.append(int(n.split("-")[2]))
            except: pass
    next_num = max(ct_nums, default=0) + 1
    ct_id = f"CT-2026-{next_num:03d}"

    payload = {
        "name": ct_id,
        "ip_address": diag["ip"],
        "model": diag.get("model", "Unknown"),
        "pool_user": diag.get("worker", ""),
        "serial": diag.get("serial", ""),
        "mac": diag.get("mac", ""),
        "firmware_type": diag.get("firmware_type", "unknown"),
        "firmware_version": diag.get("firmware_version", ""),
    }
    r = requests.post(f"{PLATFORM_API}/miners", headers=HEADERS, json=payload, timeout=5)
    miner_id = r.json().get("miner", {}).get("id", "")
    log.info(f"  Registered {ct_id} ({diag['ip']}) in platform API: {miner_id}")
    return miner_id, ct_id

def push_telemetry(miner_id: str, diag: dict):
    """Push current stats to platform API."""
    payload = {
        "hashrate_th": diag.get("hashrate_5s", 0) / 1000 if diag.get("hashrate_5s",0) > 1000 else diag.get("hashrate_5s", 0),
        "temperature": 0,
        "power_watts": 0,
        "accepted_shares": diag.get("accepted", 0),
        "rejected_shares": 0,
        "uptime_seconds": diag.get("elapsed", 0),
        "status": diag.get("test_result", "PENDING"),
        "firmware_type": diag.get("firmware_type", "unknown"),
        "firmware_version": diag.get("firmware_version", ""),
        "needs_reflash": diag.get("needs_reflash", False),
        "pool_url": diag.get("pool", ""),
        "pool_known": diag.get("pool_known", True),
        "serial": diag.get("serial", ""),
    }
    try:
        requests.post(f"{PLATFORM_API}/miners/{miner_id}/telemetry",
                     headers=HEADERS, json=payload, timeout=5)
    except:
        pass

# ── PRINT TRIGGER ─────────────────────────────────────────────────────────────
PRINT_USER     = _conf("print", "print_user", "ctadmin")
PRINT_SSH_PORT = _conf("print", "print_ssh_port", "22")

def trigger_print(diag: dict, ct_id: str):
    """Trigger label print — locally if brother_ql is installed, else via SSH
    to the print host. Retries up to 3 times; label leads with CT ID + serial
    so the sticker is unambiguous about which physical unit it belongs to."""
    script = f"""
import sys, os, datetime, qrcode
sys.path.insert(0, os.path.expanduser("~/Library/Python/3.9/lib/python/site-packages"))
try:
    from PIL import Image, ImageDraw, ImageFont
    from brother_ql.conversion import convert
    from brother_ql.backends.helpers import send
    from brother_ql.raster import BrotherQLRaster
except ImportError:
    # Try system python path
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "--user", "brother_ql", "qrcode", "pillow"], capture_output=True)
    from PIL import Image, ImageDraw, ImageFont
    from brother_ql.conversion import convert
    from brother_ql.backends.helpers import send
    from brother_ql.raster import BrotherQLRaster

PRINTER = "tcp://{PRINTER_IP}"
NOW = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def gf(size):
    for p in ["/System/Library/Fonts/Helvetica.ttc","/Library/Fonts/Arial.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]:
        try: return ImageFont.truetype(p, size)
        except: pass
    return ImageFont.load_default()

fBIG=gf(32); fMED=gf(26); fSML=gf(21); fTINY=gf(16)

qr_mod = qrcode.QRCode(version=3,box_size=3,border=1)
qr_mod.add_data("CT:{ct_id}|SN:{diag.get('serial','')}|IP:{diag['ip']}|MAC:{diag['mac']}|MODEL:{diag['model']}|"+NOW)
qr_mod.make(fit=True)
qr_img = qr_mod.make_image(fill_color="black",back_color="white").convert("RGB").resize((88,88))

W,H = 696, 520
img = Image.new("RGB",(W,H),"white")
d = ImageDraw.Draw(img)
d.rectangle([0,0,W-1,H-1],outline="black",width=5)

# Header
d.rectangle([0,0,W,88],fill="black")
img.paste(qr_img,(6,2))
d.text((102,6),"{ct_id}",font=fBIG,fill="white")
d.text((102,42),"SN {diag.get('serial') or 'UNKNOWN — SCAN UNIT'}",font=fMED,fill="#ffffff")
d.text((102,68),"CRYPTOTHERM TESTING  |  "+NOW,font=fTINY,fill="#aaaaaa")

# Result banner
result="{diag['test_result']}"
d.rectangle([0,90,W,144],fill="black" if result=="PASS" else "#444444")
d.text((14,98),"TEST: "+result,font=fBIG,fill="white")

y=150
rows=[
    ("SERIAL", "{diag.get('serial') or '? — SCAN UNIT'}"),
    ("MODEL",  "{diag['model']}"),
    ("FW",     "{diag.get('firmware_type','?')} {diag.get('firmware_version','')}"),
    ("IP",     "{diag['ip']}"),
    ("MAC",    "{diag['mac']}"),
    ("POOL",   "{diag.get('worker','?')}"),
    ("HASH",   "%.1f GH/s" % float({diag.get('hashrate_5s',0)})),
    ("SHARES", "Acc:{diag.get('accepted',0)}  |  HEALTH {diag.get('health',0)}/100"),
]
for lbl,val in rows:
    d.text((12,y),lbl+":",font=fSML,fill="#555555")
    d.text((130,y),val,font=fSML,fill="black")
    d.line([12,y+30,W-12,y+30],fill="#dddddd",width=1)
    y+=34

# Fault
fault="{diag.get('fault_code') or ''}"
if fault:
    d.text((12,y),"FAULT: "+fault,font=fMED,fill="black"); y+=30
    d.text((12,y),"{diag.get('fault_title') or ''}",font=fSML,fill="black"); y+=28

# Footer
d.line([10,H-32,W-10,H-32],fill="black",width=2)
d.text((12,H-26),"Printed: "+NOW+" | Auto-Discovery | Cryptotherm",font=fTINY,fill="black")

qlr=BrotherQLRaster("QL-810W"); qlr.exception_on_warning=True
convert(qlr=qlr,images=[img],label="62",rotate="0",threshold=70.0,dither=False,compress=False,red=False,dpi_600=False,hq=True,cut=True)
send(instructions=qlr.data,printer_identifier=PRINTER,backend_identifier="network",blocking=True)
print("PRINTED OK: {ct_id}")
"""

    # Run locally if brother_ql is available, else pipe the script over SSH
    # to the print host's stdin (`python3 -`). The old code passed both
    # input= and stdin= to subprocess.run — a ValueError on every call — and
    # told the remote shell to read a temp file that only existed locally,
    # so SSH printing never worked.
    serial = diag.get("serial") or "no-serial"
    have_local = subprocess.run(
        ["python3", "-c", "import brother_ql"], capture_output=True).returncode == 0

    for attempt in range(1, 4):
        try:
            if have_local:
                proc = subprocess.run(["python3", "-"], input=script.encode(),
                                      capture_output=True, timeout=60)
            else:
                proc = subprocess.run([
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=10", "-p", str(PRINT_SSH_PORT),
                    f"{PRINT_USER}@{PRINT_HOST}",
                    "export PATH=$HOME/Library/Python/3.9/bin:$PATH; python3 -",
                ], input=script.encode(), capture_output=True, timeout=60)

            out = proc.stdout.decode(errors="ignore")
            if proc.returncode == 0 and "PRINTED OK" in out:
                log.info(f"  Label printed: {ct_id} (SN {serial})")
                return
            err = proc.stderr.decode(errors="ignore").strip().splitlines()
            log.warning(f"  Print attempt {attempt}/3 failed for {ct_id} "
                        f"(SN {serial}): rc={proc.returncode} "
                        f"{err[-1] if err else out.strip()[-200:]}")
        except Exception as e:
            log.warning(f"  Print attempt {attempt}/3 error for {ct_id} (SN {serial}): {e}")
        time.sleep(5 * attempt)

    log.error(f"  PRINT FAILED after 3 attempts: {ct_id} (SN {serial}) — "
              f"check printer {PRINTER_IP} and print host {PRINT_HOST}")

# ── STATE MANAGEMENT ──────────────────────────────────────────────────────────
def load_state() -> dict:
    try:
        return json.loads(open(STATE_FILE).read())
    except:
        return {}

def save_state(state: dict):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def miner_fingerprint(ip: str, mac: str) -> str:
    return hashlib.md5(f"{ip}:{mac}".encode()).hexdigest()[:8]

# ── MAIN LOOP ─────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("Cryptotherm Auto-Discovery starting")
    log.info(f"Subnet: {SUBNET}.0/24  |  Interval: {SCAN_INTERVAL}s")
    log.info("=" * 60)

    state = load_state()  # {fingerprint: {ct_id, last_seen, test_result, ...}}

    while True:
        try:
            log.info(f"Scanning {SUBNET}.1-254 for miners...")
            found_ips = []

            # Parallel port scan
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(scan_cgminer_port, f"{SUBNET}.{i}"): i for i in range(1, 255)}
                for fut in concurrent.futures.as_completed(futures):
                    i = futures[fut]
                    if fut.result():
                        found_ips.append(f"{SUBNET}.{i}")

            log.info(f"Found {len(found_ips)} miner(s): {found_ips}")

            for ip in found_ips:
                mac = get_mac(ip)
                fp  = miner_fingerprint(ip, mac)

                # New miner?
                if fp not in state:
                    log.info(f"NEW MINER DETECTED: {ip} (MAC: {mac})")
                    diag = run_diagnostics(ip)

                    # Register + push telemetry right away so the platform
                    # sees the unit, but DON'T block the scan loop on warmup
                    # — the old 10-min sleep here stalled discovery and
                    # printing for every other miner on the bench.
                    miner_id, ct_id = get_or_create_miner(diag)
                    push_telemetry(miner_id, diag)

                    diag["ct_id"] = ct_id
                    diag["miner_id"] = miner_id
                    state[fp] = {
                        "ct_id": ct_id, "miner_id": miner_id,
                        "ip": ip, "mac": mac,
                        "serial": diag.get("serial",""),
                        "test_result": diag["test_result"],
                        "model": diag.get("model","?"),
                        "firmware_type": diag.get("firmware_type","unknown"),
                        "first_seen": datetime.now().isoformat(),
                        "last_seen": datetime.now().isoformat(),
                        "label_printed": False,
                    }

                    if diag["test_result"] == "PENDING":
                        log.info(f"  {ct_id} warming up — will re-check on next sweeps (no label yet)")
                    else:
                        log.info(f"  Printing CT label for {ct_id}...")
                        trigger_print(diag, ct_id)
                        state[fp]["label_printed"] = True
                    save_state(state)

                else:
                    # Known miner — update last seen; finish any pending warmup
                    entry = state[fp]
                    entry["last_seen"] = datetime.now().isoformat()

                    if entry.get("test_result") == "PENDING":
                        diag = run_diagnostics(ip)
                        waited_min = (datetime.now() -
                                      datetime.fromisoformat(entry["first_seen"])).total_seconds() / 60

                        # Give up waiting: no hash after the configured window
                        if diag["test_result"] == "PENDING" and waited_min >= FAIL_NO_HASH_MIN:
                            diag["test_result"] = "FAIL"
                            diag["fault_code"]  = "NO-HASH-TIMEOUT"
                            diag["fault_title"] = f"No hashrate after {waited_min:.0f} min"
                            diag["health"] = 20

                        if diag["test_result"] != "PENDING":
                            ct_id = entry.get("ct_id", "CT-????")
                            diag["ct_id"] = ct_id
                            push_telemetry(entry.get("miner_id",""), diag)
                            entry["test_result"] = diag["test_result"]
                            entry["serial"] = diag.get("serial", entry.get("serial",""))
                            if not entry.get("label_printed"):
                                log.info(f"  {ct_id} warmup complete ({diag['test_result']}) — printing label...")
                                trigger_print(diag, ct_id)
                                entry["label_printed"] = True
                    save_state(state)

        except KeyboardInterrupt:
            log.info("Shutting down.")
            break
        except Exception as e:
            log.error(f"Scan error: {e}", exc_info=True)

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
