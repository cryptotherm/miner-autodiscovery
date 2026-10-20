#!/usr/bin/env python3
"""
Cryptotherm Miner Auto-Discovery & Diagnostic System
Watches for new miners on the network, runs diagnostics, prints CT labels.

Deploy on: CTHome, Alienware, Mac (any machine with network access)
Requires: python3, brother_ql (on print host), requests
"""

import json, time, subprocess, socket, logging, os, sys, hashlib, configparser
import requests
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────────────────────────
# Values load from autodiscovery.conf (same directory or /opt/ct-autodiscovery)
# with CT_* environment variables taking precedence. The platform token was
# previously hardcoded here — in a PUBLIC repository — and must be rotated;
# it now only ever comes from the conf file or the environment.

def _load_config() -> dict:
    cfg = configparser.ConfigParser()
    here = os.path.dirname(os.path.abspath(__file__))
    cfg.read([
        os.path.join(here, "autodiscovery.conf"),
        "/opt/ct-autodiscovery/autodiscovery.conf",
        os.path.expanduser("~/.ct-autodiscovery/autodiscovery.conf"),
    ])
    d = cfg["discovery"] if cfg.has_section("discovery") else {}
    g = cfg["logging"] if cfg.has_section("logging") else {}

    def pick(env, key, default, section=d):
        return os.environ.get(env) or (section.get(key) if section else None) or default

    return {
        "platform_api":   pick("CT_PLATFORM_API",   "platform_api",   "http://127.0.0.1:8080"),
        "platform_token": pick("CT_PLATFORM_TOKEN", "platform_token", ""),
        "printer_ip":     pick("CT_PRINTER_IP",     "printer_ip",     "10.0.0.119"),
        "subnet":         pick("CT_SUBNET",         "subnet",         "10.0.0"),
        "scan_interval":  int(pick("CT_SCAN_INTERVAL", "scan_interval", "30")),
        "log_file":       pick("CT_LOG_FILE", "log_file", "/var/log/ct_autodiscovery.log", g),
    }

_CFG = _load_config()

PLATFORM_API   = _CFG["platform_api"].rstrip("/")
PLATFORM_TOKEN = _CFG["platform_token"]
PRINTER_IP     = _CFG["printer_ip"]     # QL-810W WiFi
SUBNET         = _CFG["subnet"]
SCAN_INTERVAL  = _CFG["scan_interval"]  # seconds between sweeps
CGMINER_PORT   = 4028
CGMINER_TIMEOUT = 3
LOG_FILE       = _CFG["log_file"]


def _state_file() -> str:
    """Persistent state location — /tmp lost every reboot, which made the
    tool re-register and re-print labels for the entire fleet after a restart."""
    for candidate in ("/var/lib/ct-autodiscovery", os.path.expanduser("~/.ct-autodiscovery")):
        try:
            os.makedirs(candidate, exist_ok=True)
            if os.access(candidate, os.W_OK):
                return os.path.join(candidate, "discovered_miners.json")
        except OSError:
            continue
    return "/tmp/ct_discovered_miners.json"

STATE_FILE = _state_file()

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
MINER_MODELS = {
    "Antminer S19k Pro": {"algo": "SHA-256", "ideal_ths": 120, "fans": 4, "chains": 3, "asics_per_chain": 77},
    "Antminer S19 XP":   {"algo": "SHA-256", "ideal_ths": 141, "fans": 4, "chains": 3, "asics_per_chain": 76},
    "Antminer L7":       {"algo": "Scrypt",  "ideal_ghs": 9.16,"fans": 4, "chains": 1, "asics_per_chain": 0},
    "MicroBT WhatsMiner": {"algo": "SHA-256","ideal_ths": 103, "fans": 2, "chains": 3, "asics_per_chain": 156},
}

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

    existing = next((m for m in miners if m.get("ip_address") == diag["ip"]), None)
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
    }
    try:
        requests.post(f"{PLATFORM_API}/miners/{miner_id}/telemetry",
                     headers=HEADERS, json=payload, timeout=5)
    except:
        pass

# ── PRINT TRIGGER ─────────────────────────────────────────────────────────────
def trigger_print(diag: dict, ct_id: str):
    """Trigger label print — either locally or via SSH to CTHome."""
    import tempfile

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

qr_mod = qrcode.QRCode(version=2,box_size=3,border=1)
qr_mod.add_data("CT:{ct_id}|IP:{diag['ip']}|MAC:{diag['mac']}|MODEL:{diag['model']}|"+NOW)
qr_mod.make(fit=True)
qr_img = qr_mod.make_image(fill_color="black",back_color="white").convert("RGB").resize((88,88))

W,H = 696, 520
img = Image.new("RGB",(W,H),"white")
d = ImageDraw.Draw(img)
d.rectangle([0,0,W-1,H-1],outline="black",width=5)

# Header
d.rectangle([0,0,W,88],fill="black")
img.paste(qr_img,(6,2))
d.text((102,6),"CRYPTOTHERM TESTING",font=fBIG,fill="white")
d.text((102,42),"Auto-Discovered Miner",font=fMED,fill="#cccccc")
d.text((102,68),"{ct_id}  |  "+NOW,font=fTINY,fill="#aaaaaa")

# Result banner
result="{diag['test_result']}"
d.rectangle([0,90,W,144],fill="black" if result=="PASS" else "#444444")
d.text((14,98),"TEST: "+result,font=fBIG,fill="white")

y=150
rows=[
    ("MODEL",  "{diag['model']}"),
    ("IP",     "{diag['ip']}"),
    ("MAC",    "{diag['mac']}"),
    ("SERIAL", "{diag.get('serial','?')}"),
    ("POOL",   "{diag.get('worker','?')}"),
    ("HASH",   "%.1f GH/s" % float({diag.get('hashrate_5s',0)})),
    ("SHARES", "Acc:{diag.get('accepted',0)}"),
    ("HEALTH", "{diag.get('health',0)}/100"),
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

    # Write temp script and run via SSH on MacBook (has brother_ql)
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script)
            tmp = f.name

        # Try local first, then SSH to MacBook
        if subprocess.run(["python3", "-c", "import brother_ql"], capture_output=True).returncode == 0:
            subprocess.run(["python3", tmp], timeout=30)
        else:
            # SSH to MacBook via tunnel
            subprocess.run([
                "ssh", "-i", "/home/work/.ssh/id_ed25519",
                "-o", "StrictHostKeyChecking=no", "-p", "2220",
                "austinbank@localhost",
                f"export PATH=$HOME/Library/Python/3.9/bin:$PATH; python3 < {tmp}"
            ], input=open(tmp).read().encode(), timeout=30,
               stdin=subprocess.PIPE)
        os.unlink(tmp)
        log.info(f"  Label printed for {ct_id}")
    except Exception as e:
        log.error(f"  Print failed: {e}")

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
def finalize_miner(state: dict, fp: str, ip: str, mac: str, diag: dict):
    """Register the miner with the platform, record state, print its label."""
    miner_id, ct_id = get_or_create_miner(diag)
    push_telemetry(miner_id, diag)

    diag["ct_id"] = ct_id
    diag["miner_id"] = miner_id
    first_seen = state.get(fp, {}).get("first_seen", datetime.now().isoformat())
    state[fp] = {
        "ct_id": ct_id, "ip": ip, "mac": mac,
        "test_result": diag["test_result"],
        "model": diag.get("model", "?"),
        "first_seen": first_seen,
        "last_seen": datetime.now().isoformat(),
    }
    save_state(state)

    log.info(f"  Printing CT label for {ct_id}...")
    trigger_print(diag, ct_id)


def main():
    log.info("=" * 60)
    log.info("Cryptotherm Auto-Discovery starting")
    log.info(f"Subnet: {SUBNET}.0/24  |  Interval: {SCAN_INTERVAL}s")
    log.info(f"State file: {STATE_FILE}")
    log.info("=" * 60)
    log.warning(
        "NOTE: this standalone tool is DEPRECATED for the test bench — the "
        "miner-testbench server's autoscan owns bench discovery (racks on "
        "192.168.2-6.x). Use this only for the separate platform/CTOps fleet."
    )
    if not PLATFORM_TOKEN:
        log.error(
            "No platform token configured. Set platform_token in "
            "autodiscovery.conf or CT_PLATFORM_TOKEN in the environment. "
            "Exiting rather than registering miners unauthenticated."
        )
        sys.exit(1)

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

                if fp not in state:
                    # New miner
                    log.info(f"NEW MINER DETECTED: {ip} (MAC: {mac})")
                    diag = run_diagnostics(ip)

                    if diag["test_result"] == "PENDING":
                        # Don't block the whole scan loop while it warms up —
                        # record it and re-diagnose on the next sweeps.
                        log.info("  Miner warming up — will re-check on next sweep")
                        state[fp] = {
                            "ct_id": None, "ip": ip, "mac": mac,
                            "test_result": "PENDING",
                            "model": diag.get("model", "?"),
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                        }
                        save_state(state)
                    else:
                        finalize_miner(state, fp, ip, mac, diag)

                elif state[fp].get("test_result") == "PENDING":
                    # Warming up from an earlier sweep — re-diagnose
                    diag = run_diagnostics(ip)
                    first_seen = state[fp].get("first_seen", datetime.now().isoformat())
                    try:
                        waited_min = (datetime.now() - datetime.fromisoformat(first_seen)).total_seconds() / 60
                    except ValueError:
                        waited_min = 999
                    if diag["test_result"] != "PENDING" or waited_min >= 20:
                        finalize_miner(state, fp, ip, mac, diag)
                    else:
                        state[fp]["last_seen"] = datetime.now().isoformat()
                        save_state(state)

                else:
                    # Known miner — update last seen
                    state[fp]["last_seen"] = datetime.now().isoformat()
                    save_state(state)

        except KeyboardInterrupt:
            log.info("Shutting down.")
            break
        except Exception as e:
            log.error(f"Scan error: {e}", exc_info=True)

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
