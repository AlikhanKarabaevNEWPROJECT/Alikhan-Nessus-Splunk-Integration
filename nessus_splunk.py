#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author: Алихан Карабаев
Description: Fetches scan data from Nessus API and sends to Splunk via HEC.
"""

import os
import json
import time
import requests
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ===============================
# CONFIGURATION
# ===============================

CONFIG_PATH = "servers.json"
SENT_DB = "sent.json"  # файл для хранения уже отправленных уязвимостей

# Load configuration file safely
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    raise SystemExit(f"Failed to load {CONFIG_PATH}: {e}")

try:
    SPLUNK_URL = f"{config['Splunk']['Protocol']}://{config['Splunk']['Address']}:{config['Splunk']['Port']}/services/collector/event"
    NESSUS_URL = f"https://{config['Nessus']['Address']}:{config['Nessus']['Port']}/scans"
except KeyError as e:
    raise SystemExit(f"Missing required key in servers.json: {e}")

# Environment variables
HEC_TOKEN = os.getenv("HEC_TOKEN")
NESSUS_ACCESS_KEY = os.getenv("N_ACCESS_KEY")
NESSUS_SECRET_KEY = os.getenv("N_SECRET_KEY")

if not all([HEC_TOKEN, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY]):
    raise SystemExit("Missing environment variables: HEC_TOKEN, N_ACCESS_KEY, or N_SECRET_KEY")

HEADERS_NESSUS = {
    "X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}"
}
HEADERS_SPLUNK = {
    "Authorization": f"Splunk {HEC_TOKEN}"
}

# ===============================
# HTTP SESSION WITH RETRIES
# ===============================
session = requests.Session()
retries = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))
requests.packages.urllib3.disable_warnings()

# ===============================
# UTILITY FUNCTIONS
# ===============================

def log(msg, level="INFO"):
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "ERR": "\033[91m", "WARN": "\033[93m"}
    reset = "\033[0m"
    print(f"{colors.get(level, '')}[{level}] {msg}{reset}")

def fetch_json(url, headers=None, params=None):
    """Generic JSON fetcher with error handling"""
    try:
        resp = session.get(url, headers=headers, params=params, timeout=15, verify=False)
        if resp.status_code == 200:
            return resp.json()
        log(f"Bad response {resp.status_code} from {url}", "WARN")
    except Exception as e:
        log(f"Request error: {e}", "ERR")
    return None

def send_to_splunk(event):
    """Send event to Splunk HEC"""
    payload = {
        "index": "main",
        "sourcetype": "_json",
        "host": "nessus",
        "event": event
    }
    try:
        r = session.post(SPLUNK_URL, headers=HEADERS_SPLUNK, json=payload, timeout=10, verify=False)
        if r.status_code == 200:
            log(f"Sent vulnerability {event.get('plugin_id', 'unknown')} to Splunk", "OK")
        else:
            log(f"Failed to send to Splunk (code {r.status_code})", "WARN")
    except Exception as e:
        log(f"Error sending to Splunk: {e}", "ERR")

def load_sent_db():
    """Load sent vulnerabilities DB"""
    try:
        with open(SENT_DB, "r") as f:
            items = json.load(f)
            return set(tuple(x) for x in items)
    except FileNotFoundError:
        return set()
    except Exception as e:
        log(f"Failed to load sent DB: {e}", "WARN")
        return set()

def save_sent_db(sent_set):
    """Save sent vulnerabilities DB"""
    try:
        with open(SENT_DB, "w") as f:
            json.dump([list(x) for x in sent_set], f, indent=2)
    except Exception as e:
        log(f"Failed to save sent DB: {e}", "WARN")

# Load sent DB
SENT = load_sent_db()

# ===============================
# MAIN LOGIC
# ===============================

def process_scan(scan_id):
    """Process all hosts and vulnerabilities from a single Nessus scan with deduplication"""
    scan_data = fetch_json(f"{NESSUS_URL}/{scan_id}", headers=HEADERS_NESSUS)
    if not scan_data or "hosts" not in scan_data:
        log(f"Skipping scan {scan_id}: no data", "WARN")
        return

    info = scan_data.get("info", {})
    scanner_start = datetime.fromtimestamp(info.get("scanner_start", time.time())).strftime("%Y-%m-%d %H:%M:%S")
    scanner_end = datetime.fromtimestamp(info.get("scanner_end", time.time())).strftime("%Y-%m-%d %H:%M:%S")
    status = info.get("status", "unknown")

    local_sent = set()  # дубликаты внутри одного запуска
    for host in scan_data["hosts"]:
        host_id = host.get("host_id")
        hostname = host.get("hostname", "unknown")
        if host_id is None:
            continue
        host_detail = fetch_json(f"{NESSUS_URL}/{scan_id}/hosts/{host_id}", headers=HEADERS_NESSUS)
        if not host_detail or "vulnerabilities" not in host_detail:
            continue

        for vuln in host_detail["vulnerabilities"]:
            plugin_id = vuln.get("plugin_id")
            if plugin_id is None:
                continue

            key = (str(scan_id), str(host_id), str(plugin_id))
            if key in SENT or key in local_sent:
                continue  # уже отправлено

            plugin_detail = fetch_json(f"{NESSUS_URL}/{scan_id}/hosts/{host_id}/plugins/{plugin_id}", headers=HEADERS_NESSUS)
            if plugin_detail:
                vuln.update(plugin_detail)
            vuln.update({
                "hostname": hostname,
                "scanner_start": scanner_start,
                "scanner_end": scanner_end,
                "scanner_status": status,
                "scan_id": scan_id,
                "host_id": host_id
            })
            send_to_splunk(vuln)

            local_sent.add(key)
            SENT.add(key)

    save_sent_db(SENT)

def main():
    log("Fetching Nessus scan list...")
    data = fetch_json(NESSUS_URL, headers=HEADERS_NESSUS)
    if not data or "scans" not in data:
        log("No scans found or failed to connect to Nessus.", "ERR")
        return

    for scan in data["scans"]:
        scan_id = scan.get("id")
        scan_name = scan.get("name")
        log(f" Processing scan '{scan_name}' (ID {scan_id})")
        process_scan(scan_id)

if __name__ == "__main__":
    main()
