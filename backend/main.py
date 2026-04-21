"""
NetGuard IDS - Backend API
FastAPI + WebSocket real-time intrusion detection system
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import random
import time
from datetime import datetime
from typing import List, Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NetGuard IDS API", version="2.4.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# THREAT SIGNATURES DATABASE
# ─────────────────────────────────────────────
SIGNATURES = [
    {"id": "SID:1001", "name": "Port Scan Detected",      "severity": "MEDIUM",   "proto": "TCP"},
    {"id": "SID:1002", "name": "SYN Flood Attack",         "severity": "CRITICAL", "proto": "TCP"},
    {"id": "SID:1003", "name": "SQL Injection Attempt",    "severity": "HIGH",     "proto": "HTTP"},
    {"id": "SID:1004", "name": "DNS Amplification",        "severity": "HIGH",     "proto": "DNS"},
    {"id": "SID:1005", "name": "ICMP Ping Sweep",          "severity": "LOW",      "proto": "ICMP"},
    {"id": "SID:1006", "name": "Brute Force SSH",          "severity": "HIGH",     "proto": "TCP"},
    {"id": "SID:1007", "name": "XSS Payload Detected",    "severity": "MEDIUM",   "proto": "HTTP"},
    {"id": "SID:1008", "name": "ARP Spoofing",             "severity": "CRITICAL", "proto": "ARP"},
    {"id": "SID:1009", "name": "Malware C2 Beacon",        "severity": "CRITICAL", "proto": "TCP"},
    {"id": "SID:1010", "name": "Directory Traversal",      "severity": "HIGH",     "proto": "HTTP"},
    {"id": "SID:1011", "name": "UDP Flood",                "severity": "HIGH",     "proto": "UDP"},
    {"id": "SID:1012", "name": "Nmap OS Fingerprint",      "severity": "MEDIUM",   "proto": "TCP"},
    {"id": "SID:1013", "name": "Normal Traffic",           "severity": "INFO",     "proto": "TCP"},
    {"id": "SID:1014", "name": "Normal Traffic",           "severity": "INFO",     "proto": "UDP"},
    {"id": "SID:1015", "name": "Normal DNS Query",         "severity": "INFO",     "proto": "DNS"},
]

PAYLOADS = {
    "SQL Injection Attempt":  "GET /login?id=1' OR '1'='1&pass=admin HTTP/1.1",
    "XSS Payload Detected":   "POST /comment body=<script>alert(document.cookie)</script>",
    "Brute Force SSH":        "SSH-2.0-libssh2_1.9.0 [FAILED AUTH attempt #47]",
    "SYN Flood Attack":       "TCP [SYN] x10000 packets from single source in 1.2s",
    "Malware C2 Beacon":      "POST /gate.php beacon_id=0xAF3D interval=30s exfil=true",
    "DNS Amplification":      "DNS ANY query -> 50x amplification ratio",
    "Directory Traversal":    "GET /../../../../etc/passwd HTTP/1.1",
    "Port Scan Detected":     "TCP SYN sweep across 1024 ports detected in 2.3s",
    "ARP Spoofing":           "ARP reply: 192.168.1.1 is-at DE:AD:BE:EF:CA:FE (FAKE)",
    "Nmap OS Fingerprint":    "TCP options: MSS=1460 WS=512 TS NOP SACK probe sequence",
    "ICMP Ping Sweep":        "ICMP echo-request flood to /24 subnet (254 hosts)",
    "UDP Flood":              "UDP 1400B x5000/s to port 53 from spoofed IPs",
}

GEO_DATA = {
    "185.220.101.47": {"country": "Russia",      "flag": "RU", "city": "Moscow"},
    "91.108.4.0":     {"country": "China",       "flag": "CN", "city": "Beijing"},
    "198.199.88.31":  {"country": "USA",         "flag": "US", "city": "New York"},
    "45.142.212.100": {"country": "Netherlands", "flag": "NL", "city": "Amsterdam"},
    "103.21.244.0":   {"country": "India",       "flag": "IN", "city": "Mumbai"},
    "194.165.16.29":  {"country": "Germany",     "flag": "DE", "city": "Frankfurt"},
}

ATTACK_IPS  = list(GEO_DATA.keys())
LEGIT_IPS   = ["192.168.1.10","192.168.1.22","10.0.0.5","172.16.0.8","192.168.1.100"]
DEST_IPS    = ["192.168.1.1","10.0.0.1","192.168.1.50"]
COMMON_PORTS= [80,443,22,25,53,3306,8080,21,3389,8443]

PORT_MAP = {
    22:   {"name":"SSH",     "status":"open"},
    80:   {"name":"HTTP",    "status":"open"},
    443:  {"name":"HTTPS",   "status":"open"},
    21:   {"name":"FTP",     "status":"closed"},
    25:   {"name":"SMTP",    "status":"filtered"},
    3306: {"name":"MySQL",   "status":"closed"},
    3389: {"name":"RDP",     "status":"filtered"},
    8080: {"name":"HTTP-Alt","status":"open"},
    53:   {"name":"DNS",     "status":"open"},
    139:  {"name":"NetBIOS", "status":"filtered"},
    445:  {"name":"SMB",     "status":"closed"},
    1433: {"name":"MSSQL",   "status":"closed"},
    8443: {"name":"HTTPS-Alt","status":"open"},
    27017:{"name":"MongoDB", "status":"filtered"},
}

# ─────────────────────────────────────────────
# IN-MEMORY STATE
# ─────────────────────────────────────────────
state: Dict[str, Any] = {
    "packet_count":   0,
    "threat_count":   0,
    "blocked_ips":    set(),
    "geo_hits":       {},
    "alerts":         [],
    "packets":        [],
}

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"Client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)
        logger.info(f"Client disconnected. Total: {len(self.active)}")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ─────────────────────────────────────────────
# PACKET GENERATION ENGINE
# ─────────────────────────────────────────────
def generate_packet() -> dict:
    is_attack = random.random() < 0.25
    src_ip    = random.choice(ATTACK_IPS) if is_attack else random.choice(LEGIT_IPS)
    dst_ip    = random.choice(DEST_IPS)

    attack_sigs = [s for s in SIGNATURES if s["severity"] != "INFO"]
    benign_sigs = [s for s in SIGNATURES if s["severity"] == "INFO"]
    sig = random.choice(attack_sigs if is_attack else benign_sigs)

    state["packet_count"] += 1
    pkt = {
        "id":       state["packet_count"],
        "time":     datetime.now().strftime("%H:%M:%S.%f")[:12],
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "proto":    sig["proto"],
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(COMMON_PORTS),
        "size":     random.randint(40, 1480),
        "ttl":      random.choice([32, 64, 128, 255]),
        "flags":    random.choice(["SYN","ACK","SYN-ACK","FIN","RST"]) if sig["proto"] == "TCP" else "-",
        "severity": sig["severity"],
        "sig_name": sig["name"],
        "sig_id":   sig["id"],
        "payload":  PAYLOADS.get(sig["name"], "(benign traffic)"),
        "is_attack": is_attack,
    }

    if is_attack:
        state["threat_count"] += 1
        alert = {**pkt, "timestamp": time.time()}
        state["alerts"].append(alert)
        if len(state["alerts"]) > 200:
            state["alerts"] = state["alerts"][-200:]

        if src_ip in GEO_DATA:
            geo = GEO_DATA[src_ip]
            if src_ip not in state["geo_hits"]:
                state["geo_hits"][src_ip] = {**geo, "count": 0}
            state["geo_hits"][src_ip]["count"] += 1

    state["packets"].append(pkt)
    if len(state["packets"]) > 1000:
        state["packets"] = state["packets"][-1000:]

    return pkt

# ─────────────────────────────────────────────
# REST ENDPOINTS
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "NetGuard IDS running", "version": "2.4.1"}

@app.get("/api/stats")
def get_stats():
    return {
        "packet_count":  state["packet_count"],
        "threat_count":  state["threat_count"],
        "blocked_count": len(state["blocked_ips"]),
        "blocked_ips":   list(state["blocked_ips"]),
        "geo_hits":      state["geo_hits"],
        "signatures":    4847,
        "detection_rate": 99.2,
    }

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return {"alerts": state["alerts"][-limit:]}

@app.get("/api/packets")
def get_packets(limit: int = 100):
    return {"packets": state["packets"][-limit:]}

@app.get("/api/portscan")
def port_scan():
    return {
        "target":  "192.168.1.1",
        "scanned": len(PORT_MAP),
        "ports":   [{"port": p, **v} for p, v in PORT_MAP.items()]
    }

@app.post("/api/block/{ip}")
def block_ip(ip: str):
    state["blocked_ips"].add(ip)
    return {"blocked": ip, "total_blocked": len(state["blocked_ips"])}

@app.post("/api/simulate-attack")
async def simulate_attack():
    attacks = [
        {"sig": "SID:1002", "name": "SYN Flood Attack",      "sev": "CRITICAL"},
        {"sig": "SID:1003", "name": "SQL Injection Attempt",  "sev": "HIGH"},
        {"sig": "SID:1008", "name": "ARP Spoofing",           "sev": "CRITICAL"},
        {"sig": "SID:1009", "name": "Malware C2 Beacon",      "sev": "CRITICAL"},
    ]
    atk    = random.choice(attacks)
    src_ip = random.choice(ATTACK_IPS)
    pkts   = []

    for _ in range(5):
        state["packet_count"] += 1
        state["threat_count"] += 1
        pkt = {
            "id":       state["packet_count"],
            "time":     datetime.now().strftime("%H:%M:%S.%f")[:12],
            "src_ip":   src_ip,
            "dst_ip":   random.choice(DEST_IPS),
            "proto":    "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice(COMMON_PORTS),
            "size":     random.randint(40, 1480),
            "ttl":      64,
            "flags":    "SYN",
            "severity": atk["sev"],
            "sig_name": atk["name"],
            "sig_id":   atk["sig"],
            "payload":  PAYLOADS.get(atk["name"], "attack payload"),
            "is_attack": True,
        }
        state["alerts"].append({**pkt, "timestamp": time.time()})
        state["packets"].append(pkt)
        state["blocked_ips"].add(src_ip)
        pkts.append(pkt)

        if src_ip in GEO_DATA:
            geo = GEO_DATA[src_ip]
            if src_ip not in state["geo_hits"]:
                state["geo_hits"][src_ip] = {**geo, "count": 0}
            state["geo_hits"][src_ip]["count"] += 5

    await manager.broadcast({"type": "attack_burst", "packets": pkts})
    return {"injected": len(pkts), "attack": atk["name"], "src": src_ip}

@app.delete("/api/alerts")
def clear_alerts():
    state["alerts"].clear()
    state["threat_count"] = 0
    state["geo_hits"].clear()
    state["blocked_ips"].clear()
    return {"cleared": True}

# ─────────────────────────────────────────────
# WEBSOCKET - LIVE STREAM
# ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Generate 1-3 packets per tick
            batch = [generate_packet() for _ in range(random.randint(1, 3))]
            await manager.broadcast({
                "type":    "packet_batch",
                "packets": batch,
                "stats": {
                    "packet_count":  state["packet_count"],
                    "threat_count":  state["threat_count"],
                    "blocked_count": len(state["blocked_ips"]),
                    "geo_hits":      state["geo_hits"],
                }
            })
            await asyncio.sleep(0.6)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WS error: {e}")
        manager.disconnect(websocket)
