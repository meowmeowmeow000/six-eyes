#!/usr/bin/env python3
"""
Six Eyes v10 // Scapy Topological Packet Sculptor & Live IPC Injector
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
from scapy.all import IP, TCP, conf, sniff

conf.verb = 0

def resolve_ipc_sock_path() -> str:
    name = "six_eyes_v10.sock"
    try:
        fd, path = tempfile.mkstemp(prefix=".se10-probe-", dir="/run")
        os.close(fd)
        os.unlink(path)
        return f"/run/{name}"
    except OSError:
        return f"/tmp/{name}"

IPC_SOCK_PATH = resolve_ipc_sock_path()
DEFAULT_CANDIDATE_IPS = [
    "104.18.2.161",
    "104.18.3.161",
    "104.21.16.1",
    "172.67.128.1",
    "162.159.135.42",
    "188.114.97.3",
]

def split_tls_client_hello(record_bytes: bytes, sni_bytes: bytes) -> list[bytes]:
    if len(record_bytes) < 48 or record_bytes[0] != 0x16:
        return [record_bytes]
    ver_major, ver_minor = record_bytes[1], record_bytes[2]
    rec_len = struct.unpack("!H", record_bytes[3:5])[0]
    if 5 + rec_len != len(record_bytes):
        return [record_bytes]
    payload = record_bytes[5:]
    cut1 = 37
    cut2 = len(payload) // 2
    idx = payload.find(sni_bytes)
    if idx > cut1:
        cut2 = idx + (len(sni_bytes) // 2)
    if cut2 <= cut1 or cut2 >= len(payload):
        cut2 = (cut1 + len(payload)) // 2
    chunks = [payload[:cut1], payload[cut1:cut2], payload[cut2:]]
    records = []
    for c in chunks:
        if not c:
            continue
        hdr = struct.pack("!BBBH", 0x16, ver_major, ver_minor, len(c))
        records.append(hdr + c)
    return records

class DPISculptor:
    def __init__(self, target_ip: str, worker_sni: str):
        self.target_ip = target_ip
        self.worker_sni = worker_sni
        self.clean_sni = "www.cloudflare.com"
        self.packets = []
        self.pcap_lock = threading.Lock()

    def _sniffer_thread(self, duration: float = 3.5):
        pkts = sniff(filter=f"host {self.target_ip} and tcp", timeout=duration)
        with self.pcap_lock:
            self.packets.extend(pkts)

    def _standard_tls_probe(self, sni: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(2.5)
        try:
            s.connect((self.target_ip, 443))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=sni)
            ss.do_handshake()
            ss.close()
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _verify_fragmented_ws_101(self) -> tuple[bool, int, int, int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(4.0)
        t0 = time.monotonic()
        try:
            s.connect((self.target_ip, 443))
            tcp_ms = int((time.monotonic() - t0) * 1000)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])
            in_bio = ssl.MemoryBIO()
            out_bio = ssl.MemoryBIO()
            ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_hostname=self.worker_sni)
            t_tls = time.monotonic()
            first_flight = True
            sni_bytes = self.worker_sni.encode("utf-8")
            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    outgoing = out_bio.read()
                    if outgoing:
                        if first_flight:
                            first_flight = False
                            records = split_tls_client_hello(outgoing, sni_bytes)
                            for i, rec in enumerate(records):
                                s.sendall(rec)
                                if i < len(records) - 1:
                                    time.sleep(0.002)
                        else:
                            s.sendall(outgoing)
                    incoming = s.recv(16384)
                    if not incoming:
                        return False, tcp_ms, 0, 0
                    in_bio.write(incoming)
            rem = out_bio.read()
            if rem:
                s.sendall(rem)
            tls_ms = int((time.monotonic() - t_tls) * 1000)
            t_ws = time.monotonic()
            ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
            req = (
                f"GET /tunnel HTTP/1.1\r\n"
                f"Host: {self.worker_sni}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://{self.worker_sni}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n"
            ).encode("utf-8")
            ssl_obj.write(req)
            s.sendall(out_bio.read())
            while True:
                try:
                    resp = ssl_obj.read(4096)
                    break
                except ssl.SSLWantReadError:
                    enc_in = s.recv(16384)
                    if not enc_in:
                        return False, tcp_ms, tls_ms, 0
                    in_bio.write(enc_in)
            ws_ms = int((time.monotonic() - t_ws) * 1000)
            status_line = resp.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
            ws_ok = "101" in status_line
            return ws_ok, tcp_ms, tls_ms, ws_ms
        except Exception:
            return False, 0, 0, 0
        finally:
            try:
                s.close()
            except Exception:
                pass

    def map_route(self):
        print(f"\n[+] Sculpting & Echolocating Route: {self.target_ip} -> {self.worker_sni}")
        self.packets = []
        sniffer = threading.Thread(target=self._sniffer_thread, args=(3.0,))
        sniffer.start()
        time.sleep(0.15)
        self._standard_tls_probe(self.clean_sni)
        sniffer.join()
        server_ttl = None
        for pkt in self.packets:
            if IP in pkt and TCP in pkt and pkt[IP].src == self.target_ip:
                if pkt[TCP].flags == "SA" or int(pkt[TCP].flags) == 0x12:
                    server_ttl = int(pkt[IP].ttl)
                    break
        if not server_ttl:
            print("    └─ [-] Unroutable IP or TCP SYN blocked.")
            return None
        print(f"    ├─ Phase 1 (Baseline): True Edge SYN-ACK TTL = {server_ttl}")
        self.packets = []
        sniffer = threading.Thread(target=self._sniffer_thread, args=(3.0,))
        sniffer.start()
        time.sleep(0.15)
        self._standard_tls_probe(self.worker_sni)
        sniffer.join()
        forged_ttls = []
        for pkt in self.packets:
            if IP in pkt and TCP in pkt and pkt[IP].src == self.target_ip:
                flags_str = str(pkt[TCP].flags)
                if "R" in flags_str or "F" in flags_str:
                    if abs(int(pkt[IP].ttl) - server_ttl) > 4:
                        forged_ttls.append(int(pkt[IP].ttl))
        dpi_active = len(forged_ttls) > 0
        hops_to_dpi = 0
        if dpi_active:
            dpi_ttl = forged_ttls[0]
            start_ttl = 64 if dpi_ttl < 64 else (128 if dpi_ttl < 128 else 255)
            hops_to_dpi = start_ttl - dpi_ttl
            print(f"    ├─ Phase 2 (DPI Provocation): Forged RST/FIN TTL={dpi_ttl} (DPI Middlebox @ {hops_to_dpi} hops)")
        else:
            print("    ├─ Phase 2 (DPI Provocation): No forged TCP resets observed.")
        ws_ok, tcp_ms, tls_ms, ws_ms = self._verify_fragmented_ws_101()
        stealth_mode = "tls_micro_frag" if dpi_active else "tls_frag"
        total_ms = tcp_ms + tls_ms + ws_ms
        score = max(10, min(100, 100 - (total_ms // 10) + (15 if ws_ok else -25)))
        print(
            f"    └─ Phase 3 (Surgical TLS-Split WS): 101_Verified={ws_ok} | "
            f"TCP={tcp_ms}ms TLS={tls_ms}ms WS={ws_ms}ms | Mode={stealth_mode} | Score={score}"
        )
        return {
            "target_ip": self.target_ip,
            "clean_sni": self.worker_sni,
            "stealth_mode": stealth_mode,
            "expected_ttl": server_ttl,
            "dpi_distance_hops": hops_to_dpi,
            "tcp_ms": tcp_ms,
            "tls_handshake_ms": tls_ms,
            "ws_upgrade_ms": ws_ms,
            "ws_verified": ws_ok,
            "confidence_score": score,
            "dpi_active": dpi_active,
        }

def inject_live_ipc(primary_route: dict, ttl_tolerance: int, lockdown: bool):
    if not os.path.exists(IPC_SOCK_PATH):
        print(f"[i] IPC socket {IPC_SOCK_PATH} not present (Go engine offline); saved combat.profile for boot.")
        return
    payload = {
        "action": "inject_route",
        "route": primary_route,
        "expected_ttl": primary_route["expected_ttl"],
        "ttl_tolerance": ttl_tolerance,
        "lockdown": lockdown,
    }
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(IPC_SOCK_PATH)
        sock.sendall(json.dumps(payload).encode("utf-8"))
        resp_raw = sock.recv(4096)
        sock.close()
        resp = json.loads(resp_raw.decode("utf-8"))
        print(f"[⚡] Live IPC Injection -> {resp.get('status')}: {resp.get('message')}")
    except Exception as exc:
        print(f"[-] Live IPC injection failed: {exc}")

def main():
    if os.geteuid() != 0:
        print("[-] Error: Scapy packet sniffing requires root privileges. Run with sudo.")
        sys.exit(1)
    if len(sys.argv) < 2:
        print("Usage: sudo python3 scanner/scapy_cartographer.py <WORKER_HOST> [IP1 IP2 ...]")
        sys.exit(1)
    worker_sni = sys.argv[1]
    ips = sys.argv[2:] if len(sys.argv) > 2 else DEFAULT_CANDIDATE_IPS
    print("========================================================================")
    print(" 👁️  SIX EYES CARTOGRAPHER v10 // PACKET SCULPTOR & IPC INJECTOR")
    print("========================================================================")
    routes = []
    for ip in ips:
        sculptor = DPISculptor(ip, worker_sni)
        res = sculptor.map_route()
        if res:
            routes.append(res)
    if not routes:
        print("[-] No routable Cloudflare edges found.")
        sys.exit(1)
    routes.sort(
        key=lambda r: (
            r["ws_verified"],
            r["confidence_score"],
            -(r["tcp_ms"] + r["tls_handshake_ms"] + r["ws_upgrade_ms"]),
        ),
        reverse=True,
    )
    primary = routes[0]
    failovers = routes[1:6]
    any_dpi = any(r.get("dpi_active") for r in routes)
    tol = 2 if any_dpi else 4
    combat_profile = {
        "version": "10.0-six-eyes",
        "worker_host": worker_sni,
        "expected_ttl": primary["expected_ttl"],
        "operational_doctrine": {
            "telemetry_polling_ms": 3000,
            "max_acceptable_latency_ms": 800,
            "fallback_threshold_streak": 3,
        },
        "modules": {
            "xdp_shield": {
                "mode": "lockdown" if any_dpi else "adaptive",
                "expected_ttl": primary["expected_ttl"],
                "ttl_tolerance": tol,
                "rst_burst_threshold": 5,
            },
            "stealth_factory": {
                "primary_mode": primary["stealth_mode"],
                "fallback_mode": "tls_micro_frag",
                "fragmentation_delay_ms": 3 if any_dpi else 2,
                "jitter_ms": 3,
                "allow_insecure_certs": False,
            },
            "warm_pool": {
                "target_capacity": 3,
                "keepalive_interval_sec": 10,
            },
        },
        "contingency_matrix": [
            {"condition": "http_403_forbidden", "action": "escalate_stealth_mode"},
            {"condition": "dpi_tls_reset", "action": "escalate_stealth_mode"},
            {"condition": "dial_timeout", "action": "flush_pool_and_rotate_ip"},
            {"condition": "dial_unreachable", "action": "flush_pool_and_rotate_ip"},
            {"condition": "tcp_rst_storm", "action": "engage_xdp_lockdown"},
        ],
        "primary_route": primary,
        "failover_routes": failovers,
    }
    with open("combat.profile", "w", encoding="utf-8") as f:
        json.dump(combat_profile, f, indent=2)
    print(f"\n[✓] Strategic combat.profile compiled (Primary: {primary['target_ip']} | TTL={primary['expected_ttl']} ±{tol}).")
    inject_live_ipc(primary, tol, any_dpi)

if __name__ == "__main__":
    main()
