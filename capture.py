"""
AI-Based IDS — Gercek Trafik Yakalama
Calistirmak icin: python capture.py  (Administrator olarak)
Gereksinim: pip install scapy
"""

import os
import json
import time
import queue
import threading
import requests
from collections import deque, defaultdict
from datetime import datetime, timezone
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf as scapy_conf

API_URL      = "http://127.0.0.1:5000"
RESULTS_FILE = "live_results.json"
WINDOW_SECS  = 5
THRESHOLD    = 3    # flood esigi
SCAN_THRESH  = 4    # port tarama esigi

EXCLUDED_PORTS = {53, 123, 5353, 137, 138}

EXCLUDED_SRCS  = {"192.168.1.1", "192.168.0.1", "10.202.0.1", "10.202.0.254", "192.168.1.254"}

with open("encoder_mapping.json") as f:
    enc_map = json.load(f)
with open("feature_columns.json") as f:
    feature_columns = json.load(f)

PORT_SERVICE = {
    20:"ftp_data", 21:"ftp",  22:"ssh",   23:"telnet", 25:"smtp",
    53:"domain",   80:"http", 110:"pop_3",113:"auth",  143:"imap4",
    443:"http_443",445:"netbios_ssn",     513:"login", 514:"shell",
    515:"printer", 8080:"http_8001",      179:"bgp",   119:"nntp",
    123:"ntp_u",   389:"ldap",512:"exec", 194:"IRC",   79:"finger",
}

def _service(port, proto):
    if proto == "icmp": return "ecr_i"
    return PORT_SERVICE.get(port, "other")

def _flag(pkt):
    if TCP not in pkt: return "SF"
    f = int(pkt[TCP].flags)
    RST, SYN, ACK, FIN = 0x004, 0x002, 0x010, 0x001
    if f & RST:              return "RSTO" if f & ACK else "RSTR"
    if (f & SYN) and (f & ACK): return "S1"
    if (f & SYN):            return "S0"
    if f & FIN:              return "SF"
    return "OTH"

# ===== Trackers =====
_syn_tracker  = defaultdict(deque)
_scan_tracker = defaultdict(lambda: defaultdict(deque))
_icmp_tracker = defaultdict(deque)
_udp_tracker  = defaultdict(deque)
_track_lock   = threading.Lock()

def _check(src, dst, dst_port, proto, flag, t):
    cutoff = t - WINDOW_SECS
    with _track_lock:
        if flag == "S0" and dst_port not in EXCLUDED_PORTS:
            q = _syn_tracker[(dst, dst_port)]
            q.append(t)
            while q and q[0] < cutoff: q.popleft()
            if len(q) >= THRESHOLD:
                return len(q), "syn_flood"
            pq = _scan_tracker[src][dst_port]
            pq.append(t)
            while pq and pq[0] < cutoff: pq.popleft()
            scan_n = sum(len([x for x in dq if x > cutoff])
                         for dq in _scan_tracker[src].values())
            if scan_n >= SCAN_THRESH:
                return scan_n, "port_scan"
        elif proto == "icmp":
            q = _icmp_tracker[(src, dst)]
            q.append(t)
            while q and q[0] < cutoff: q.popleft()
            if len(q) >= THRESHOLD:
                return len(q), "icmp_flood"
        elif proto == "udp" and dst_port not in EXCLUDED_PORTS:
            q = _udp_tracker[(src, dst, dst_port)]
            q.append(t)
            while q and q[0] < cutoff: q.popleft()
            if len(q) >= THRESHOLD:
                return len(q), "udp_flood"
    return 0, "none"

def _make_features(attack_type, service_enc, count, src_bytes):
    f = {col: 0 for col in feature_columns}
    c = min(count * 3, 511)
    h = min(count * 3, 255)

    if attack_type == "syn_flood":
        f.update({"protocol_type":enc_map["protocol_type"]["tcp"],
                  "service":service_enc,"flag":enc_map["flag"]["S0"],
                  "src_bytes":0,"dst_bytes":0,"count":c,"srv_count":c,
                  "serror_rate":1.0,"srv_serror_rate":1.0,"same_srv_rate":1.0,
                  "dst_host_count":h,"dst_host_srv_count":h,
                  "dst_host_serror_rate":1.0,"dst_host_srv_serror_rate":1.0})
    elif attack_type == "icmp_flood":
        f.update({"protocol_type":enc_map["protocol_type"]["icmp"],
                  "service":enc_map["service"]["ecr_i"],"flag":enc_map["flag"]["SF"],
                  "src_bytes":1032,"dst_bytes":0,"count":c,"srv_count":c,
                  "same_srv_rate":1.0,"dst_host_count":255,
                  "dst_host_srv_count":h,"dst_host_same_srv_rate":1.0})
    elif attack_type == "udp_flood":
        f.update({"protocol_type":enc_map["protocol_type"]["udp"],
                  "service":service_enc,"flag":enc_map["flag"]["SF"],
                  "src_bytes":src_bytes,"dst_bytes":0,"count":c,"srv_count":c,
                  "same_srv_rate":1.0,"dst_host_count":h,"dst_host_srv_count":h})
    elif attack_type == "port_scan":
        f.update({"protocol_type":enc_map["protocol_type"]["tcp"],
                  "service":enc_map["service"].get("private",49),
                  "flag":enc_map["flag"]["REJ"],"src_bytes":0,"dst_bytes":0,
                  "count":min(count,30),"srv_count":1,
                  "rerror_rate":1.0,"srv_rerror_rate":1.0,
                  "diff_srv_rate":1.0,"srv_diff_host_rate":1.0,
                  "dst_host_count":min(count*5,255),"dst_host_srv_count":1,
                  "dst_host_diff_srv_rate":1.0,
                  "dst_host_rerror_rate":1.0,"dst_host_srv_rerror_rate":1.0})
    return f

# ===== Trafik penceresi =====
_win      = deque()
_win_lock = threading.Lock()
_SE = {"S0","S1","S2","S3"}
_RE = {"REJ","RSTO","RSTR"}

def _traffic_features(dst, service, flag, t):
    cutoff = t - WINDOW_SECS
    with _win_lock:
        while _win and _win[0][0] < cutoff: _win.popleft()
        window = list(_win)
        _win.append((t, dst, service, flag))
    c  = sum(1 for _,ip,_,_ in window if ip==dst) or 1
    s  = sum(1 for _,_,sv,_ in window if sv==service) or 1
    sm = sum(1 for _,ip,sv,_ in window if ip==dst and sv==service)
    se = sum(1 for _,ip,_,fl in window if ip==dst and fl in _SE)
    re = sum(1 for _,ip,_,fl in window if ip==dst and fl in _RE)
    return {"count":c,"srv_count":s,
            "serror_rate":se/c,"srv_serror_rate":se/max(s,1),
            "rerror_rate":re/c,"srv_rerror_rate":re/max(s,1),
            "same_srv_rate":sm/c,"diff_srv_rate":(c-sm)/c,
            "srv_diff_host_rate":0.0}

# ===== Sonuc listesi =====
_attacks  = []
_benigns  = []
_rlock    = threading.Lock()

def _save(result):
    with _rlock:
        if result["prediction"] == "ATTACK":
            _attacks.insert(0, result)
            if len(_attacks) > 500: _attacks.pop()
        else:
            _benigns.insert(0, result)
            if len(_benigns) > 100: _benigns.pop()
        tmp = RESULTS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_attacks + _benigns, f)
        os.replace(tmp, RESULTS_FILE)

# ===== Kuyruk =====
_q = queue.Queue(maxsize=2000)

def _worker():
    while True:
        try:
            arr, src, dst, proto, dport, flag, urgent, sbytes = _q.get(timeout=1)
        except queue.Empty:
            continue

        service     = _service(dport, proto)
        proto_enc   = enc_map["protocol_type"].get(proto, 1)
        service_enc = enc_map["service"].get(service, enc_map["service"]["other"])
        flag_enc    = enc_map["flag"].get(flag, enc_map["flag"]["OTH"])

        count, atype = _check(src, dst, dport, proto, flag, arr)

        if atype != "none":
            features = _make_features(atype, service_enc, count, sbytes)
        else:
            features = {col: 0 for col in feature_columns}
            features.update({"protocol_type":proto_enc,"service":service_enc,
                              "flag":flag_enc,"src_bytes":sbytes,
                              "land":1 if src==dst else 0,"urgent":urgent})
            features.update(_traffic_features(dst, service, flag, arr))

        try:
            r = requests.post(f"{API_URL}/predict", json=features, timeout=2).json()
            # Simülasyon IP'leri: 10.10.10.x (eski) veya hedef subnet'in .201-.204 adresleri (yeni)
            _last = src.rsplit(".", 1)
            true_lbl = 1 if (src.startswith("10.10.10.") or
                             (len(_last) == 2 and _last[-1].isdigit() and 201 <= int(_last[-1]) <= 204)) else 0
            pred_lbl = 1 if r["prediction"] == "ATTACK" else 0
            mismatch = true_lbl != pred_lbl

            result = {"timestamp":datetime.now(timezone.utc).isoformat(),
                      "src":src,"dst":dst,"protocol":proto,"service":service,
                      "flag":flag,"src_bytes":sbytes,"attack_type":atype,
                      "prediction":r["prediction"],
                      "category":r.get("attack_category","-"),
                      "probability":round(r["attack_probability"]*100,2),
                      "true_label":"ATTACK" if true_lbl else "BENIGN",
                      "feedback_gitti":"✅" if mismatch else ""}
            icon = "🔴" if result["prediction"]=="ATTACK" else "🟢"
            print(f"{icon} {src:>15} → {dst:<15} | "
                  f"{proto.upper():<4} {service:<12} | "
                  f"[{atype:<10}] {result['prediction']} ({result['category']}) "
                  f"%{result['probability']:.1f}")
            _save(result)
            if (result["prediction"] == "ATTACK"
                    and result["category"] != "Normal"):
                try: requests.post(f"{API_URL}/alert", json=result, timeout=2)
                except: pass

            if mismatch:
                fb = features.copy()
                fb["true_label"]      = true_lbl
                fb["predicted_label"] = pred_lbl
                fb["source"]          = "real_traffic"
                try:
                    requests.post(f"{API_URL}/feedback", json=fb, timeout=2)
                    tur = "FN" if true_lbl == 1 else "FP"
                    print(f"📝 [{tur}] Feedback → {src} → {dst}")
                except: pass
        except Exception:
            pass
        _q.task_done()

def capture_packet(pkt):
    if IP not in pkt: return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if src.startswith("127.") or dst.startswith("127."):
        if not src.startswith("10.10.10."):
            return
    if src in EXCLUDED_SRCS: return
    arr = time.time()
    ip  = pkt[IP]
    if TCP in pkt:
        proto, dport = "tcp", pkt[TCP].dport
        flag = _flag(pkt); urgent = 1 if int(pkt[TCP].flags) & 0x020 else 0
    elif UDP in pkt:
        proto, dport = "udp", pkt[UDP].dport; flag, urgent = "SF", 0
    elif ICMP in pkt:
        proto, dport = "icmp", 0; flag, urgent = "SF", 0
    else: return
    try:
        _q.put_nowait((arr, ip.src, ip.dst, proto, dport, flag, urgent, len(pkt)))
    except queue.Full:
        pass

if __name__ == "__main__":
    print("=" * 60)
    print("  AI-Based IDS — Gercek Trafik Yakalama")
    print("=" * 60)
    print(f"  API   : {API_URL}")
    print(f"  Kayit : {RESULTS_FILE}")
    print("  Durdurmak icin: Ctrl+C")
    print("=" * 60 + "\n")

    for _ in range(4):
        threading.Thread(target=_worker, daemon=True).start()

    all_ifaces = [n for n, i in scapy_conf.ifaces.items()
                  if "loopback" not in str(i.description).lower()]

    print(f"  {len(all_ifaces)} interface dinleniyor...\n")
    try:
        sniff(iface=all_ifaces, prn=capture_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print("\nYakalama durduruldu.")
