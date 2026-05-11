"""
AI-Based IDS — Saldiri Simulatoru
Arkadaşın bilgisayarında çalıştırır:  python attack_sim.py
Gereksinim: pip install scapy  +  Administrator olarak çalıştır
"""

import time
import sys
from scapy.all import IP, TCP, UDP, ICMP, send, RandShort

TARGET = input("Hedef IP (IDS bilgisayarı): ").strip()
if not TARGET:
    print("IP girilmedi, çıkılıyor.")
    sys.exit(1)


print(f"\nHedef: {TARGET}")
print("=" * 40)


def ping_flood(count=100):
    print(f"\n[ICMP] Ping flood → {TARGET} ({count} paket)")
    for i in range(count):
        send(IP(src="10.10.10.11", dst=TARGET) / ICMP(), verbose=False)
        time.sleep(0.01)
    print("[ICMP] Tamamlandi.")


def syn_flood(port=80, count=300):
    print(f"\n[TCP SYN] SYN flood → {TARGET}:{port} ({count} paket)")
    fake_src = "10.10.10.10"
    for i in range(count):
        send(IP(src=fake_src, dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()), verbose=False)
        time.sleep(0.005)
    print("[TCP SYN] Tamamlandi.")


def port_scan(ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 79, 80, 110, 135, 139,
                 143, 445, 512, 513, 514, 1433, 3306, 5432, 8080]
    print(f"\n[PROBE] Port tarama → {TARGET} ({len(ports)} port)")
    for port in ports:
        send(IP(src="10.10.10.13", dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()), verbose=False)
        time.sleep(0.05)
    print("[PROBE] Tamamlandi.")


def udp_flood(port=6000, count=100):
    print(f"\n[UDP] UDP flood → {TARGET}:{port} ({count} paket)")
    for i in range(count):
        send(IP(src="10.10.10.12", dst=TARGET) / UDP(dport=port, sport=RandShort()) / b"XXXXXXXX", verbose=False)
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
