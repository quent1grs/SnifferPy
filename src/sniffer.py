import scapy.all as scapy
# ________________________________________________________________________verif proto et count
TCPcount = 0
UDPcount = 0
ARPcount = 0
ICMPcount = 0
DNScount = 0
unknowncount = 0

def get_protocol_name(packet):
    if packet.haslayer(scapy.TCP):
        return "TCP"
    elif packet.haslayer(scapy.UDP):
        return "UDP"
    elif packet.haslayer(scapy.ICMP):
        return "ICMP"
    elif packet.haslayer(scapy.ARP):
        return "ARP"
    elif packet.haslayer(scapy.DNS):
        return "DNS"
    else:
        return "Unknown"
# _____________________________________________________________________________________________________print les info par rapport au proto
def print_info(packet):
    global TCPcount, UDPcount, ARPcount, ICMPcount, DNScount, unknowncount
    
    try:
        # Affiche le nom du protocole
        protocol = get_protocol_name(packet)
        print(f"Protocole: {protocol}")
        
        if packet.haslayer(scapy.IP):
            print(f"IP Source: {packet[scapy.IP].src}")
            print(f"IP Destination: {packet[scapy.IP].dst}")
        
        if packet.haslayer(scapy.TCP):
            print(f"Port Source: {packet[scapy.TCP].sport}")
            print(f"Port Destination: {packet[scapy.TCP].dport}")
            TCPcount += 1
        
        if packet.haslayer(scapy.UDP):
            print(f"Port Source: {packet[scapy.UDP].sport}")
            print(f"Port Destination: {packet[scapy.UDP].dport}")
            UDPcount += 1
        
        if packet.haslayer(scapy.ICMP):
            print(f"ICMP Type: {packet[scapy.ICMP].type}")
            print(f"ICMP Code: {packet[scapy.ICMP].code}")
            ICMPcount += 1
        
        if packet.haslayer(scapy.ARP):
            print(f"Type ARP: {packet[scapy.ARP].op}")  # 1 = Request, 2 = Reply
            print(f"IP Source: {packet[scapy.ARP].psrc}")
            print(f"IP Destination: {packet[scapy.ARP].pdst}")
            print(f"MAC Source: {packet[scapy.ARP].hwsrc}")
            print(f"MAC Destination: {packet[scapy.ARP].hwdst}")
            ARPcount += 1
        
        if packet.haslayer(scapy.DNS):
            if packet[scapy.DNS].qr == 0:
        # Requête DNS
                print(f"DNS Query Name: {packet[scapy.DNS].qd.qname.decode()}")
            elif packet[scapy.DNS].qr == 1:
        # Réponse DNS
                print(f"DNS Response for Query: {packet[scapy.DNS].qd.qname.decode()}")
            if packet[scapy.DNS].an:
                for i in range(packet[scapy.DNS].ancount):
                    print(f"Answer {i + 1}: {packet[scapy.DNS].an[i].rdata}")
                DNScount += 1
        
        if protocol == "Unknown":
            unknowncount += 1
        
        print(f"Résumé: {packet.summary()}")
        
    except Exception as e:
        print(f"Erreur lors de l'analyse du paquet: {e}")
    
    print("\n" + ("-" * 50) + "\n")
# _____________________________________________________________________________________________________ input et gestion d'erreur de l'input
print("Interfaces réseau disponibles:" '\n')
print(scapy.get_if_list())

while True:
    interface_name = input("\nEntrez le nom de l'interface réseau à écouter : ")
    if interface_name in scapy.get_if_list():
        break
    else:
        print("Erreur : l'interface spécifiée n'existe pas.")

while True:
    count = input("\nEntrez le nombre de paquets à capturer : ")
    if count.isdigit() and int(count) > 0:
        count = int(count)
        break
    else:
        print("Erreur : veuillez entrer un entier positif.")
# _____________________________________________________________________________________________________ début de la capture, print des infos et résumé des count
print(f"\nDébut de la capture de {count} paquets sur l'interface {interface_name}...\n")


p = scapy.sniff(iface=interface_name, prn=print_info, count=count)

print(f"\nCapture terminée. {len(p)} paquets capturés.")
print(f"Paquets TCP capturés: {TCPcount}")
print(f"Paquets UDP capturés: {UDPcount}")
print(f"Paquets ARP capturés: {ARPcount}")
print(f"Paquets ICMP capturés: {ICMPcount}")
print(f"Paquets DNS capturés: {DNScount}")
print(f"Paquets inconnus capturés: {unknowncount}")
# _____________________________________________________________________________________________________