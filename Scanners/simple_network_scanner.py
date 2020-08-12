import argparse
from scapy.all import ARP, Ether, srp

def scan_devices(target_ip):
    arp = ARP(pdst=target_ip)# create the Ether broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    packet = ether/arp # stack pakcets
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, recieved in result:
        clients.append({"ip": recieved.psrc, 'mac': recieved.hwsrc})
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    a = 0
    for client in clients:
        print("\n{:16}    {}".format(client['ip'], client['mac']))    
        a = a + 1
    print("\nTotal devices in the network:", a, "\n")
if __name__ == "__main__":            

    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("--host", help="Host to scan.", default = "192.168.43.1/24")
    args = parser.parse_args()
    host = args.host
    scan_devices(host)
