import socket
import subprocess
import sys
from datetime import datetime
from scapy.all import *
import argparse
import logging
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
from time import strftime


SYNACK = 0x12
RSTACK = 0x14

def scanport(port, target):
    
    srcport = RandShort()
    conf.verb = 0
    SYNACKpkt = sr1(IP(dst=target)/TCP(sport = srcport, dport = port, flags="S"))
    pktflags = SYNACKpkt.getlayer(TCP).flags
    if pktflags == SYNACK:
        return True
    else:
        return False
    RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
    send(RSTpkt)

def get_ports(target1, min_port, max_port):
    try:
        try:
            if min_port >= 0 and max_port >=0 and max_port >= min_port:
                pass
            else:
                print("Invalid range of ports\nExiting...")
                sys.exit(1)
        except Exception:
            print("Invalid range of ports\nExiting...")
            sys.exit(1)
    except KeyboardInterrupt:
        print("User requested program termination\nExiting")
        sys.exit(1)
    
    ports = range(min_port, max_port + 1)
    start_clock = datetime.now()
    
    
    print("[*] Scanning started at " + strftime("%H:%M:%S") + "\n")
    print("[*] Scanning:", target1, "\n")
    for port in ports:
        status = scanport(port, target1)
        if status == True:
            print("port " + str(port) + ": Open")
    
    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    print("\n[*] Scanning finished")
    print("[*] Total scan duration: " + str(total_time))
        
def scan(ip2, stp, enp):
    
    arp = ARP(pdst=ip2)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append(received.psrc)
    for client in clients:
        client = str(client)
        
        get_ports(client, stp, enp)
    

def main(hst, sp, ep):
    
    if "/" in hst:
        
        scan(hst, sp, ep)
    
    else:
        
        get_ports(hst, sp, ep)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("--host", help="Host to scan.", default = "192.168.43.1/24")
    parser.add_argument("--ports", "-p", dest="port_range", default="1-2000", help="Port range to scan, default is 1-2000")
    args = parser.parse_args()
    host, port_range = args.host, args.port_range      
    start_port, end_port = port_range.split("-")
    start_port, end_port = int(start_port), int(end_port)
    host_str = str(host)
    #host = socket.gethostbyname(host_str)
    main(host, start_port, end_port)
