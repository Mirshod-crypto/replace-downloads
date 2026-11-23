#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
ack_list = []
try:
    def process_packet(packet):
        scapy_packet=scapy.IP(packet.get_payload())
        # if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                # agar dport da http tursa - biz sorov yuborganmiz
                if ".zip" in scapy_packet[scapy.Raw].load.decode():
                    print("ZIP request")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                    print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                # agar sport da http tursa javob kelayapti
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("Changing")
                    print(scapy_packet.show())
        packet.accept()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[+]Quitting..........")