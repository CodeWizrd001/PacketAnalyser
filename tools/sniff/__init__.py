'''Sniffing Module 

Module Designed For Sniffing and Handing over Data Processing'''

from scapy.all import *

from ..utils import Count
from ..harden import Tables

def expand(x) :
    yield x 
    while x.payload :
        x = x.payload

class Sniffer :
    def __init__(self,interface="eth0",store=False,functions={}) :
        self.interface = interface
        self.store = store
        self.functions = functions

    def __repr__(self) :
        print(f"Sniffer Object : {hex(id(self))}")

    def process_packet(self,packet) :
        Flags = {
            'FIN' : 0x01,
            'SYN' : 0x02,
            'RST' : 0x04,
            'PSH' : 0x08,
            'ACK' : 0x10,
            'URG' : 0x20,
            'ECE' : 0x40,
            'CWR' : 0x80,
        }
        flags = {
            'FIN' : 0,
            'SYN' : 0,
            'RST' : 0,
            'PSH' : 0,
            'ACK' : 0,
            'URG' : 0,
            'ECE' : 0,
            'CWR' : 0,
        }

        if packet.haslayer(IP) :
            if str(packet[IP].src) == '192.168.175.129' :
                return

        if packet.haslayer(TCP) and packet.haslayer(IP) :
            Count.addRequest(str(packet[IP].src)+':'+str(packet[TCP].dport),'tcp')
            F = packet['TCP'].flags 
            for f in Flags :
                flags[f] = F & Flags[f]
            if flags['FIN'] & flags['URG'] & flags['PSH'] :
                print(f'[+] Xmas Packet Detected From {packet[IP].src} to {packet[IP].dst}')

        elif packet.haslayer(UDP) and packet.haslayer(IP):
            Count.addRequest(str(packet[IP].src)+':'+str(packet[UDP].dport),'udp')

        elif packet.haslayer(ICMP) :
            Count.addRequest(packet[IP].src,'icmp')

        elif packet.haslayer(IP) :
            Count.addRequest(packet[IP].src)
        
        else :
            pass

        if packet.haslayer(Raw) :
            b = bytes(packet[Raw].load)
            load = packet[Raw].load

    def run(self) :
        sniff(iface=self.interface,store=self.store,prn=self.process_packet)