#Before you start, make sure to install scapy in your Windows Command Prompt [Open Command Prompt with Administrator Privilege]
#Then type and run: pip install scapy
#Save this python file, named as Packet Capture in a folder. Example: C:\Users\User 1\Desktop\Python Folder
#In CMD that you've opened as administrator, run: cd C:\Users\User 1\Desktop\Python Folder
#After running previous command, run: python Packet Capture.py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import binascii

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        #Determine the protocols
        protocol_name = ""
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown Protocol"

        #Print packet into readable format
        print("=" * 50)
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        #Prints payload data
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            try:
                readable_payload = payload.decode('utf-8')
            except UnicodeDecodeError:
                readable_payload = binascii.hexlify(payload).decode('utf-8')
            
            print(f"Payload: {readable_payload}")
            if TCP in packet:
                tcp_layer = packet[TCP]
                print(f"Source Port: {tcp_layer.sport}")
                print(f"Destination Port: {tcp_layer.dport}")
                print(f"Flags: {tcp_layer.flags}")
            elif UDP in packet:
                udp_layer = packet[UDP]
                print(f"Source Port: {udp_layer.sport}")
                print(f"Destination Port: {udp_layer.dport}")
        elif packet.haslayer(ICMP):
            payload = bytes(packet[ICMP].payload)
            try:
                readable_payload = payload.decode('utf-8')
            except UnicodeDecodeError:
                readable_payload = binascii.hexlify(payload).decode('utf-8')
            
            print(f"Payload: {readable_payload}")
        else:
            print("No payload data available")

        print("=" * 50)

def main():
    #Packet Capture on the default network interface
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    main()

#This is the First task assigned by CODEALPHA to Vedish. Task has been completed. 
#In order for the code to run successfully, follow line 1-5
#The code contains the following information regarding the packets captured: 
#Protocol; Source IP; Destination IP; Source Port; Destination Port; Flags; Payload; Host, and so much more!
#Unfortunately I wouldn't be able to execute the python file since It will produce Confidential information.