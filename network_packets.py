from scapy.all import sniff, IP, conf

# Function to process each captured packet
def packet_analysis(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("="*50)

# Use Layer 3 socket
conf.L3socket = conf.L3socket

# Sniff packets on the network
print("Starting packet sniffer...")
sniff(filter="ip", prn=packet_analysis)
