from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer (like checking if the envelope has an address)
        ip_layer = packet[IP]
        protocol = "Unknown"
        if TCP in packet:
            protocol = "TCP"  # If it's a TCP packet, mark it as TCP
        elif UDP in packet:
            protocol = "UDP"  # If it's a UDP packet, mark it as UDP

        # Print out the packet information
        print(f"Protocol: {protocol}")
        print(f"Source IP: {ip_layer.src}")  # Sender's address
        print(f"Destination IP: {ip_layer.dst}")  # Recipient's address

        if protocol == "TCP":
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")  # Sender's port (like a room number)
            print(f"Destination Port: {tcp_layer.dport}")  # Recipient's port

        elif protocol == "UDP":
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        print("\n")

# Start sniffing packets and using the packet_callback function to process them
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)