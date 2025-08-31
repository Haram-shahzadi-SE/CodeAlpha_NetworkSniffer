from scapy.all import sniff, IP, TCP, UDP

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Detect protocol type
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Source: {ip_src} --> Destination: {ip_dst} | Protocol: {protocol}")

        # Print payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print("Payload:", bytes(packet.payload)[:50], "\n")  # Show first 50 bytes

# Start sniffing packets
print("Starting network sniffer... Press CTRL+C to stop.")
sniff(prn=packet_callback, store=False, count=20)  # Capture 20 packets
