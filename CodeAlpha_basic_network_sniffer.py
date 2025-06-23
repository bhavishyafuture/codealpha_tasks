from scapy.all import sniff

# Function to process captured packets
def process_packet(packet):
    # Process packet data here
    print(packet.summary())  # Example: Print packet summary

# Main function to capture packets
def capture_packets(interface, packet_count=-1):
    sniff(iface=interface, prn=process_packet, count=packet_count)

# Main function
def main():
    interface = input("Enter interface name (e.g., 'Ethernet', 'Wi-Fi'): ")
    capture_packets(interface)

if __name__ == "__main__":
    main()
