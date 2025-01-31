from scapy.all import sniff, get_if_list

# Function to process each packet
def packet_callback(packet):
    print(packet.summary())

# List available interfaces
interfaces = get_if_list()

# Sniff on each interface for 3 seconds
for iface in interfaces:
    print(f"Sniffing on interface: {iface}")
    sniff(iface=iface, prn=packet_callback, timeout=3)
