from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

# Define a packet callback function
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Check if the packet has a TCP or UDP layer
        if TCP in packet:
            layer_type = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            layer_type = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            layer_type = "Other"
            sport = None
            dport = None

        # Print the captured packet information
        print(f"IP Src: {ip_src} -> IP Dst: {ip_dst} | Protocol: {protocol} | Layer: {layer_type} | Src Port: {sport} | Dst Port: {dport}")

# Start sniffing on the specified interface
def start_sniffing(interface):
    print(f"Starting sniffer on {interface}...")
    # Use L3Socket instead of Layer 2 to avoid Npcap issues
    conf.L3socket = conf.L3socket
    sniff(iface=interface, prn=packet_callback, store=False)

# Example usage
if __name__ == "__main__":
    interface = "Ethernet"  # Change this to your network interface
    start_sniffing(interface)
