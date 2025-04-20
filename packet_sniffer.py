from scapy.all import sniff, IP, TCP, UDP, ICMP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Callback function to process captured packets
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n{TAB_1}IPv4 Packet:")
        print(f"{TAB_2}Source: {ip_layer.src}, Destination: {ip_layer.dst}")
        print(f"{TAB_2}Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"{TAB_1}TCP Segment:")
            print(f"{TAB_2}Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            print(f"{TAB_2}Flags: {tcp_layer.flags}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"{TAB_1}UDP Segment:")
            print(f"{TAB_2}Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"{TAB_1}ICMP Packet:")
            print(f"{TAB_2}Type: {icmp_layer.type}, Code: {icmp_layer.code}")

# Main function to start sniffing packets
def main():
    print("Starting packet capture...")
    sniff(filter="ip", prn=process_packet)

if __name__ == "__main__":
    main()

