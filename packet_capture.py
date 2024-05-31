import scapy.all as scapy

def packet_callback(packet):
    # Process each captured packet here
    print(packet.summary())

# Capture all packets for a specified duration (in seconds)
capture_duration = 10
scapy.sniff(prn=packet_callback, timeout=capture_duration)
