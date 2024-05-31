import scapy.all as scapy
import time

def send_intrusion_packet(target_ip, target_port, payload):
    # Craft a TCP packet with the specified payload
    packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=target_port) / scapy.Raw(load=payload)

    # Send the packet
    scapy.send(packet, verbose=False)
for i in range(0,11):
    # Test intrusion by sending a packet with a suspicious payload
    target_ip = "127.0.0.1"  # Replace with the actual target IP address
    target_port = 5000  # Replace with the actual target port
    suspicious_payload = b"login failed"
    send_intrusion_packet(target_ip, target_port, suspicious_payload)
    print('package sent!')

    # Wait for a moment to allow the packet to be captured
    time.sleep(2)
