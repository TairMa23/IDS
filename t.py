from collections import defaultdict

from scapy.all import IP, TCP, send
from scapy.packet import Raw

from core.packet_capture import analyze_packet


def simulate_port_scan(target_ip, src_ip, num_ports=15):
    for port in range(10000, 10000 + num_ports):  # פורטים בין 10000 ל-10015 לדוגמה
        packet = IP(dst=target_ip, src=src_ip) / TCP(dport=port, flags='S')
        send(packet)


# בדיקת זיהוי SQL Injection
def simulate_sql_injection():
    packet = IP() / TCP() / Raw(load="SELECT * FROM users")
    analyze_packet(packet)


def simulate_xss_attack():
    # Creating a packet with an XSS payload
    xss_payload = "<script>alert('XSS');</script>"
    packet = IP(src='192.168.1.5', dst='192.168.1.1') / TCP(sport=12345, dport=80) / Raw(load=xss_payload)
    send(packet)


# simulate_port_scan
target_ip = '192.168.1.1'
src_ip = '192.168.1.4'
# simulate_port_scan(target_ip, src_ip)
# simulate_sql_injection()
# simulate_xss_attack()
