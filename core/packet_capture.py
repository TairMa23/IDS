from scapy.all import sniff

from app.routes import update_traffic_summary
from core.rules import detect_xss

captured_packets = []


def process_packet(packet):
    """
    Processes each captured network packet.

    Args:
        packet (scapy.packet.Packet): The network packet to process.

    This function:
    - Adds the packet to the list of captured packets.
    - Updates the traffic summary with the new packet.
    - Analyzes the packets if the number of captured packets reaches 100.
    """
    global captured_packets
    captured_packets.append(packet)
    update_traffic_summary(packet)
    if len(captured_packets) >= 100:  # ניתוח כל 100 חבילות
        for pkt in captured_packets:
            analyze_packet(pkt)
        captured_packets = []


def start_sniffing():
    """
    Starts the packet sniffing process.

    This function uses Scapy to capture packets and processes them using the
    `process_packet` function. The `store=0` parameter ensures that packets
    are not stored in memory.
    """
    sniff(prn=process_packet, store=0)


def analyze_packet(packet):
    """
    Analyzes a network packet for potential security threats.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    This function checks the packet against several detection functions:
    - `detect_port_scan` for port scan attempts.
    - `detect_sql_injection` for SQL injection attempts.
    - `detect_xss` for XSS (Cross-Site Scripting) attempts.

    If any threat is detected, it triggers an alert using the `alert` function.
    """
    from core.rules import detect_port_scan, detect_sql_injection
    from core.alerts import alert

    if detect_port_scan(packet):
        alert("Port scan detected!", packet)
    if detect_sql_injection(packet):
        alert("SQL Injection attempt detected!", packet)
    if detect_xss(packet):
        alert("XSS attempt detected!", packet)
