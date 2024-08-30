from scapy.all import sniff

captured_packets = []

def process_packet(packet):
    global captured_packets
    captured_packets.append(packet)

    if len(captured_packets) >= 100:  # ניתוח כל 100 חבילות
        for pkt in captured_packets:
            analyze_packet(pkt)
        captured_packets = []

def start_sniffing():
    sniff(prn=process_packet, store=0)

def analyze_packet(packet):
    from core.rules import detect_port_scan, detect_ddos_attack, detect_sql_injection
    from core.alerts import alert

    if detect_port_scan(packet):
        alert("Port scan detected!", packet)
    if detect_ddos_attack(packet):
        alert("DDoS attack detected!", packet)
    # if detect_sql_injection(packet):
    #     alert("SQL Injection attempt detected!", packet)
