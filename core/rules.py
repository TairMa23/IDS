from collections import defaultdict
from datetime import datetime, timedelta
import re

syn_tracker = defaultdict(list)
PORT_SCAN_THRESHOLD = 10  # Number of SYN packets
TIME_WINDOW = timedelta(seconds=3)  # Within 1 second


def detect_port_scan(packet):
    """
    Detects port scan attacks based on the number of SYN packets from a single IP.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    Returns:
        bool: True if a port scan is detected, otherwise False.
    """
    if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        src_ip = packet['IP'].src
        current_time = datetime.now()
        syn_tracker[src_ip].append(current_time)
        # Filter out timestamps older than TIME_WINDOW
        syn_tracker[src_ip] = [time for time in syn_tracker[src_ip] if current_time - time <= TIME_WINDOW]
        if len(syn_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            return True
    return False


# Patterns to detect SQL Injection attacks
SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b.*\bfrom\b)",  # UNION SELECT FROM pattern
    r"(\bselect\b.*\bfrom\b)",  # Simple SELECT FROM pattern
    r"(\bselect\b.*\bfrom\b.*\bwhere\b)",  # SELECT FROM WHERE pattern with complex conditions
    r"(\bor\b.*=.*\bor\b)",  # OR 1=1 pattern
    r"(sleep\(\d+\))",  # SLEEP function used in SQL injection
    r"(benchmark\(\d+,\s*.*\))"  # BENCHMARK function
]


def detect_sql_injection(packet):
    """
    Detects SQL Injection attacks by analyzing the payload for known SQL injection patterns.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    Returns:
        bool: True if SQL injection patterns are detected, otherwise False.
    """
    if packet.haslayer('Raw'):
        payload = str(packet['Raw'].load).lower()
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload):
                return True
    return False


# Patterns to detect Cross-Site Scripting (XSS) attacks
XSS_PATTERNS = [
    r"<script.*?>.*?</script>",  # Basic <script> tag
    r"on\w+\s*=",  # Event handlers like onclick=, onload=, etc.
    r"javascript:",  # JavaScript protocol in URI
    r"data:text/html",  # Data URI containing HTML
    r"<img.*?src\s*=.*?>",  # Potentially malicious image tags
    r"<iframe.*?src\s*=.*?>",  # Potentially malicious iframe tags
]


def detect_xss(packet):
    """
    Detects Cross-Site Scripting (XSS) attacks by analyzing the payload for known XSS patterns.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    Returns:
        bool: True if XSS patterns are detected, otherwise False.
    """
    if packet.haslayer('Raw'):
        payload = str(packet['Raw'].load).lower()
        for pattern in XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
    return False
