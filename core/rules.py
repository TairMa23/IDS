from collections import defaultdict
from collections import defaultdict
from datetime import datetime, timedelta
from time import time
import re

syn_tracker = defaultdict(list)
PORT_SCAN_THRESHOLD = 10  # Number of SYN packets
TIME_WINDOW = timedelta(seconds=3)  # Within 1 second

ddos_counter = defaultdict(int)
rate_limiter = defaultdict(float)
RATE_LIMIT = 1000  # packets per second
DDOS_THRESHOLD = 1000  # Total packets threshold


def detect_port_scan(packet):
    if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        src_ip = packet['IP'].src
        current_time = datetime.now()
        syn_tracker[src_ip].append(current_time)
        # Filter out timestamps older than TIME_WINDOW
        syn_tracker[src_ip] = [time for time in syn_tracker[src_ip] if current_time - time <= TIME_WINDOW]
        print(f"SYN Count for {src_ip}: {len(syn_tracker[src_ip])}")  # הודעת דיבאג
        if len(syn_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            return True
    return False


# רשימת IPs שכבר זוהו
detected_ips = set()


def detect_ddos_attack(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        current_time = time()

        # בדיקה אם עבר יותר משנייה מאז הפעם האחרונה שקיבלנו חבילה מ-IP זה
        if current_time - rate_limiter[src_ip] > 1:
            ddos_counter[src_ip] = 0  # איפוס המונה
            rate_limiter[src_ip] = current_time  # עדכון זמן הפעם האחרונה

        ddos_counter[src_ip] += 1  # הגדלת המונה עבור חבילות מאותו IP

        # בדיקה אם מספר החבילות עבר את המגבלות והאם ה-IP לא זוהה קודם
        if ddos_counter[src_ip] > RATE_LIMIT and ddos_counter[src_ip] > DDOS_THRESHOLD:
            if src_ip not in detected_ips:
                detected_ips.add(src_ip)  # הוספת ה-IP לרשימת ה-IPים שזוהו
                return True  # החזרת TRUE רק אם ה-IP לא זוהה קודם
    return False  # החזרת FALSE אם לא זוהתה מתקפה או אם ה-IP כבר זוהה קודם


SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b.*\bfrom\b)",  # UNION SELECT FROM pattern
    r"(\bselect\b.*\bfrom\b.*\bwhere\b)",  # SELECT FROM WHERE pattern with complex conditions
    r"(\bor\b.*=.*\bor\b)",  # OR 1=1 pattern
    r"(sleep\(\d+\))",  # SLEEP funcjjtion used in SQL injection
    r"(benchmark\(\d+,\s*.*\))"  # BENCHMARK function
]


def detect_sql_injection(packet):
    if packet.haslayer('Raw'):
        payload = str(packet['Raw'].load).lower()
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload):
                return True
    return False
