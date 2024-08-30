import unittest
from collections import defaultdict  # ייבוא defaultdict
from scapy.all import IP, TCP
from core.rules import detect_port_scan, detect_ddos_attack


# יצירת מחלקה לבדיקות
class TestRules(unittest.TestCase):

    def setUp(self):
        # אפשר לאפס כאן את כל המידע הגלובלי שמשמש לזיהוי
        # לדוגמה, אם ישנם משתנים גלובליים כמו syn_tracker, ddos_tracker וכו'.
        global syn_tracker, ddos_tracker  # נניח שהם גלובליים, אחרת יש להחזיר פונקציה לאיפוס
        syn_tracker = defaultdict(list)
        ddos_tracker = defaultdict(int)

    def test_port_scan_detection(self):
        for _ in range(11):  # מעבר הסף החדש של 10 חבילות
            packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
            result = detect_port_scan(packet)
            print(f"Port scan detection result: {result}")  # דיבאג
        self.assertTrue(result)


    def test_ddos_attack_detection(self):
        # בדיקת זיהוי התקפת DDoS
        packet = IP(dst="192.168.1.1") / TCP(dport=80)
        for _ in range(999):  # עדיין תחת הסף
            self.assertFalse(detect_ddos_attack(packet))
        self.assertTrue(detect_ddos_attack(packet))  # אחרי מעבר הסף

    """
    def test_sql_injection_detection(self):
        # בדיקת זיהוי SQL Injection
        packet = IP() / TCP() / Raw(load="SELECT * FROM users")
        self.assertTrue(detect_sql_injection(packet))

        packet = IP() / TCP() / Raw(load="Hello World")
        self.assertFalse(detect_sql_injection(packet))
"""

if __name__ == "__main__":
    unittest.main()
