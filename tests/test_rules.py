import unittest
from collections import defaultdict  # ייבוא defaultdict
from scapy.all import IP, TCP
from scapy.packet import Raw

from core.rules import detect_port_scan, TIME_WINDOW, detect_sql_injection, detect_xss
from datetime import datetime, timedelta


# יצירת מחלקה לבדיקות
class TestRules(unittest.TestCase):
    """
    Unit test class for testing various security rules.
    """

    def setUp(self):
        """
        Set up the testing environment.

        This method is called before each test case.
        It initializes global variables used for tracking packets and events.
        """
        global syn_tracker, packet_tracker
        syn_tracker = defaultdict(list)
        packet_tracker = defaultdict(list)

    def test_port_scan_detection(self):
        """
        Test the detection of port scans.

        This test sends multiple packets to the same destination port
        to simulate a port scan and checks if it is detected.
        """
        for _ in range(11):  # Test with more than the threshold of 10 packets
            packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
            result = detect_port_scan(packet)
        self.assertTrue(result, "Port scan detection failed")

    def test_sql_injection_detection(self):
        """
        Test the detection of SQL Injection attacks.

        This test checks for the presence of SQL injection patterns
        in packet payloads.
        """
        packet = IP() / TCP() / Raw(load="SELECT * FROM users")
        self.assertTrue(detect_sql_injection(packet))

        packet = IP() / TCP() / Raw(load="Hello World")
        self.assertFalse(detect_sql_injection(packet))

    def test_xss_detection(self):
        """
        Test the detection of Cross-Site Scripting (XSS) attacks.

        This test checks for common XSS patterns in packet payloads.
        """
        # Test XSS detection
        packet = IP() / TCP() / Raw(load="<script>alert('XSS')</script>")
        self.assertTrue(detect_xss(packet))

        packet = IP() / TCP() / Raw(load="<img src='javascript:alert(\"XSS\")')>")
        self.assertTrue(detect_xss(packet))

        packet = IP() / TCP() / Raw(load="Normal text without XSS")
        self.assertFalse(detect_xss(packet))


if __name__ == "__main__":
    unittest.main()
