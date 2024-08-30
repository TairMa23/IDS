import unittest
from scapy.all import IP, TCP
from core.packet_capture import analyze_packet

class TestPacketCapture(unittest.TestCase):
    def test_port_scan_detection(self):
        packet = IP(dst="127.0.0.1")/TCP(dport=80, flags="S")
        self.assertTrue(analyze_packet(packet))

if __name__ == "__main__":
    unittest.main()
