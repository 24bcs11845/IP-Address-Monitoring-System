import unittest
from unittest.mock import patch

from scapy.all import IP, TCP, ICMP
import monitor


class DetectorTests(unittest.TestCase):

    def setUp(self):
        self.detector = monitor.Detector()
        self.alerts = []

        self.old_detector = monitor.detector
        self.old_ips = monitor.LOCAL_IPS

        monitor.detector = self.detector
        monitor.LOCAL_IPS = set()

        self.addCleanup(
            setattr, monitor, "detector", self.old_detector
        )
        self.addCleanup(
            setattr, monitor, "LOCAL_IPS", self.old_ips
        )

        p = patch.object(
            monitor,
            "save_alert",
            side_effect=lambda ip, rule, severity, desc:
                self.alerts.append(rule)
        )
        p.start()
        self.addCleanup(p.stop)

    def tcp(self, port, flags=2):
        packet = (
            IP(src="192.168.200.130",
               dst="192.168.200.131")
            / TCP(dport=port, flags=flags)
        )
        monitor.on_packet(packet)

    def test_scan_triggers_only_r01(self):
        for port in range(1, 17):
            self.tcp(port)

        self.assertEqual(self.alerts, ["R-01"])

    def test_syn_flood_triggers_only_r03(self):
        for _ in range(101):
            self.tcp(80)

        self.assertEqual(self.alerts, ["R-03"])

    def test_80_syn_packets_are_quiet(self):
        for _ in range(80):
            self.tcp(80)

        self.assertEqual(self.alerts, [])

    def test_130_syn_packets_trigger_r03(self):
        for _ in range(130):
            self.tcp(80)

        self.assertEqual(self.alerts, ["R-03"])

    def test_xmas_triggers_only_r05(self):
        for _ in range(3):
            self.tcp(80, 0x29)

        self.assertEqual(self.alerts, ["R-05"])

    def test_echo_replies_are_ignored(self):
        for _ in range(130):
            packet = (
                IP(src="192.168.200.130",
                   dst="192.168.200.131")
                / ICMP(type=0)
            )
            monitor.on_packet(packet)

        self.assertEqual(self.alerts, [])

    def test_echo_requests_trigger_r04(self):
        for _ in range(101):
            packet = (
                IP(src="192.168.200.130",
                   dst="192.168.200.131")
                / ICMP(type=8)
            )
            monitor.on_packet(packet)

        self.assertEqual(self.alerts, ["R-04"])

    def test_legitimate_flags_never_trigger_r05(self):
        for flags in (0x12, 0x10, 0x18, 0x11, 0x04, 0x14):
            self.assertFalse(
                self.detector.is_illegal_flags(flags)
            )

    def test_history_is_bounded(self):
        for _ in range(3000):
            self.detector.check_port_scan(
                "192.168.200.130", 80, now=1000
            )

        self.assertEqual(
            len(self.detector.port_history["192.168.200.130"]),
            monitor.HISTORY_CAP
        )


if __name__ == "__main__":
    unittest.main()
