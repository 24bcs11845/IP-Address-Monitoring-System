"""
IP Address Monitoring System — MINIMAL CORE VERSION
======================================================
This is the smallest honest version of the project: it watches live
network traffic and flags any single IP address that contacts an
unusually large number of different ports in a short time window
(a classic port-scan signature).

That's it. One rule. No GeoIP, no threat-intel API, no machine
learning, no dashboard. Everything else in the full project report
builds ON TOP of this same core idea — this file is the part you
should be able to explain line by line, out loud, from memory.

HOW IT WORKS (in plain terms)
------------------------------
1. Watch every packet going in/out of the network interface.
2. For each packet, note: which IP sent it, and which port it went to.
3. Keep a short-term memory per IP: "which ports has this IP touched
   in the last 10 seconds?"
4. If that count crosses a threshold (15 ports), print an alert.

HOW TO RUN
----------
    pip install scapy --break-system-packages
    sudo python3 basic_monitor.py

Then, from another machine (or your Kali VM), run:
    nmap -sS -p 1-100 <this_machine_ip>

Watch the alert print within a few seconds.
"""

from collections import defaultdict, deque
import time
from scapy.all import sniff, IP, TCP

# ---- The only two settings that matter -------------------------------
PORT_THRESHOLD = 15    # how many different ports = suspicious
TIME_WINDOW = 10        # within how many seconds

# ---- Memory: for each IP, remember the ports it recently contacted ----
activity = defaultdict(deque)   # { "192.168.1.5": deque[(time, port), ...] }
already_alerted = set()         # IPs we've already flagged, so we don't spam


def check_for_port_scan(src_ip, dst_port):
    """Core detection logic — everything in this project builds on this idea."""
    now = time.time()
    history = activity[src_ip]

    # Step A: remember this connection
    history.append((now, dst_port))

    # Step B: forget anything older than our time window
    while history and now - history[0][0] > TIME_WINDOW:
        history.popleft()

    # Step C: how many DIFFERENT ports has this IP touched recently?
    distinct_ports = {port for _, port in history}

    # Step D: if it's a lot, and we haven't already said so, raise an alert
    if len(distinct_ports) > PORT_THRESHOLD and src_ip not in already_alerted:
        print(f"[ALERT] {src_ip} contacted {len(distinct_ports)} different "
              f"ports in the last {TIME_WINDOW} seconds — possible port scan")
        already_alerted.add(src_ip)


def on_packet_received(packet):
    """Called automatically by Scapy for every packet captured."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        check_for_port_scan(packet[IP].src, packet[TCP].dport)


if __name__ == "__main__":
    print("Monitoring started. Watching for port scans...")
    print("Press Ctrl+C to stop.\n")
    sniff(iface="ens33", prn=on_packet_received, filter="tcp", store=False)
