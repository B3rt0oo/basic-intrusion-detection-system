# Basic Intrusion Detection System (IDS)
# Detects port scans and suspicious activity
# Logs alerts in real-time

from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import logging

# Configure logging
logging.basicConfig(filename="alerts.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Track connection attempts
connection_attempts = defaultdict(list)

# IDS thresholds
PORT_SCAN_THRESHOLD = 1  # Number of unique ports in the time window
TIME_WINDOW = 30           # Seconds

def detect_intrusion(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        timestamp = time.time()

        # Record attempt
        connection_attempts[src_ip].append((dst_port, timestamp))

        # Keep only recent attempts
        recent_attempts = [p for p in connection_attempts[src_ip] if timestamp - p[1] <= TIME_WINDOW]
        connection_attempts[src_ip] = recent_attempts

        # Check for port scan
        unique_ports = set(p[0] for p in recent_attempts)
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            alert_msg = f"[ALERT] Possible Port Scan from {src_ip}! Ports: {list(unique_ports)}"
            print(alert_msg)
            logging.info(alert_msg)

def start_ids():
    print("Basic Intrusion Detection System Started...")
    sniff(prn=detect_intrusion, store=False)

if __name__ == "__main__":
    start_ids()
