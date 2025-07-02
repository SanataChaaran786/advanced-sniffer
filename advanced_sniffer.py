from collections import Counter

protocol_counter = Counter()
dest_ip_counter = Counter()
import csv
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
from functools import lru_cache
import requests
import argparse
import signal
import sys
import os

# Setup log file
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"packet_log_{timestamp}.txt"
log = open(log_file, "w")

# Create CSV file for logging
csv_file = open(f"packet_log_{timestamp}.csv", "w", newline="")
csv_writer = csv.writer(csv_file)

# Write the header row
csv_writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Dest Port", "Location"])

# Alert tracking
packet_count = defaultdict(int)
port_access = defaultdict(set)
last_alert_time = {}

# Geolocation function with caching
@lru_cache(maxsize=100)
def get_ip_location(ip):
    try:
        # Ignore private/local IPs
        if ip.startswith(("192.", "10.", "172.", "127.")):
            return "Local Network"
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        data = res.json()
        return f"{data.get('org', 'Unknown')}, {data.get('country', 'Unknown')}"
    except:
        return "Unknown"

# Packet Handler
def packet_handler(packet):
    if IP in packet:
        protocol_name = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        protocol_counter[protocol_name] += 1

        dst_ip = packet[IP].dst
        dest_ip_counter[dst_ip] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        location = get_ip_location(dst_ip)

        log_line = f"{src_ip} -> {dst_ip} | {location} | Protocol: {proto}"

        sport = dport = ''  # Initialize to empty
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            log_line += f" | TCP: {sport} -> {dport}"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            log_line += f" | UDP: {sport} -> {dport}"

        print(log_line)
        log.write(log_line + "\n")
        

        # Add this part to write to CSV
        timestamp_now = datetime.now().strftime("%H:%M:%S")
        csv_writer.writerow([
            timestamp_now,
            src_ip,
            dst_ip,
            "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
            sport,
            dport,
            location
        ])
# Graceful shutdown
def stop_sniffer(signal, frame):
    print("\n[!] Sniffing stopped by user.")
    log.close()
    csv_file.close()
    sys.exit(0)

signal.signal(signal.SIGINT, stop_sniffer)

# Command-line arguments
parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
parser.add_argument("-i", "--iface", help="Network interface (e.g., Wi-Fi)", default=None)
parser.add_argument("-c", "--count", help="Number of packets to capture (0 = unlimited)", type=int, default=0)
args = parser.parse_args()

# Start sniffing
print("[*] Sniffing started... Press Ctrl+C to stop.")
sniff(prn=packet_handler, iface=args.iface, count=args.count if args.count > 0 else 0)

# Stop sniffer
def stop_sniffer(signal, frame):
    print("\n[!] Sniffing stopped by user.")
    log.close()
    csv_file.close()  
    sys.exit(0)
print("\n===== TRAFFIC SUMMARY =====")
total_packets = sum(protocol_counter.values())
print(f"Total Packets: {total_packets}")

print("\nTop 5 Destination IPs:")
for ip, count in dest_ip_counter.most_common(5):
    print(f" - {ip}: {count} packets")

print("\nProtocol Usage:")
for proto, count in protocol_counter.items():
    print(f" - {proto}: {count} packets")
print("===========================\n")