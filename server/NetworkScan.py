import scapy.all as scapy
import requests
import logging
import time
import threading
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

# Ensure the reports directory exists
REPORTS_DIR = "/reports/network/"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Function to generate a new log filename every 10 minutes
def get_log_filename():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return os.path.join(REPORTS_DIR, f"network_scan_{timestamp}.log")

# Setup logging
log_filename = get_log_filename()
def setup_logging():
    global log_filename
    log_filename = get_log_filename()
    logging.basicConfig(filename=log_filename, level=logging.INFO, format="%(asctime)s - %(message)s")
    logger = logging.getLogger()
    logger.handlers.clear()  # Clear existing handlers
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(logging.StreamHandler())  # Print logs to terminal
    return logger

logger = setup_logging()

# Malicious IP List URL
MALICIOUS_IP_LIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

# Fetch Malicious IPs
def fetch_malicious_ips():
    """Fetch the latest malicious IP list"""
    try:
        response = requests.get(MALICIOUS_IP_LIST_URL)
        if response.status_code == 200:
            return set(line.strip() for line in response.text.splitlines() if line and not line.startswith("#"))
    except Exception as e:
        logger.error(f"Failed to fetch malicious IPs: {e}")
    return set()

malicious_ips = fetch_malicious_ips()

def update_malicious_ips():
    """Periodically update the malicious IP list"""
    global malicious_ips
    while True:
        malicious_ips = fetch_malicious_ips()
        logger.info("Updated malicious IP list.")
        time.sleep(600)  # Update every 10 minutes

def rotate_logs():
    """Rotate log files every 10 minutes"""
    while True:
        time.sleep(600)  # Rotate every 10 minutes
        global logger
        logger = setup_logging()
        logger.info("Log file rotated.")

def packet_callback(packet):
    """Process captured packets and check for malicious IPs"""
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        flags = ""

        if packet.haslayer(scapy.TCP):
            flags = packet[scapy.TCP].flags
            if flags == 2:
                flags = "SYN"
            elif flags == 18:
                flags = "SYN-ACK"
        elif packet.haslayer(scapy.UDP):
            flags = "UDP"
        elif packet.haslayer(scapy.ICMP):
            flags = "ICMP"
        else:
            flags = "Unknown"

        alert = src_ip in malicious_ips or dst_ip in malicious_ips
        log_msg = (f"Packet Info: {src_ip} → {dst_ip} | Protocol: {protocol} | Flags: {flags} | "
                   f"Status: {'MALICIOUS' if alert else 'SAFE'}")
        logger.info(log_msg)
        
        if alert:
            logger.warning(f"{Fore.RED}[ALERT] Malicious IP Detected: {src_ip} → {dst_ip}{Style.RESET_ALL}")

if __name__ == "__main__":
    logger.info("Starting detailed network monitoring...")
    threading.Thread(target=update_malicious_ips, daemon=True).start()
    threading.Thread(target=rotate_logs, daemon=True).start()
    scapy.sniff(prn=packet_callback, store=False, filter="ip")