import os
import time
import subprocess
import sqlite3
import logging
from colorama import Fore, Style, init
from multiprocessing import Process, Queue
from tqdm import tqdm

# Initialize colorama
init()

# Setup logging
logging.basicConfig(filename="system_scan.log", level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())  # Print logs to terminal

# Constants
DB_FILE = "services.db"

# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            port INTEGER PRIMARY KEY,
            service TEXT,
            version TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Fetch running services on open ports
def get_service_info(port):
    try:
        service = subprocess.getoutput(f"netstat -an | grep {port}")
        return service if service else "Unknown"
    except:
        return "Unknown"

# Update Database
def update_database(port, service):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM services WHERE port=?", (port,))
    result = cursor.fetchone()
    if result:
        existing_service = result[0]
        if existing_service != service:
            logger.info(f"{Fore.YELLOW}[UPDATE] Port {port} service changed to {service}{Style.RESET_ALL}")
            cursor.execute("UPDATE services SET service=?, last_updated=CURRENT_TIMESTAMP WHERE port=?", (service, port))
    else:
        cursor.execute("INSERT INTO services (port, service) VALUES (?, ?)", (port, service))
        logger.info(f"{Fore.GREEN}[NEW] Port {port} running {service} added to database.{Style.RESET_ALL}")
    conn.commit()
    conn.close()

# Port Scanner Process
def scan_open_ports(queue):
    while True:
        open_ports = {}
        result = subprocess.getoutput("netstat -tuln").split("\n")
        for line in result:
            parts = line.split()
            if len(parts) > 3 and parts[0] in ["tcp", "udp"]:
                port = int(parts[3].split(":")[-1])
                service = get_service_info(port)
                open_ports[port] = service
                update_database(port, service)
        queue.put(("ports", open_ports))
        for _ in tqdm(range(10), desc="Scanning in progress", unit="s"):
            time.sleep(1)

# Main Process for Displaying Data
def display_results(queue):
    clear_screen = lambda: os.system("clear" if os.name == "posix" else "cls")
    data = {"ports": {}}
    while True:
        try:
            key, value = queue.get()
            data[key] = value
            clear_screen()
            print(Fore.CYAN + "\n===== SYSTEM SCAN RESULTS =====" + Style.RESET_ALL)
            print(Fore.YELLOW + "\n[ OPEN PORTS & SERVICES ]" + Style.RESET_ALL)
            print("-" * 40)
            for port, service in sorted(data["ports"].items()):
                print(f"{Fore.GREEN}Port {port:<5} | Service: {service}{Style.RESET_ALL}")
            print("-" * 40)
            time.sleep(5)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    init_db()
    queue = Queue()
    Process(target=scan_open_ports, args=(queue,)).start()
    display_results(queue)
