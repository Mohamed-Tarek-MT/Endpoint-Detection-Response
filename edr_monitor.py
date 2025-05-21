import time
import threading
import requests
from collections import defaultdict
from scapy.all import sniff, IP, ICMP, AsyncSniffer
import subprocess
from datetime import datetime

# Configuration
ICMP_THRESHOLD = 40  # Packets per second
BLOCK_DURATION = 0   # 0 means block forever
ALERT_SERVER = "http://10.0.0.8:5000/agent"
MONITOR_INTERFACE = "ens37"  # UPDATE THIS TO YOUR ACTIVE INTERFACE
WHITELIST = {"192.168.100.10", "10.0.0.8"}  # trusted IPs here

# Global state
icmp_counts = defaultdict(int)
blocked_ips = set()
lock = threading.Lock()

def block_ip(ip):
    if ip in blocked_ips:
        return
    subprocess.call(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    subprocess.call(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
    subprocess.call(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    print(f"[+] Blocked IP {ip} using iptables.")
    blocked_ips.add(ip)

def send_alert(ip, pps):
    alert = {
        "source_ip": ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": f"High ICMP rate: {pps} pps"
    }
    try:
        response = requests.post(ALERT_SERVER, json=alert)
        if response.status_code == 200:
            print(f"[+] Alert sent for IP {ip}")
        else:
            print(f"[!] Failed to send alert for {ip}: {response.status_code}")
    except Exception as e:
        print(f"[!] Exception while sending alert for {ip}: {e}")

def process_packet(packet):
    if IP in packet and ICMP in packet:
        src_ip = packet[IP].src
        with lock:
            icmp_counts[src_ip] += 1

def monitor_traffic():
    print("[*] Starting ICMP traffic monitor... Press Ctrl+C to stop.")
    try:
        def loop():
            while True:
                time.sleep(1)
                with lock:
                    for ip, count in icmp_counts.items():
                        if ip in WHITELIST:
                            continue
                        if count > ICMP_THRESHOLD and ip not in blocked_ips:
                            print(f"[!] High ICMP rate detected from {ip}: {count} pps")
                            block_ip(ip)
                            send_alert(ip, count)
                    icmp_counts.clear()

        sniffer = AsyncSniffer(iface=MONITOR_INTERFACE, filter="icmp", prn=process_packet, store=False)
        sniffer.start()

        monitor_thread = threading.Thread(target=loop, daemon=True)
        monitor_thread.start()

        while monitor_thread.is_alive():
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] Stopping ICMP monitor and sniffer...")
        sniffer.stop()
        exit(0)

if __name__ == "__main__":
    monitor_traffic()
