import psutil
import time
import os
import threading
import requests
import subprocess
from collections import defaultdict, Counter
from scapy.all import sniff, TCP, IP, ICMP

# ==============================
# banner :)
# ==============================
ASCII_BANNER = r"""
 _______ .-. .-.,---.    ,---.    .--.  _______ 
|__   __|| | | || .-.\   | .-'   / /\ \|__   __|
  )| |   | `-' || `-'/   | `-.  / /__\ \ )| |   
 (_) |   | .-. ||   (    | .-'  |  __  |(_) |   
   | |   | | |)|| |\ \   |  `--.| |  |)|  | |   
   `-'   /(  (_)|_| \)\  /( __.'|_|  (_)  `-'   
        (__)        (__)(__)                    
   .---.   ,--,  .---.  ,---.  ,---.            
  ( .-._).' .') / .-. ) | .-.\ | .-'            
 (_) \   |  |(_)| | |(_)| |-' )| `-.            
 _  \ \  \  \   | | | | | |--' | .-'            
( `-'  )  \  `-.\ `-' / | |    |  `--.          
 `----'    \____\)---'  /(     /( __.'          
                (_)    (__)   (__)              
  GitHub: Usernamerobot
"""


# GLOBAL CONFIG 🙂

HAIR_TRIGGER = True
AUTO_BLOCK = True
BASELINE_SECONDS = 20
MAX_EVENTS = 8
KNOWN_BAD_IPS = set()


syn_count = 0
icmp_count = 0
outbound_count = 0
external_ip_counter = Counter()
ip_port_map = defaultdict(set)
baseline_connections = 0
baseline_bandwidth = 0
learning_mode = True
previous_threat = "SAFE"
event_log = []
spinner_states = ["|", "/", "-", "\\"]
spinner_index = 0


# FIREWALL BLOCK 

def block_ip(ip):
    rule_name = f"AutoBlock_{ip}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    subprocess.call(cmd, shell=True)


# GEOIP CHECK

def get_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"


def packet_callback(packet):
    global syn_count, icmp_count, outbound_count, external_ip_counter, ip_port_map
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(ICMP):
            icmp_count += 1

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags == "S":
                syn_count += 1
            ip_port_map[ip_dst].add(tcp.dport)

        if not ip_dst.startswith(("192.168.", "10.", "172.")):
            outbound_count += 1
            external_ip_counter[ip_dst] += 1

def start_sniffer():
    sniff(prn=packet_callback, store=False)


# LOGGING

def log_event(message):
    timestamp = time.strftime("%H:%M:%S")
    event_log.insert(0, f"{timestamp} {message}")
    if len(event_log) > MAX_EVENTS:
        event_log.pop()

# 
# "UI"
# 
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def draw_dashboard(threat, upload, download, connections):
    global spinner_index
    spinner = spinner_states[spinner_index % len(spinner_states)]
    spinner_index += 1
    clear()
    print("+------------------------------------------------------------+")
    print(f"| Threat Level: {threat:<42}|")
    print(f"| Upload: {upload:>6.2f} MB/s{' ' * 35}|")
    print(f"| Download: {download:>6.2f} MB/s{' ' * 33}|")
    print(f"| Connections: {connections:<38}|")
    print(f"| SYN/sec: {syn_count:<43}|")
    print(f"| ICMP/sec: {icmp_count:<42}|")
    print(f"| Outbound/sec: {outbound_count:<39}|")
    top_ip, count = ("None", 0)
    if external_ip_counter:
        top_ip, count = external_ip_counter.most_common(1)[0]
    print(f"| Top IP: {top_ip} ({count} pkts)               |")
    print(f"| Spinner: {spinner:<46}|")
    print("|------------------------------------------------------------|")
    print("| Events:                                                    |")
    if event_log:
        for e in event_log:
            print(f"| {e:<58}|")
    else:
        print("| No recent events                                           |")
    print("+------------------------------------------------------------+")


# SETUP SCREEN
 
def setup_wizard():
    global HAIR_TRIGGER, AUTO_BLOCK, KNOWN_BAD_IPS, BASELINE_SECONDS
    clear()
    
    # Print cool looking banner
    print(ASCII_BANNER)
    
    print("=== Network Threat Monitor Setup ===\n")
    
    # "Hair trigger" option
    choice = input("Enable hair-trigger detection? (y/n) [y]: ").strip().lower()
    HAIR_TRIGGER = choice != "n"

    # ip block option
    choice = input("Enable auto-block for suspicious IPs? (y/n) [y]: ").strip().lower()
    AUTO_BLOCK = choice != "n"

    # Known bad IPs
    ips = input("Enter known malicious IPs separated by commas (or leave blank): ").strip()
    if ips:
        KNOWN_BAD_IPS = set(ip.strip() for ip in ips.split(","))

    # Baseline time 🙂
    secs = input(f"Set baseline learning duration in seconds [default {BASELINE_SECONDS}]: ").strip()
    if secs.isdigit():
        BASELINE_SECONDS = int(secs)

    print("\nNext, baseline learning will start.")
    print(f"Use your computer normally for {BASELINE_SECONDS} seconds.\n")
    for i in range(BASELINE_SECONDS, 0, -1):
        print(f"Starting baseline in: {i} seconds", end="\r")
        time.sleep(1)
    print("Baseline learning starting now...\n")
    time.sleep(1)


# main loop

def main():
    global syn_count, icmp_count, outbound_count
    global external_ip_counter, ip_port_map
    global baseline_connections, baseline_bandwidth
    global learning_mode, previous_threat, BASELINE_SECONDS

    setup_wizard()

    thread = threading.Thread(target=start_sniffer, daemon=True)
    thread.start()

    old_net = psutil.net_io_counters()
    start_time_baseline = time.time()

    while True:
        new_net = psutil.net_io_counters()
        upload = (new_net.bytes_sent - old_net.bytes_sent) / 1024 / 1024
        download = (new_net.bytes_recv - old_net.bytes_recv) / 1024 / 1024
        old_net = new_net

        connections = len(psutil.net_connections())
        score = 0

        # BASELINE
        if learning_mode:
            baseline_connections += connections
            baseline_bandwidth += download
            if time.time() - start_time_baseline >= BASELINE_SECONDS:
                baseline_connections /= BASELINE_SECONDS
                baseline_bandwidth /= BASELINE_SECONDS
                learning_mode = False
                log_event("Baseline established")
        else:
            if connections > baseline_connections * 1.5:
                score += 2
                log_event(f"Connection spike: {connections} (baseline {baseline_connections:.1f})")
            if download > baseline_bandwidth * 2:
                score += 2
                log_event(f"Bandwidth anomaly: Download={download:.2f} MB/s (baseline {baseline_bandwidth:.2f})")

        # "HAIR TRIGGER"
        if HAIR_TRIGGER:
            if syn_count > 5:
                score += 2
                log_event(f"SYN spike: {syn_count} SYN/sec")
            if icmp_count > 5:
                score += 1
                log_event(f"ICMP spike: {icmp_count} pkts/sec")
            if outbound_count > 10:
                score += 2
                log_event(f"Outbound spike: {outbound_count} pkts/sec")

            if external_ip_counter:
                top_ip, count = external_ip_counter.most_common(1)[0]
                if count > 15:
                    score += 3
                    log_event(f"External IP dominance: {top_ip} ({count} pkts)")
                    if AUTO_BLOCK:
                        block_ip(top_ip)
                        log_event(f"AUTO-BLOCKED {top_ip}")
                    country = get_country(top_ip)
                    log_event(f"Country: {country}")
                    if country not in ("United States", "Canada", "United Kingdom"):
                        score += 2
                        log_event("Suspicious country detected")
                if top_ip in KNOWN_BAD_IPS:
                    score += 5
                    log_event("Known malicious IP detected")

        # "THREAT LEVEL"
        if score >= 6:
            threat = "HIGH"
        elif score >= 2:
            threat = "ELEVATED"
        else:
            threat = "SAFE"

        if threat != previous_threat:
            log_event(f"Threat changed: {previous_threat} -> {threat}")
            previous_threat = threat

        draw_dashboard(threat, upload, download, connections)

        # Reset per second counters
        syn_count = 0
        icmp_count = 0
        outbound_count = 0
        external_ip_counter.clear()
        ip_port_map.clear()

        time.sleep(1)

if __name__ == "__main__":
    main()
