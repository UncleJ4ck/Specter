import os
import sys
import time
import re
import requests
import random
import subprocess
import json
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11EltRSN, Dot11EltMicrosoftWPA
from threading import Thread, Lock

CHANNELS_2_4_GHZ = range(1, 15)
CHANNELS_5_GHZ = range(36, 166, 4)
CHANNELS_6_GHZ = range(1, 234)

print_lock = Lock()
current_channel = None
networks = {}
vendor_cache = {}
rogue_aps = {}

def run_command(command):
    try:
        subprocess.run(command, check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        
def is_rogue(ssid, bssid, encryption, vendor, known_networks):
    ssid = ssid.lower()
    bssid = bssid.lower()
    encryption = encryption.lower()
    vendor = vendor.lower()
    ssid_listed = any(network['ssid'].lower() == ssid for network in known_networks)
    if not ssid_listed:
        return False
    for network in known_networks:
        known_ssid = network['ssid'].lower()
        known_bssid = network['bssid'].lower()
        known_vendor = network['vendor'].lower()
        if known_ssid == ssid and known_bssid == bssid and known_vendor == vendor:
            return False
    return True


def set_monitor_mode(interface):
    run_command(["sudo", "ip", "link", "set", interface, "down"])
    run_command(["sudo", "iw", interface, "set", "monitor", "none"])
    run_command(["sudo", "ip", "link", "set", interface, "up"])

def load_known_networks(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Known networks file not found: {file_path}")
        return {}

def get_manufacturer(bssid):
    if bssid in vendor_cache:
        return vendor_cache[bssid][:20]
    try:
        response = requests.get(f'http://api.macvendors.com/{bssid}')
        vendor = response.text.strip()
        if "errors" in vendor or len(vendor) == 0:
            vendor = 'NOT FOUND'
    except requests.exceptions.RequestException:
        vendor = 'NOT FOUND'
    vendor_cache[bssid] = vendor
    return vendor[:20]

def change_mac(interface):
    print("Changing MAC address...")
    new_mac = "00:10:FF:" + ':'.join(f"{random.randint(0, 255):02x}" for _ in range(3)).upper()
    run_command(["sudo", "ip", "link", "set", interface, "down"])
    run_command(["sudo", "ip", "link", "set", interface, "address", new_mac])
    run_command(["sudo", "ip", "link", "set", interface, "up"])
    print(f"New MAC address: {new_mac}")

def get_wireless_frequency(interface):
    try:
        iwconfig_output = subprocess.check_output(["iwconfig", interface]).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Failed to get wireless frequency: {e}")
        return None

    match = re.search(r'Frequency:(\d+\.\d+) GHz', iwconfig_output)
    return float(match.group(1)) if match else None

def channel_hopper(interface, channels):
    global current_channel
    while True:
        for channel in channels:
            current_channel = channel
            run_command(["iwconfig", interface, "channel", str(channel)])
            time.sleep(1)

def extract_cipher_suites(packet):
    ciphers = set()
    if packet.haslayer(Dot11EltRSN):
        rsn = packet[Dot11EltRSN]
        for suite in rsn.pairwise_cipher_suites:
            if suite.cipher == 2:
                ciphers.add("TKIP")
            elif suite.cipher == 4:
                ciphers.add("CCMP")
        group_suite = rsn.group_cipher_suite
        if group_suite.cipher == 2:
            ciphers.add("TKIP")
        elif group_suite.cipher == 4:
            ciphers.add("CCMP")
    return '/'.join(ciphers)

def parse_encryption(packet):
    crypto = set()
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%} {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if re.search("privacy", capability):
            crypto.add("WPA/WPA2")
        p = packet
        while isinstance(p, Dot11Elt):
            if p.ID == 0 and "ssid" not in crypto:
                pass
            elif isinstance(p, Dot11EltRSN):
                wpa_version = "WPA2"
                if any(x.suite == 8 for x in p.akm_suites) and \
                        all(x.suite not in [2, 6] for x in p.akm_suites) and \
                        p.mfp_capable and p.mfp_required and \
                        all(x.cipher not in [1, 2, 5] for x in p.pairwise_cipher_suites):
                    wpa_version = "WPA3"
                elif any(x.suite == 8 for x in p.akm_suites) and \
                        any(x.suite == 2 for x in p.akm_suites) and \
                        p.mfp_capable and not p.mfp_required:
                    wpa_version = "WPA3-transition"
                if p.akm_suites:
                    auth = p.akm_suites[0].sprintf("%suite%")
                    crypto.add(wpa_version + "/%s" % auth)
                else:
                    crypto.add(wpa_version)
            elif p.ID == 221 and isinstance(p, Dot11EltMicrosoftWPA):
                if p.akm_suites:
                    auth = p.akm_suites[0].sprintf("%suite%")
                    crypto.add("WPA/%s" % auth)
                else:
                    crypto.add("WPA")
            p = p.payload
        if not crypto and hasattr(packet, 'cap') and packet.cap.privacy:
            crypto.add("WEP")
    return '/'.join(crypto) if crypto else "Open"

def extract_tsf(packet):
    if packet.haslayer(Dot11Beacon):
        tsf = packet[Dot11Beacon].timestamp
    elif packet.haslayer(Dot11ProbeResp):
        tsf = packet[Dot11ProbeResp].timestamp
    else:
        tsf = 'N/A'
    return tsf


def update_networks(ssid, bssid, channel, power, encryption, cipher, tsf, known_networks):
    ssid = ''.join(c if c.isprintable() else '.' for c in ssid) if ssid else "Hidden/Corrupted SSID"
    vendor = get_manufacturer(bssid)
    with print_lock:
        networks[bssid] = {
            'ssid': ssid,
            'channel': channel,
            'power': power,
            'encryption': encryption,
            'cipher': cipher,
            'tsf': tsf,
            'vendor': vendor if vendor != 'NOT FOUND' else "Unknown"
        }
        print_all_networks(known_networks)


def save_rogue_aps():
    with open('rogue_aps.json', 'w') as file:
        json.dump(rogue_aps, file, indent=4)


def print_all_networks(known_networks):
    global current_channel
    global networks
    networks_count = len(networks)
    if networks_count > 41:
        networks.clear()
        print("\033[1;33;40mNetworks list cleared to avoid flooding the terminal.\033[0m\n")
        return
    os.system('clear')
    header_format = "| {:<19} | {:<27} | {:<17} | {:<4} | {:<4} | {:<16} | {:<9} | {:<13} | {:<20} | {:<8} |"
    separator = "-" * 168
    print(f"\033[1;33;40mTotal Networks Found: {networks_count} | Current Channel: {current_channel}\033[0m\n")
    print("\033[1;32;40m" + separator + "\033[0m")
    print("\033[1;32;40m" + header_format.format("Date", "SSID", "BSSID", "CH", "PWR", "ENC", "CIPHER", "TSF", "VENDOR", "Rogue AP") + "\033[0m")
    print(separator)
    sorted_networks = sorted(networks.items(), key=lambda item: item[1]['power'], reverse=True)
    for bssid, info in sorted_networks:
        rogue_status = "YES" if is_rogue(info['ssid'], bssid, info['encryption'], info['vendor'], known_networks) else "NO"
        color = "\033[1;31;40m" if rogue_status == "YES" else "\033[0m"
        tsf_formatted = f"{info['tsf']:.2e}" if isinstance(info['tsf'], int) else info['tsf']
        ssid_display = (info['ssid'][:24] + '...') if len(info['ssid']) > 27 else info['ssid']
        vendor_display = (info['vendor'][:17] + '...') if len(info['vendor']) > 20 else info['vendor']
        print(color + header_format.format(
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ssid_display, bssid.upper(),
            info['channel'], info['power'], info['encryption'], info['cipher'],
            tsf_formatted, vendor_display, rogue_status) + "\033[0m")
    print(separator)

def packet_handler(packet, known_networks):
    global rogue_aps
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore')
            ssid = ssid if ssid.strip() else "Hidden Network"
        except UnicodeDecodeError:
            ssid = "Hidden/Corrupted SSID"
        channel = int(ord(packet[Dot11Elt:3].info))
        power = packet.dBm_AntSignal
        encryption = parse_encryption(packet)
        cipher = extract_cipher_suites(packet)
        tsf = extract_tsf(packet)
        vendor = get_manufacturer(bssid)
        info = {
            'ssid': ssid,
            'channel': channel,
            'power': power,
            'encryption': encryption,
            'cipher': cipher,
            'tsf': tsf,
            'vendor': vendor
        }
        if is_rogue(ssid, bssid, encryption, vendor, known_networks):
            rogue_status = "YES"
            rogue_aps[bssid] = info
        else:
            rogue_status = "NO"
        update_networks(ssid, bssid, channel, power, encryption, cipher, tsf, known_networks)

def run_command(command):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return e

def interface_is_up(interface):
    result = run_command(["ip", "link", "show", "up", interface])
    return result.returncode == 0 if result else False

def get_active_interface(primary_interface, secondary_interface):
    if interface_is_up(primary_interface):
        return primary_interface
    elif interface_is_up(secondary_interface):
        return secondary_interface
    else:
        return None

def sniff_networks(interface, known_networks):
    try:
        sniff(iface=interface, prn=lambda packet: packet_handler(packet, known_networks), store=0)
    except Exception as e:
        print(f"Error sniffing on {interface}: {e}")


def main():
    global current_channel
    if len(sys.argv) < 4:
        print("Usage: python script.py <primary_interface> <known_networks.json> <secondary_interface>")
        sys.exit(1)
    primary_interface = sys.argv[1]
    known_networks_file = sys.argv[2]
    secondary_interface = sys.argv[3]
    known_networks = load_known_networks(known_networks_file)
    try:
        while True:
            active_interface = get_active_interface(primary_interface, secondary_interface)
            if not active_interface:
                print("Both interfaces are down. Exiting.")
                break
            print(f"Using interface {active_interface}")
            set_monitor_mode(active_interface)
            change_mac(active_interface)
            frequency = get_wireless_frequency(active_interface)
            channels = CHANNELS_2_4_GHZ if frequency < 5 else CHANNELS_5_GHZ if frequency < 6 else CHANNELS_6_GHZ
            print(f"Starting WiFi scan on {active_interface}... (Press Ctrl+C to stop)")
            channel_thread = Thread(target=channel_hopper, args=(active_interface, channels), daemon=True)
            channel_thread.start()
            sniff_networks(active_interface, known_networks)
            run_command(["sudo", "ip", "link", "set", active_interface, "down"])
            run_command(["sudo", "iw", active_interface, "set", "type", "managed"])
            run_command(["sudo", "ip", "link", "set", active_interface, "up"])
            time.sleep(1)
    except KeyboardInterrupt:
        print("Saving rogue APs data...")
        save_rogue_aps()
        run_command(["sudo", "iw", active_interface, "set", "type", "managed"])
        run_command(["sudo", "ip", "link", "set", active_interface, "up"])
    print("Saving rogue APs data...")
    save_rogue_aps()

if __name__ == "__main__":
    main()
