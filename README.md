# Specter

Specter is a dynamic WiFi network analysis tool crafted in Python, utilizing Scapy's powerful packet processing capabilities. It offers real-time scanning of WiFi environments, providing detailed insights into each network. Its core functionality lies in identifying rogue access points, a crucial aspect for network security. Specter is designed for network administrators, security professionals, and enthusiasts interested in wireless network integrity and security.

## Features

- Real-Time WiFi Scanning: Monitors WiFi networks in your vicinity, capturing essential details like SSID, BSSID, channel, and signal strength.
- Rogue Access Point (AP) Detection: Efficiently spots unauthorized or rogue APs, critical for preventing security breaches.
- MAC Address Spoofing: Anonymizes your monitoring device by changing its MAC address.
- Adaptive Channel Hopping: Seamlessly navigates through various WiFi channels, enhancing the scope of network discovery.
- Vendor Information Retrieval: Fetches and displays manufacturer details for network devices.
- Resilient Data Logging: Saves rogue AP data automatically, preventing loss of information during unexpected script terminations or crashes.

## Installation

```bash
git clone https://github.com/UncleJ4ck/specter.git
cd specter
pip3 install -r requirements.txt
```

## Usage

Before running Specter, ensure you have the necessary permissions to manipulate network interfaces and capture network traffic.

```bash

sudo python specter.py <wireless_interface> <known_networks.json> <secondary_wireless_interface>

    <wireless_interface>: Your wireless network interface name.
    <known_networks.json>: A JSON file containing details of known networks for rogue AP detection.
    <secondary_wireless_interface>: Your secondary wireless network interface name.

```

## Testing

![img1](/img/img1.png)

> Creating an experimental EvilTwin using Airegeddon

![img2](/img/img2.png)

> Detecting the simple eviltwil using spectre

Tested on:
- Ubuntu 22.04
- PopOS
- Raspberry PI 3 Model B+
  
## TO-DO

- [ ] Add detection of other attack vectors
- [x] Switching between two interfaces
- [ ] Add deauthentication as a defensive mechanism
- [x] Multithreading
- [x] Fixing Bugs
- [x] Mac Spoofing
- [x] Karma Attacks Detection
- [x] Logging 
