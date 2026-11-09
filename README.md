# Basic Network Sniffer

A beginner-friendly Python project that captures packets and displays basic network metadata using Scapy.

## Features

- Live packet capture (up to 50 packets by default)
- IPv4 and IPv6 source/destination addresses
- TCP, UDP and ICMP identification
- Source and destination ports for TCP/UDP
- DNS packet indication
- Packet size and a short payload preview
- Ctrl+C to stop capture early

## Requirements

- Python 3.9 or newer
- Scapy
- Windows users: Npcap (https://npcap.com/)

## Installation

Open a terminal in this project folder and run:

```bash
python -m pip install -r requirements.txt
```

On Windows, install Npcap using its official installer. If prompted, enable WinPcap API-compatible mode.

## Run

Windows: open PowerShell or VS Code as Administrator, then run:

```bash
python network_sniffer.py
```

Linux/macOS: packet capture may require elevated privileges:

```bash
sudo python3 network_sniffer.py
```

## How to test

1. Start the sniffer.
2. Open a website or perform a normal network activity on your own device.
3. Observe source/destination IPs, protocols and ports.
4. Press Ctrl+C to stop before 50 packets if desired.

## Safety and privacy

Only capture traffic on devices and networks you own or are explicitly authorized to monitor. Packet payloads can contain private data. This project displays only a short payload preview and does not decrypt HTTPS/TLS traffic or collect credentials.
