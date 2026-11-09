from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

PACKET_LIMIT = 50
PAYLOAD_PREVIEW_BYTES = 32
packet_count = 0


def analyze_packet(packet):
    """Print a safe, concise summary of one captured packet."""
    global packet_count
    packet_count += 1

    print("\n" + "=" * 68)
    print(f"PACKET NUMBER : {packet_count}")
    print(f"TIME          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ip_layer = packet[IP] if IP in packet else (
        packet[IPv6] if IPv6 in packet else None
    )

    if ip_layer is None:
        print("Network layer : Non-IP packet")
        print("Summary       :", packet.summary())
        return

    print(f"Source IP     : {ip_layer.src}")
    print(f"Destination IP: {ip_layer.dst}")
    print(f"IP Version    : {ip_layer.version}")
    print(f"Packet Size   : {len(packet)} bytes")

    if TCP in packet:
        transport = packet[TCP]
        print("Protocol      : TCP")
        print(f"Source Port   : {transport.sport}")
        print(f"Destination Port: {transport.dport}")
    elif UDP in packet:
        transport = packet[UDP]
        print("Protocol      : UDP")
        print(f"Source Port   : {transport.sport}")
        print(f"Destination Port: {transport.dport}")
    elif ICMP in packet:
        print("Protocol      : ICMP")
    else:
        print(f"Protocol      : IP protocol number {ip_layer.proto}")

    if DNS in packet:
        print("DNS           : Yes")

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        preview = payload[:PAYLOAD_PREVIEW_BYTES]
        print(f"Payload length: {len(payload)} bytes")
        print("Payload (hex) :", preview.hex())
        print("Payload (text):", repr(
            preview.decode("utf-8", errors="replace")
        ))
        if len(payload) > PAYLOAD_PREVIEW_BYTES:
            print("Payload       : Preview truncated")


def start_sniffer():
    print("=" * 68)
    print("                 BASIC PYTHON NETWORK SNIFFER")
    print("=" * 68)
    print(f"Capturing up to {PACKET_LIMIT} packets.")
    print("Press Ctrl+C to stop early.")
    print("Use only on your own device/network or with explicit permission.")
    print("=" * 68)

    try:
        sniff(prn=analyze_packet, count=PACKET_LIMIT, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("\nPermission denied. Run the terminal as Administrator.")
    except Exception as exc:
        print(f"\nCapture error: {exc}")
        print("On Windows, check that Npcap is installed and running.")


if __name__ == "__main__":
    start_sniffer()
