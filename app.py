from flask import Flask, render_template, request, jsonify
import socket
import concurrent.futures  # Import for ThreadPoolExecutor
from scapy.all import srp, Ether, ARP, IP, sniff
import time  # Import time module for adding delays
import ipaddress
import threading

app = Flask(__name__)

def scan_network(ip_range):
    print("Scanning network for devices...\n")
    devices = []
    devices_info = []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=10, verbose=False, inter=0.1)  # Add inter parameter for delay between packets
        devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]

        if devices:
            print("Found active devices:")
            for i, (ip, mac) in enumerate(devices, start=1):
                print(f"Device {i}:")
                print(f"  IP Address: {ip}")
                print(f"  MAC Address: {mac}")
                print("  Status: Online")
                open_ports = scan_ports(ip)
                print(f"  Open Ports: {open_ports}")
                print()
                devices_info.append({
                    "ip": ip,
                    "mac": mac,
                    "ports": open_ports
                })
        else:
            print("No active devices found in the specified IP range.")
    except Exception as e:
        print(f"An error occurred during scanning: {str(e)}")

    return devices_info


def scan_ports(ip_address):
    open_ports = []
    print(f"Scanning ports for {ip_address}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for port in range(1, 1025):
            futures.append(executor.submit(scan_port, ip_address, port))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result != -1:
                open_ports.append(result)
    return open_ports

def scan_port(ip_address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)  # Adjust timeout as necessary
        result = s.connect_ex((ip_address, port))
        if result == 0:
            return port
    return -1

# List to store captured packets
captured_packets = []


def packet_handler(pkt, ip_range):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if ip_in_range(src_ip, ip_range) or ip_in_range(dst_ip, ip_range):
            packet_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'summary': pkt.summary(),
                'details': str(pkt.show(dump=True))
            }
            captured_packets.append(packet_info)
            print(f'Captured Packet: {src_ip} -> {dst_ip}')
            if len(captured_packets) > 50:
                captured_packets.pop(0)


def ip_in_range(ip_addr, ip_range):
    try:
        start_ip = ipaddress.IPv4Address(ip_range[0])
        end_ip = ipaddress.IPv4Address(ip_range[1])
        ip_to_check = ipaddress.IPv4Address(ip_addr)
        return start_ip <= ip_to_check <= end_ip
    except Exception:
        return False


def start_sniffing(interface, ip_range, count):
    print(f"Sniffing {count} packets on interface {interface}...")
    try:
        kwargs = {"prn": lambda pkt: packet_handler(pkt, ip_range), "count": count}
        if interface and interface.strip():
            kwargs["iface"] = interface.strip()
        sniff(**kwargs)
    except Exception as e:
        print(f"Sniffing error: {e}")
    print("Sniffing complete.")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/capture')
def capture():
    return render_template('index1.html', packets=captured_packets)


@app.route('/packets')
def get_packets():
    return jsonify(packets=captured_packets)


@app.route('/start_capture', methods=['POST'])
def start_capture():
    data = request.form
    interface = data.get('interface', '').strip()
    start_ip = data.get('start_ip', '').strip()
    end_ip = data.get('end_ip', '').strip()
    try:
        count = int(data.get('count', 10))
    except ValueError:
        count = 10

    capture_thread = threading.Thread(target=start_sniffing, args=(interface, (start_ip, end_ip), count), daemon=True)
    capture_thread.start()

    return 'Packet capture started successfully.'


@app.route('/results')
def results():
    return render_template('scan_results.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    ip_range = data.get('ip_range')
    devices_info = scan_network(ip_range) if ip_range else []
    return jsonify(devices=devices_info)


if __name__ == "__main__":
    app.run(debug=True)
