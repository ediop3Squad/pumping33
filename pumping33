import os
import subprocess
import time
from scapy.all import *
import threading

# Global variables
target_network = None
handshake_captured = False
capture_count = 0

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
        global target_network, handshake_captured, capture_count
        
        # Capture the handshake packets
        if packet.haslayer(EAPOL):
            handshake_captured = True
            capture_count += 1
            print(f"Handshake captured from {packet.addr2}!")
            if capture_count >= 1:  # Modify this for more handshakes
                target_network = packet.addr2
                print(f"Captured handshake from {target_network}. Stopping capture.")
                return False  # Stop sniffing

    sniff(iface=interface, prn=packet_handler, store=0, timeout=30)

def start_handshake_capture(interface):
    """Start capturing handshakes."""
    global handshake_captured, capture_count
    handshake_captured = False
    capture_count = 0

    print(f"Listening for handshakes on {interface}...")
    scan_networks(interface)

def crack_password(handshake_file, wordlist_file):
    """Attempt to crack the password using a wordlist."""
    print(f"Attempting to crack the password using {wordlist_file}...")

    # Placeholder for the cracking logic
    # This is where you would integrate with actual cracking libraries or methods
    with open(wordlist_file, 'r') as f:
        for line in f:
            password = line.strip()
            print(f"Trying password: {password}")
            # Here you would check if the password is valid for the handshake
            time.sleep(1)  # Simulate delay for each attempt

    print("Cracking completed. No valid password found.")

def main():
    print_logo()  # Call the function to print the logo

    interfaces = get_network_interfaces()
    print("Available Interfaces:")
    
    for index, iface in enumerate(interfaces):
        print(f"{index + 1}: {iface}")

    selected_iface = input("Select an interface (e.g., eth0, wlan0): ").strip()

    if selected_iface not in interfaces:
        print("Invalid interface selected. Please run the script again.")
        return

    wordlist_file = input("Enter the path to your wordlist file: ").strip()

    # Start capturing handshakes in a separate thread
    capture_thread = threading.Thread(target=start_handshake_capture, args=(selected_iface,))
    capture_thread.start()

    # Wait for handshake capture
    while not handshake_captured:
        time.sleep(1)

    capture_thread.join()  # Wait for the capture thread to finish

    if target_network:
        print(f"Captured handshake from {target_network}.")
        
        # Call the crack password function
        crack_password('captured_handshake', wordlist_file)  # Handshake file can be saved during capture

if __name__ == "__main__":
    main()
