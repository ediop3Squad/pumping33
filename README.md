# pumping33 ![image](https://github.com/user-attachments/assets/5b555105-ea81-4e9b-873a-5171778e32a7)


The interface wlan0 is not available, as per the script output. The script lists two available interfaces:

lo (loopback interface)
eth0@if5

if requirements.txt aint workin try "sudo apt install python3-scapy"


Pumping33
Pumping33 is a Wi-Fi password cracking tool that allows users to capture packets, perform dictionary attacks on WPA/WPA2 handshakes, and attempt to crack the Wi-Fi password.

Table of Contents
Installation
Requirements
Running Pumping33
Understanding Pumping33
Using Pumping33
Disclaimer
Installation
1. Clone the repository:
Open your terminal and run the following command to clone the repository:

bash
Copy code
git clone https://github.com/ediop3Squad/pumping33.git
2. Navigate to the project directory:
bash
Copy code
cd pumping33
3. Install the dependencies:
Pumping33 requires certain libraries like scapy. Install them using the following commands:

bash
Copy code
sudo apt-get install python3-pip
pip3 install -r requirements.txt
4. Set up the Wordlist (for dictionary attack):
You'll need to provide your own wordlist for the dictionary attack. If you don't have one, you can download a common one like rockyou.txt by running:

bash
Copy code
sudo apt-get install wordlists
gunzip /usr/share/wordlists/rockyou.txt.gz
Alternatively, create or download any custom wordlist you want to use.

Requirements
1. Operating System:
Linux (Recommended: Kali Linux, Ubuntu)
2. Python Version:
Python 3.x
3. Root Access:
You need root access to run this tool because it requires capturing network traffic and putting your network interface into monitor mode.
4. Wi-Fi Adapter:
A Wi-Fi adapter that supports monitor mode and packet injection.
Running Pumping33
1. Launch Pumping33:
To start Pumping33, run:

bash
Copy code
sudo python3 pumping33.py
2. Choose Network Interface:
When prompted, select your network interface (e.g., eth0, wlan0, etc.). This interface should be in monitor mode to capture packets.

3. Specify Wordlist:
You will be prompted to provide the path to the wordlist file for the dictionary attack. For example:

bash
Copy code
/usr/share/wordlists/rockyou.txt
4. Select Target Network:
The script will scan for nearby Wi-Fi networks, and you'll be asked to select the target by choosing its corresponding number.

Understanding Pumping33
Pumping33 works by performing the following tasks:

Capturing Wi-Fi Packets: The tool listens to the network traffic and captures the WPA/WPA2 handshake required for cracking the Wi-Fi password.

Dictionary Attack: Once the handshake is captured, it attempts to crack the password by comparing the captured handshake against a wordlist of possible passwords.

Displaying the Key: If successful, the tool will display the cracked Wi-Fi password (key) in the terminal.

Using Pumping33
Step-by-step Example:
Launch the tool:

bash
Copy code
sudo python3 pumping33.py
Select the network interface: Enter wlan0 (or the interface you want to use).

Provide the path to the wordlist: Example:

bash
Copy code
/usr/share/wordlists/rockyou.txt
Choose the target network:

The tool will scan for available Wi-Fi networks and display a numbered list.
Select your target by typing the corresponding number.
Start the attack: Pumping33 will start capturing the handshake and running the dictionary attack. If successful, the password will be displayed.

Disclaimer
This tool is intended for educational and penetration testing purposes only. Unauthorized access to Wi-Fi networks is illegal and punishable under the law. Always obtain permission from the network owner before attempting to crack any network passwords.

The creator of this tool (ediop3Squad) is not responsible for any misuse or illegal activity conducted with this software.

Contributing
Feel free to submit pull requests or open issues to improve the functionality of Pumping33. Contributions are always welcome!

Made by:
ediop3Squad Leader
