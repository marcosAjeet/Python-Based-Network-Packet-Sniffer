Python-Based Network Packet Sniffer
A GUI network protocol analyzer built with Scapy and Tkinter. Captures

live traffic and parses it down through Ethernet, IP, TCP, UDP, and ICMP

layers — similar in spirit to a lightweight Wireshark, built for learning

how these protocols are structured on the wire.
Features
·	Live packet capture on any available network interface
·	BPF filter support (e.g. tcp port 80, udp, host 192.168.1.1)
·	Layer-by-layer breakdown of each captured packet (Ethernet → IP → TCP/UDP/ICMP)
·	Live packet table: source/destination, protocol, ports, length, flags
·	Running protocol statistics (TCP / UDP / ICMP / Other counts)
·	Export captured traffic to a standard .pcap file (viewable in Wireshark)
Requirements
·	Python 3.8+
·	Npcap (Windows only) or libpcap (Linux/macOS, usually preinstalled)
·	Administrator/root privileges (raw sockets require elevated access)
Setup
pip install -r requirements.txt

Running
Linux / macOS:
sudo python3 sniffer_gui.py

Windows (run terminal as Administrator):
python sniffer_gui.py

Usage
1.	Select a network interface from the dropdown.
2.	(Optional) Enter a BPF filter, e.g. tcp, udp port 53, icmp.
3.	Click Start Capture to begin sniffing; click Stop to end it.
4.	Click any row in the packet table to see its full layer breakdown below.
5.	Click Save as .pcap to export the session for analysis in Wireshark.
6.	Click Clear to reset the table and statistics.
Project Structure
packet_sniffer/
├── sniffer_gui.py      # Main application (GUI + capture logic)
├── requirements.txt    # Python dependencies
└── README.md

How It Works
·	scapy.sniff() runs in a background thread so the GUI stays responsive.
·	Each captured packet is pushed onto a thread-safe queue and drained by

the Tkinter main loop every 100ms (Tkinter is not thread-safe, so all UI

updates happen on the main thread).
·	For each packet, Scapy layers are inspected in order (Ether → IP/IPv6

→ TCP/UDP/ICMP) to populate both the summary row and the detailed

field-by-field breakdown.
Ethical Use Notice
Only capture traffic on networks you own or have explicit authorization to

monitor. Unauthorized packet interception may violate wiretapping laws

(e.g., the U.S. Computer Fraud and Abuse Act) and similar laws elsewhere.

This tool is intended for educational and authorized security-testing use.
Possible Extensions
·	Add a payload hex/ASCII viewer pane
·	DNS query/response parsing
·	Geo-IP lookups for source/destination addresses
·	Alerting rules (e.g. flag suspicious port scan patterns)
