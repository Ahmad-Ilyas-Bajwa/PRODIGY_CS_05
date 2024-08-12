This tool is designed as part of an internship task in Cyber Security at Prodigy InfoTech.

This project is a simple Network Packet Analyzer built using Python's Scapy library and Tkinter for the graphical user interface (GUI). The tool captures network packets and displays detailed information about each packet, including source and destination IP addresses, protocols, ports, and payload data.

Prerequisites
- Scapy Library: Scapy is used for packet capturing and analysis.
- Tkinter: Tkinter is included with most Python installations.
- Administrator Privileges: Running packet sniffing tools often requires administrative privileges. Ensure you run the program with appropriate permissions.

Working
- GUI Interface: The main window provides a text widget to display packet details and a button to start sniffing.
- Packet Capture: Once "Start Sniffing" is clicked, the program begins to capture the next 10 packets passing through the network interface.
- Packet Details: For each captured packet, details such as IP addresses, protocol (TCP/UDP), port numbers, and raw payload are extracted and displayed in the text area of the GUI.
- Automatic Scrolling: The text area automatically scrolls to the latest packet captured, ensuring that the user sees the most recent information.
