import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, Raw

class PacketSnifferApp:
    def __init__(self, root):
        # Initialize the main window
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Text widget to display captured packet information
        self.text = tk.Text(root, height=20, width=80)
        self.text.pack()
        
        # Button to start packet sniffing
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

    def packet_callback(self, packet):
        """Callback function to process and display packet details."""
        # Check if the packet contains an IP layer
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src  # Extract the source IP address
            dst_ip = ip_layer.dst  # Extract the destination IP address
            protocol = ip_layer.proto  # Extract the protocol used
            result = f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n"  # Format the result
            
            # Check if the packet contains a TCP layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                result += f"Protocol: TCP\nSource Port: {tcp_layer.sport}\nDestination Port: {tcp_layer.dport}\n"
            
            # Check if the packet contains a UDP layer
            elif UDP in packet:
                udp_layer = packet[UDP]
                result += f"Protocol: UDP\nSource Port: {udp_layer.sport}\nDestination Port: {udp_layer.dport}\n"

            # Check if the packet contains a Raw layer (payload)
            if packet.haslayer(Raw):
                payload = packet[Raw].load  # Extract the payload data
                result += f"Payload: {payload}\n"
            
            # Add a separator line between packets
            result += "-" * 50 + "\n"
            
            # Insert the packet information into the text widget
            self.text.insert(tk.END, result)
            self.text.yview(tk.END)  # Automatically scroll to the end of the text widget

    def start_sniffing(self):
        """Start sniffing packets and process them using the callback function."""
        sniff(prn=self.packet_callback, count=10)  # Start packet sniffing with the callback function

# Create the main window
root = tk.Tk()
app = PacketSnifferApp(root)  # Create an instance of the PacketSnifferApp class
root.mainloop()  # Start the Tkinter main loop
