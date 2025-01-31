import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, get_if_list
import psutil
import threading
from datetime import datetime
import socket
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer and Network Connections")
        self.root.geometry("1200x600")

        # Fetch the local IP address dynamically
        self.local_ip = self.get_local_ip()

        # Create a frame for the search bar and sniff duration input
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10, fill=tk.X)

        # Add a search entry and button to the frame
        self.search_var = tk.StringVar()
        self.search_label = tk.Label(self.input_frame, text="Search:")
        self.search_label.pack(side=tk.LEFT, padx=10)
        self.search_entry = tk.Entry(self.input_frame, textvariable=self.search_var, width=50)
        self.search_entry.pack(side=tk.LEFT, padx=10)
        self.search_button = tk.Button(self.input_frame, text="Search", command=self.apply_filter)
        self.search_button.pack(side=tk.LEFT)

        # Create a frame for sniff duration and interface selection
        self.sniff_interface_frame = tk.Frame(self.root)
        self.sniff_interface_frame.pack(pady=10, fill=tk.X)

        # Sniff Duration Input
        self.sniff_time_var = tk.StringVar()
        self.sniff_time_label = tk.Label(self.sniff_interface_frame, text="Sniff Duration (seconds):")
        self.sniff_time_label.pack(side=tk.LEFT, padx=10)
        self.sniff_time_entry = tk.Entry(self.sniff_interface_frame, textvariable=self.sniff_time_var, width=10)
        self.sniff_time_entry.pack(side=tk.LEFT, padx=10)
        self.sniff_time_var.set("7")  # Default sniff time is 7 seconds

        # Network Interface Dropdown
        self.interface_label = tk.Label(self.sniff_interface_frame, text="Select Network Interface:")
        self.interface_label.pack(side=tk.LEFT, padx=10)

        # Create a ComboBox to list all available interfaces
        self.interface_combo = ttk.Combobox(self.sniff_interface_frame, state="readonly", width=60)
        self.interface_combo.pack(side=tk.LEFT, padx=10)

        # Get the available interfaces and populate the ComboBox
        self.interfaces = get_if_list()
        self.interface_combo['values'] = self.interfaces

        # Set default interface (if available)
        if self.interfaces:
            self.interface_combo.set(self.interfaces[0])

        # Create a frame for the action buttons (Start Sniffing and Clear Table)
        self.action_button_frame = tk.Frame(self.root)
        self.action_button_frame.pack(pady=10, fill=tk.X)

        # Add a "Start Sniffing" button
        self.start_button = tk.Button(self.action_button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10)

        # Add a "Clear Table" button to clear the Treeview
        self.clear_button = tk.Button(self.action_button_frame, text="Clear Table", command=self.clear_table)
        self.clear_button.pack(side=tk.LEFT, padx=10)

        # Create a Treeview widget for displaying packet details
        self.tree = ttk.Treeview(self.root, columns=("Timestamp", "Packet Summary", "PID", "Local Address", "Remote Address", "Process Name", "Direction", "Protocol"), show="headings")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("Packet Summary", text="Packet Summary")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Local Address", text="Local Address")
        self.tree.heading("Remote Address", text="Remote Address")
        self.tree.heading("Process Name", text="Process Name")
        self.tree.heading("Direction", text="Direction")
        self.tree.heading("Protocol", text="Protocol")

        # Set column widths
        self.tree.column("Timestamp", width=150)
        self.tree.column("Packet Summary", width=300)
        self.tree.column("PID", width=80)
        self.tree.column("Local Address", width=120)
        self.tree.column("Remote Address", width=120)
        self.tree.column("Process Name", width=150)
        self.tree.column("Direction", width=100)
        self.tree.column("Protocol", width=120)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Configure tags for row colors
        self.tree.tag_configure("incoming", background="green", foreground="white")
        self.tree.tag_configure("outgoing", background="red", foreground="white")

        # Store the packet data for later filtering
        self.packet_data = []

    def get_local_ip(self):
        # Function to dynamically fetch the local machine's IP address
        return socket.gethostbyname(socket.gethostname())

    def packet_callback(self, packet):
        # Display packet details in the Treeview
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Determine the packet direction (Outgoing or Incoming)
            if src_ip == self.local_ip:  # Use dynamic local IP address
                packet_direction = "Outgoing"
                tag = "outgoing"  # Red for outgoing
            else:
                packet_direction = "Incoming"
                tag = "incoming"  # Green for incoming

            summary = f"{packet.summary()} ({packet_direction})"

            # Capture the timestamp of when the packet is processed
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Determine the protocol (TCP, UDP, ICMP, ARP, DNS, HTTP, etc.)
            protocol = "Unknown"
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            elif ARP in packet:
                protocol = "ARP"
            elif DNS in packet:
                protocol = "DNS"
            elif HTTP in packet:
                protocol = "HTTP"
            elif packet.haslayer(HTTP) and packet[HTTP].fields.get("Host") == b"443":
                protocol = "HTTPS"

            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    try:
                        process = psutil.Process(conn.pid)
                        pid = conn.pid
                        local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
                        process_name = process.name()

                        # Include the timestamp, protocol, and other details in the packet info
                        packet_info = (timestamp, summary, pid, local_address, remote_address, process_name, packet_direction, protocol)
                        self.packet_data.append(packet_info)  # Store packet data for filtering

                        # Schedule the packet insertion to run on the main thread with the correct tag
                        self.root.after(0, self.insert_packet_info, packet_info, tag)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

    def insert_packet_info(self, packet_info, tag):
        # Insert the packet info into the treeview with the appropriate tag for color
        self.tree.insert("", "end", values=packet_info, tags=(tag,))

    def apply_filter(self):
        search_term = self.search_var.get().lower()

        # Clear the current treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert filtered data into the table
        for packet_info in self.packet_data:
            if any(search_term in str(field).lower() for field in packet_info):
                self.tree.insert("", "end", values=packet_info)

    def clear_table(self):
        # Clear all rows from the Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_data.clear()  # Clear the packet data list as well
        print("Table cleared.")

    def start_sniffing(self):
        # Capture packets and process them using the callback function
        try:
            sniff_time = int(self.sniff_time_var.get())  # Get sniff time from the input box
        except ValueError:
            print("Invalid sniff time entered. Please enter a valid integer.")
            return

        # Get the selected interface from the ComboBox
        selected_interface = self.interface_combo.get()

        # Check if an interface is selected
        if not selected_interface:
            print("Please select a network interface.")
            return

        print(f"Sniffing on interface: {selected_interface}")

        # Start sniffing on the selected interface for the user-defined duration
        sniff(iface=selected_interface, filter="ip", timeout=sniff_time, prn=self.packet_callback)

# Initialize the Tkinter window
root = tk.Tk()
app = PacketSnifferApp(root)

# Run the Tkinter event loop
root.mainloop()
