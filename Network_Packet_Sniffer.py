import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
import psutil
import time
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer and Network Connections")
        self.root.geometry("800x600")

        # Create a frame to hold the search bar
        self.search_frame = tk.Frame(self.root)
        self.search_frame.pack(pady=10, fill=tk.X)

        # Add a search entry and button to the frame
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(self.search_frame, textvariable=self.search_var, width=50)
        self.search_entry.pack(side=tk.LEFT, padx=10)
        self.search_button = tk.Button(self.search_frame, text="Search", command=self.apply_filter)
        self.search_button.pack(side=tk.LEFT)

        # Create a Treeview widget for displaying packet details
        self.tree = ttk.Treeview(self.root, columns=("Packet Summary", "PID", "Local Address", "Remote Address", "Process Name"), show="headings")
        self.tree.heading("Packet Summary", text="Packet Summary")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Local Address", text="Local Address")
        self.tree.heading("Remote Address", text="Remote Address")
        self.tree.heading("Process Name", text="Process Name")

        # Set column widths
        self.tree.column("Packet Summary", width=300)
        self.tree.column("PID", width=80)
        self.tree.column("Local Address", width=120)
        self.tree.column("Remote Address", width=120)
        self.tree.column("Process Name", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Store the packet data for later filtering
        self.packet_data = []

        # Start the packet sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def packet_callback(self, packet):
        # Display packet details in the Treeview
        summary = packet.summary()

        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                try:
                    process = psutil.Process(conn.pid)
                    pid = conn.pid
                    local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
                    process_name = process.name()

                    packet_info = (summary, pid, local_address, remote_address, process_name)
                    self.packet_data.append(packet_info)  # Store packet data for filtering

                    # Insert packet and network connection data into the table
                    self.tree.insert("", "end", values=packet_info)
                except psutil.NoSuchProcess:
                    continue

    def apply_filter(self):
        search_term = self.search_var.get().lower()
        
        # Clear the current treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Insert filtered data into the table
        for packet_info in self.packet_data:
            if any(search_term in str(field).lower() for field in packet_info):
                self.tree.insert("", "end", values=packet_info)

    def start_sniffing(self):
        # Capture packets and process them using the callback function
        sniff(timeout=7, prn=self.packet_callback)

# Initialize the Tkinter window
root = tk.Tk()
app = PacketSnifferApp(root)

# Run the Tkinter event loop
root.mainloop()
