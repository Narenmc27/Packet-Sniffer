import scapy.all as scapy
from scapy.layers.inet import TCP, UDP, IP
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import psutil
import json

# Global Variables
packet_count = 0
protocol_counts = {'TCP': 0, 'UDP': 0, 'Other': 0}
captured_packets = []
sniffing = False  # Variable to control sniffing state

# Start the sniffer
def start_sniffing(interface, ip_filter=None, port_filter=None):
    global sniffing
    sniffing = True
    scapy.sniff(iface=interface, prn=packet_handler, store=0, filter=build_filter(ip_filter, port_filter))

# Stop the sniffer
def stop_sniffing():
    global sniffing
    sniffing = False

# Create filter for IP/Port
def build_filter(ip_filter, port_filter):
    filter_str = ""
    if ip_filter:
        filter_str += f"host {ip_filter} "
    if port_filter:
        filter_str += f"port {port_filter} "
    return filter_str.strip()

# Packet handler
def packet_handler(packet):
    global packet_count, protocol_counts, captured_packets

    if not sniffing:  # Stop processing if sniffing is not active
        return

    if IP in packet:
        protocol = 'Other'
        if TCP in packet:
            protocol = 'TCP'
            protocol_counts['TCP'] += 1
        elif UDP in packet:
            protocol = 'UDP'
            protocol_counts['UDP'] += 1

        packet_count += 1

        # Capture packet information
        packet_info = {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'protocol': protocol,
            'length': len(packet)
        }
        captured_packets.append(packet_info)

        # Display in GUI
        display_packet_info(packet_info)

# Display packets in the GUI listbox
def display_packet_info(packet_info):
    packet_text = f"Source: {packet_info['src']}, Destination: {packet_info['dst']}, Protocol: {packet_info['protocol']}, Length: {packet_info['length']}"
    packet_listbox.insert(tk.END, packet_text)
    update_statistics()

# Update statistics in GUI
def update_statistics():
    stats_text = f"Total Packets: {packet_count}\nTCP: {protocol_counts['TCP']}\nUDP: {protocol_counts['UDP']}\nOther: {protocol_counts['Other']}"
    statistics_label.config(text=stats_text)

# Export captured packets to JSON file
def export_to_json():
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if file_path:
        with open(file_path, 'w') as json_file:
            json.dump(captured_packets, json_file, indent=4)
        messagebox.showinfo("Export Successful", "Packets exported successfully!")

# Clear packets and statistics in the GUI
def clear_packets():
    global packet_count, protocol_counts, captured_packets
    packet_count = 0
    protocol_counts = {'TCP': 0, 'UDP': 0, 'Other': 0}
    captured_packets = []
    packet_listbox.delete(0, tk.END)  # Clear the listbox
    update_statistics()  # Update statistics display

# Start the sniffer in a separate thread
def run_sniffer(interface):
    start_sniffing(interface)

# Populate the list of network interfaces
def populate_interfaces():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        interface_list.append(interface)
    if interface_list:  # Check if there are any interfaces
        interface_var.set(interface_list[0])  # Set default to the first interface

# Display connection info for the selected interface
def get_connection_info(interface):
    addr_info = psutil.net_if_addrs()
    if interface in addr_info:
        info = addr_info[interface]
        connection_info = f"Connection Info for {interface}:\n"
        for addr in info:
            connection_info += f"Address: {addr.address}, Family: {addr.family}\n"
        connection_info_label.config(text=connection_info)
    else:
        connection_info_label.config(text="No connection info available.")

# When an interface is selected from the dropdown
def interface_selected(event):
    selected_interface = interface_var.get()
    get_connection_info(selected_interface)

# Start the GUI application
def start_gui():
    global packet_listbox
    global statistics_label
    global interface_var
    global interface_list
    global connection_info_label

    interface_list = []  # List to hold available interfaces

    root = tk.Tk()
    root.title("Advanced Packet Sniffer")
    root.geometry("800x600")
    root.configure(bg="#2E3440")  # Dark background

    # Styling
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", padding=6, relief="flat", background="#4CAF50", font=('Arial', 12), foreground="white")
    style.configure("TLabel", font=('Arial', 10), padding=5, foreground="#D8DEE9", background="#2E3440")
    style.configure("TFrame", background="#3B4252")

    # Packet display frame
    packet_frame = ttk.Frame(root)
    packet_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    packet_listbox = tk.Listbox(packet_frame, width=100, height=20, bg="#ECEFF4", fg="#2E3440", font=('Arial', 10))
    packet_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(packet_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    packet_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=packet_listbox.yview)

    # Statistics label
    statistics_label = ttk.Label(root, text="", justify=tk.LEFT)
    statistics_label.pack(padx=10, pady=10, anchor=tk.W)

    # Connection Info label
    connection_info_label = ttk.Label(root, text="", justify=tk.LEFT, wraplength=750)
    connection_info_label.pack(padx=10, pady=10, anchor=tk.W)

    # Interface selection dropdown
    interface_var = tk.StringVar(root)
    populate_interfaces()  # Populate the interface options
    interface_dropdown = ttk.OptionMenu(root, interface_var, *interface_list, command=interface_selected)
    interface_dropdown.pack(pady=10)

    # Control Buttons
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10)

    start_button = ttk.Button(button_frame, text="Start Sniffing", command=lambda: threading.Thread(target=run_sniffer, args=(interface_var.get(),)).start())
    start_button.grid(row=0, column=0, padx=5)

    stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
    stop_button.grid(row=0, column=1, padx=5)

    clear_button = ttk.Button(button_frame, text="Clear Packets", command=clear_packets)
    clear_button.grid(row=0, column=2, padx=5)

    export_button = ttk.Button(root, text="Export to JSON", command=export_to_json)
    export_button.pack(padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    start_gui()
