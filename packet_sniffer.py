import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP, Raw, wrpcap
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.sniffing = False
        self.packets = []  # ✅ Fix: Define self.packets here
        self.all_packets = []  # Ensure this is initialized

        # Main Window Settings
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")  # Set an appropriate window size

        # Filter Frame
        filter_frame = tk.Frame(root)
        filter_frame.pack(fill="x", padx=5, pady=5)

        tk.Label(filter_frame, text="Filter (e.g., tcp, udp, icmp):").grid(row=0, column=0, padx=5)
        self.filter_var = tk.StringVar()
        tk.Entry(filter_frame, textvariable=self.filter_var).grid(row=0, column=1, padx=5)
        tk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).grid(row=0, column=2, padx=5)

        tk.Button(filter_frame, text="Start Sniffing", command=self.start_sniffing).grid(row=0, column=3, padx=5)
        tk.Button(filter_frame, text="Stop Sniffing", command=self.stop_sniffing).grid(row=0, column=4, padx=5)
        tk.Button(filter_frame, text="Save Packets", command=self.save_packets).grid(row=0, column=5, padx=5)

        # Packet List (Treeview)
        self.packet_tree = ttk.Treeview(root, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        self.packet_tree.pack(fill="both", expand=True, padx=5, pady=5)

        for col in ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"):
            self.packet_tree.heading(col, text=col)

        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # Packet Details Section
        details_frame = tk.Frame(root)
        details_frame.pack(fill="both", expand=True, padx=5, pady=5)

        tk.Label(details_frame, text="Packet Details:").grid(row=0, column=0, sticky="w")
        self.packet_details_text = tk.Text(details_frame, wrap="word", height=10, width=100)
        self.packet_details_text.grid(row=1, column=0, columnspan=2, sticky="nsew")

        tk.Label(details_frame, text="Packet Bytes:").grid(row=2, column=0, sticky="w")
        self.packet_bytes = scrolledtext.ScrolledText(details_frame, height=5)
        self.packet_bytes.grid(row=3, column=0, columnspan=2, sticky="nsew")

        # Configure resizing behavior
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(1, weight=1)
        details_frame.rowconfigure(3, weight=1)

    def apply_filter(self):
        """Apply filter dynamically to already captured packets."""
        filter_text = self.filter_var.get().strip().lower()
        self.filtered_packets = []

        for packet in self.all_packets:
            if self.packet_matches_filter(packet, filter_text):
                self.filtered_packets.append(packet)

        self.update_display()

    def packet_matches_filter(self, packet, filter_text):
        """Check if a packet matches the applied filter."""
        if not filter_text:
            return True  # No filter, show all packets

        if IP in packet:
            proto_num = packet[IP].proto
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP {proto_num}")
        elif ARP in packet:
            protocol = "ARP"
        elif Ether in packet:
            protocol = "Ethernet"
        else:
            protocol = "Unknown"

        return filter_text.lower() in protocol.lower()

    def process_packet(self, packet):
        """Process incoming packets and update the UI dynamically based on the current filter."""
        current_filter = self.filter_var.get().strip().lower()

        src, dst, protocol = "Unknown", "Unknown", "Unknown"
        bg_color = "white"  # Default color

        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
            proto_num = packet[IP].proto
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP {proto_num}")

            if proto_num == 6:  # TCP
                bg_color = "#ADD8E6"
            elif proto_num == 17:  # UDP
                bg_color = "#90EE90"
            elif proto_num == 1:  # ICMP
                bg_color = "#FFD700"

        elif ARP in packet:
            src, dst, protocol = packet[ARP].psrc, packet[ARP].pdst, "ARP"
            bg_color = "#FFA07A"

        elif Ether in packet:
            src, dst, protocol = packet[Ether].src, packet[Ether].dst, "Ethernet"
            bg_color = "#D3D3D3"

        # Store all packets (unfiltered)
        self.all_packets.append(packet)

        # Apply filter dynamically
        if current_filter and current_filter not in protocol.lower():
            return  # Skip packets that don't match the filter

        # Update UI
        length = len(packet)
        time = packet.time
        no = len(self.packets) + 1
        info = f"{protocol} {src} > {dst}"

        # Insert row with background color
        item_id = self.packet_tree.insert("", "end", values=(no, time, src, dst, protocol, length, info))
        self.packet_tree.item(item_id, tags=(protocol,))

        # Apply colors
        self.packet_tree.tag_configure("TCP", background="#ADD8E6")
        self.packet_tree.tag_configure("UDP", background="#90EE90")
        self.packet_tree.tag_configure("ICMP", background="#FFD700")
        self.packet_tree.tag_configure("ARP", background="#FFA07A")
        self.packet_tree.tag_configure("Ethernet", background="#D3D3D3")

    def update_display(self):
        """Refresh the packet display to apply the current filter dynamically."""
        self.packet_tree.delete(*self.packet_tree.get_children())
        current_filter = self.filter_var.get().strip().lower()

        for index, packet in enumerate(self.all_packets):
            src, dst, protocol = "Unknown", "Unknown", "Unknown"
            bg_color = "white"

            if IP in packet:
                src, dst = packet[IP].src, packet[IP].dst
                proto_num = packet[IP].proto
                protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP {proto_num}")

            elif ARP in packet:
                src, dst, protocol = packet[ARP].psrc, packet[ARP].pdst, "ARP"

            elif Ether in packet:
                src, dst, protocol = packet[Ether].src, packet[Ether].dst, "Ethernet"

            # Apply filter
            if current_filter and current_filter not in protocol.lower():
                continue  # Skip packets that don't match filter

            # Insert row
            length = len(packet)
            time = packet.time
            info = f"{protocol} {src} > {dst}"

            item_id = self.packet_tree.insert("", "end", values=(index + 1, time, src, dst, protocol, length, info))
            self.packet_tree.item(item_id, tags=(protocol,))

        # Apply colors again
        self.packet_tree.tag_configure("TCP", background="#ADD8E6")
        self.packet_tree.tag_configure("UDP", background="#90EE90")
        self.packet_tree.tag_configure("ICMP", background="#FFD700")
        self.packet_tree.tag_configure("ARP", background="#FFA07A")
        self.packet_tree.tag_configure("Ethernet", background="#D3D3D3")

    def start_sniffing(self):
        """Start packet sniffing in a new thread with the applied filter."""
        if not self.sniffing:
            self.sniffing = True
            filter_expr = self.filter_var.get().strip().lower()
            print(f"Starting sniffing with filter: {filter_expr}")

            thread = threading.Thread(target=self.sniff_packets, args=(filter_expr,))
            thread.daemon = True
            thread.start()

    def sniff_packets(self, filter_expr):
        """Sniff packets with dynamic filter updates."""
        sniff(prn=self.process_packet, filter=filter_expr, store=False)

    def stop_sniffing(self):
        """Stop sniffing packets."""
        self.sniffing = False

    def save_packets(self):
        """Save captured packets to a PCAP file and a CSV file."""
        if not self.all_packets:
            print("No packets to save.")
            return

        # Save as .pcap
        pcap_file_path = "captured_packets.pcap"
        wrpcap(pcap_file_path, self.all_packets)
        print(f"Packets saved successfully to {pcap_file_path}.")

        # Save as .csv
        csv_file_path = "captured_packets.csv"
        with open(csv_file_path, mode='w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            # Write the header
            csv_writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])

            # Write packet data
            for index, packet in enumerate(self.all_packets):
                src, dst, protocol = "Unknown", "Unknown", "Unknown"

                if IP in packet:
                    src, dst = packet[IP].src, packet[IP].dst
                    proto_num = packet[IP].proto
                    protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP {proto_num}")

                elif ARP in packet:
                    src, dst, protocol = packet[ARP].psrc, packet[ARP].pdst, "ARP"

                elif Ether in packet:
                    src, dst, protocol = packet[Ether].src, packet[Ether].dst, "Ethernet"

                length = len(packet)
                time = packet.time
                info = f"{protocol} {src} > {dst}"

                csv_writer.writerow([index + 1, time, src, dst, protocol, length, info])

        print(f"Packets saved successfully to {csv_file_path}.")

    def show_packet_details(self, event):
        """Show packet details and raw bytes when a row is selected."""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        index = int(self.packet_tree.index(selected_item))

        if index >= len(self.all_packets):
            return

        packet = self.all_packets[index]
        details = packet.show(dump=True)
        raw_bytes = bytes(packet)

        self.packet_details_text.delete("1.0", tk.END)
        self.packet_details_text.insert(tk.END, details)

        self.packet_bytes.delete("1.0", tk.END)
        self.packet_bytes.insert(tk.END, raw_bytes.hex())

# Run the application
root = tk.Tk()
app = PacketSnifferApp(root)
root.mainloop()