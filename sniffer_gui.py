#!/usr/bin/env python3
"""
Python-Based Network Packet Sniffer
A GUI protocol analyzer built with Scapy + Tkinter.

Parses Ethernet, IP, TCP, UDP, and ICMP layers, displays live captured
packets in a table, shows a detailed layer-by-layer breakdown for the
selected packet, and supports BPF filters + saving captures to .pcap.

NOTE: Raw packet capture requires elevated privileges.
      Run with sudo (Linux/macOS) or as Administrator (Windows).
"""

import threading
import queue
import time
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from scapy.all import sniff, wrpcap, get_if_list
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Network Packet Sniffer")
        self.root.geometry("1150x650")

        self.sniffing = False
        self.sniff_thread = None
        self.packet_queue = queue.Queue()
        self.captured_packets = []  # store raw scapy packets for pcap export
        self.packet_count = 0
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

        self._build_ui()
        self._poll_queue()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        control_frame = ttk.Frame(self.root, padding=8)
        control_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 4))
        try:
            interfaces = get_if_list()
        except Exception:
            interfaces = []
        self.iface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
        self.iface_combo = ttk.Combobox(
            control_frame, textvariable=self.iface_var, values=interfaces, width=25, state="readonly"
        )
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(control_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=(0, 4))
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(control_frame, text='e.g. "tcp port 80" or "udp"', foreground="gray").pack(
            side=tk.LEFT, padx=(0, 12)
        )

        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        self.clear_btn = ttk.Button(control_frame, text="Clear", command=self.clear_capture)
        self.clear_btn.pack(side=tk.LEFT, padx=4)
        self.save_btn = ttk.Button(control_frame, text="Save as .pcap", command=self.save_pcap)
        self.save_btn.pack(side=tk.LEFT, padx=4)

        # Stats bar
        stats_frame = ttk.Frame(self.root, padding=(8, 0))
        stats_frame.pack(side=tk.TOP, fill=tk.X)
        self.stats_label = ttk.Label(stats_frame, text=self._stats_text(), font=("Consolas", 10))
        self.stats_label.pack(side=tk.LEFT)

        # Main pane: packet list (top) + detail view (bottom)
        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns = ("no", "time", "src", "dst", "proto", "sport", "dport", "length", "info")
        self.tree = ttk.Treeview(main_pane, columns=columns, show="headings", height=15)
        headings = {
            "no": ("No.", 50), "time": ("Time", 90), "src": ("Source", 140),
            "dst": ("Destination", 140), "proto": ("Protocol", 70),
            "sport": ("SPort", 60), "dport": ("DPort", 60),
            "length": ("Length", 60), "info": ("Info", 300),
        }
        for col, (label, width) in headings.items():
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor=tk.W)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_packet)

        vsb = ttk.Scrollbar(main_pane, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        tree_frame = ttk.Frame(main_pane)
        self.tree.pack(in_=tree_frame, side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(in_=tree_frame, side=tk.RIGHT, fill=tk.Y)
        main_pane.add(tree_frame, weight=3)

        detail_frame = ttk.Frame(main_pane)
        ttk.Label(detail_frame, text="Layer Details", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, padx=4, pady=(4, 0)
        )
        self.detail_text = tk.Text(detail_frame, height=12, font=("Consolas", 9), wrap="none")
        detail_vsb = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_vsb.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        detail_vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=4)
        main_pane.add(detail_frame, weight=2)

    def _stats_text(self):
        return (
            f"Packets: {self.packet_count:<6}  "
            f"TCP: {self.stats['TCP']:<5}  "
            f"UDP: {self.stats['UDP']:<5}  "
            f"ICMP: {self.stats['ICMP']:<5}  "
            f"Other: {self.stats['Other']:<5}"
        )

    # ------------------------------------------------------------- capture
    def start_sniffing(self):
        if self.sniffing:
            return
        iface = self.iface_var.get() or None
        bpf_filter = self.filter_var.get().strip() or None

        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.iface_combo.config(state=tk.DISABLED)

        self.sniff_thread = threading.Thread(
            target=self._sniff_worker, args=(iface, bpf_filter), daemon=True
        )
        self.sniff_thread.start()

    def _sniff_worker(self, iface, bpf_filter):
        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=self._on_packet_captured,
                store=False,
                stop_filter=lambda p: not self.sniffing,
            )
        except PermissionError:
            self.packet_queue.put(("error", "Permission denied. Run this script with root/admin privileges."))
        except Exception as e:
            self.packet_queue.put(("error", f"Capture error: {e}"))
        finally:
            self.sniffing = False

    def _on_packet_captured(self, packet):
        self.packet_queue.put(("packet", packet))

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_combo.config(state="readonly")

    def clear_capture(self):
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete("1.0", tk.END)
        self.captured_packets.clear()
        self.packet_count = 0
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.stats_label.config(text=self._stats_text())

    def save_pcap(self):
        if not self.captured_packets:
            messagebox.showinfo("No data", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if path:
            wrpcap(path, self.captured_packets)
            messagebox.showinfo("Saved", f"Saved {len(self.captured_packets)} packets to:\n{path}")

    # ---------------------------------------------------------------- poll
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.packet_queue.get_nowait()
                if kind == "packet":
                    self._add_packet_row(payload)
                elif kind == "error":
                    messagebox.showerror("Sniffer Error", payload)
                    self.stop_sniffing()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    # ------------------------------------------------------------ parsing
    def _add_packet_row(self, packet):
        self.packet_count += 1
        self.captured_packets.append(packet)

        ts = datetime.now().strftime("%H:%M:%S")
        src = dst = proto = info = ""
        sport = dport = ""
        length = len(packet)

        if Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst

        if IP in packet:
            ip_layer = packet[IP]
            src, dst = ip_layer.src, ip_layer.dst
            proto = PROTO_NAMES.get(ip_layer.proto, f"IP({ip_layer.proto})")
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            src, dst = ip_layer.src, ip_layer.dst
            proto = "IPv6"

        if TCP in packet:
            proto = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            flags = packet[TCP].flags
            info = f"Flags={flags} Seq={packet[TCP].seq}"
            self.stats["TCP"] += 1
        elif UDP in packet:
            proto = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
            info = f"Len={packet[UDP].len}"
            self.stats["UDP"] += 1
        elif ICMP in packet:
            proto = "ICMP"
            info = f"Type={packet[ICMP].type} Code={packet[ICMP].code}"
            self.stats["ICMP"] += 1
        else:
            if not proto:
                proto = "Other"
            self.stats["Other"] += 1

        self.stats_label.config(text=self._stats_text())

        row_id = self.tree.insert(
            "", tk.END,
            values=(self.packet_count, ts, src, dst, proto, sport, dport, length, info),
        )
        # keep a mapping to the raw packet for detail view
        self.tree.set(row_id, "no", self.packet_count)
        self._row_to_packet = getattr(self, "_row_to_packet", {})
        self._row_to_packet[row_id] = packet

        # auto-scroll
        self.tree.yview_moveto(1.0)

    def on_select_packet(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        row_id = selection[0]
        packet = getattr(self, "_row_to_packet", {}).get(row_id)
        if packet is None:
            return
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, self._format_layers(packet))

    def _format_layers(self, packet):
        lines = []
        layer = packet
        while layer:
            lines.append(f"### {layer.name} ###")
            for field in layer.fields_desc:
                fname = field.name
                try:
                    value = layer.getfieldval(fname)
                except Exception:
                    value = "?"
                lines.append(f"  {fname:<15} = {value}")
            lines.append("")
            layer = layer.payload if hasattr(layer, "payload") and layer.payload else None
            if layer and not layer.fields_desc and layer.name == "NoPayload":
                break
            if layer.__class__.__name__ == "NoPayload":
                break
        return "\n".join(lines)


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use("clam")
    except Exception:
        pass
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
