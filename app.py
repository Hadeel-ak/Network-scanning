import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import socket
import ipaddress
import threading
import csv
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# CONFIGURATION
# ============================================================

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

MAX_WORKERS = 50


# ============================================================
# GET LOCAL IP
# ============================================================

def get_local_ip():

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.connect(("8.8.8.8", 80))

        ip = sock.getsockname()[0]

        sock.close()

        return ip

    except Exception:

        try:
            return socket.gethostbyname(
                socket.gethostname()
            )
        except:
            return "127.0.0.1"


# ============================================================
# GET LOCAL NETWORK
# ============================================================

def get_local_network():

    local_ip = get_local_ip()

    network = ipaddress.ip_network(
        local_ip + "/24",
        strict=False
    )

    return local_ip, network


# ============================================================
# WINDOWS PING
# ============================================================

def ping_host(ip):

    try:

        result = subprocess.run(
            [
                "ping",
                "-n",
                "1",
                "-w",
                "500",
                str(ip)
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except:

        return False


# ============================================================
# GET WINDOWS ARP TABLE
# ============================================================

def get_arp_table():

    arp_table = {}

    try:

        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )

        output = result.stdout

        # Example:
        #
        #  10.255.254.1    xx-xx-xx-xx-xx-xx    dynamic

        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+\s+)"
            r"([0-9a-fA-F-]{17})\s+"
            r"(dynamic|static)",
            re.IGNORECASE
        )

        for match in pattern.finditer(output):

            ip = match.group(1).strip()

            mac = match.group(2).strip()

            mac = mac.replace("-", ":")

            arp_table[ip] = mac

    except:
        pass

    return arp_table


# ============================================================
# GET HOSTNAME
# ============================================================

def get_hostname(ip):

    try:

        hostname = socket.gethostbyaddr(
            ip
        )[0]

        return hostname

    except:

        return "Unknown"


# ============================================================
# CHECK PORT
# ============================================================

def check_port(ip, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.35)

        result = sock.connect_ex(
            (ip, port)
        )

        sock.close()

        return result == 0

    except:

        return False


# ============================================================
# PORT SCAN
# ============================================================

def scan_ports(ip):

    open_ports = []

    for port, service in COMMON_PORTS.items():

        if check_port(ip, port):

            open_ports.append(
                f"{port} ({service})"
            )

    if open_ports:

        return ", ".join(open_ports)

    return "None"


# ============================================================
# UPDATE STATUS SAFELY
# ============================================================

def update_status(text):

    root.after(
        0,
        lambda: status_label.config(
            text=text
        )
    )


# ============================================================
# UPDATE PROGRESS
# ============================================================

def update_progress(value):

    root.after(
        0,
        lambda: progress.config(
            value=value
        )
    )


# ============================================================
# ADD DEVICE TO TABLE
# ============================================================

def add_device(device):

    root.after(
        0,
        lambda: tree.insert(
            "",
            "end",
            values=(
                device["ip"],
                device["mac"],
                device["hostname"],
                device["status"],
                device["ports"]
            )
        )
    )


# ============================================================
# CLEAR RESULTS
# ============================================================

def clear_results():

    for item in tree.get_children():

        tree.delete(item)


# ============================================================
# NETWORK SCAN
# ============================================================

def scan_network():

    try:

        scan_button.config(
            state="disabled"
        )

        clear_results()

        progress["value"] = 0

        # ----------------------------------------------------
        # GET NETWORK
        # ----------------------------------------------------

        local_ip, network = get_local_network()

        root.after(
            0,
            lambda: network_label.config(
                text=f"Network: {network}   |   Your IP: {local_ip}"
            )
        )

        update_status(
            f"Scanning {network}..."
        )

        hosts = list(network.hosts())

        total_hosts = len(hosts)

        active_ips = []

        # ----------------------------------------------------
        # PING SWEEP
        # ----------------------------------------------------

        completed = 0

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {
                executor.submit(
                    ping_host,
                    str(ip)
                ): ip

                for ip in hosts
            }

            for future in as_completed(
                futures
            ):

                ip = futures[future]

                try:

                    if future.result():

                        active_ips.append(
                            str(ip)
                        )

                except:
                    pass

                completed += 1

                update_progress(
                    completed / total_hosts * 70
                )

                update_status(
                    f"Scanning devices... "
                    f"{completed}/{total_hosts}"
                )

        # ----------------------------------------------------
        # GET ARP TABLE
        # ----------------------------------------------------

        update_status(
            "Reading Windows ARP table..."
        )

        arp_table = get_arp_table()

        # ----------------------------------------------------
        # CREATE DEVICE LIST
        # ----------------------------------------------------

        devices = []

        for ip in active_ips:

            mac = arp_table.get(
                ip,
                "Unknown"
            )

            hostname = get_hostname(
                ip
            )

            device = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "status": "Online",
                "ports": "Scanning..."
            }

            devices.append(device)

            add_device(device)

        # ----------------------------------------------------
        # PORT SCANNING
        # ----------------------------------------------------

        update_status(
            f"Found {len(devices)} device(s). "
            "Checking common ports..."
        )

        total_devices = len(devices)

        if total_devices > 0:

            for index, device in enumerate(
                devices,
                start=1
            ):

                ports = scan_ports(
                    device["ip"]
                )

                device["ports"] = ports

                # Find matching row
                for item in tree.get_children():

                    values = tree.item(
                        item,
                        "values"
                    )

                    if values[0] == device["ip"]:

                        tree.item(
                            item,
                            values=(
                                device["ip"],
                                device["mac"],
                                device["hostname"],
                                device["status"],
                                ports
                            )
                        )

                        break

                update_progress(
                    70 + (
                        index / total_devices * 30
                    )
                )

                update_status(
                    f"Checking ports... "
                    f"{index}/{total_devices}"
                )

        # ----------------------------------------------------
        # FINISHED
        # ----------------------------------------------------

        progress["value"] = 100

        update_status(
            f"Scan complete — "
            f"{len(devices)} device(s) found."
        )

    except Exception as e:

        messagebox.showerror(
            "Scan Error",
            str(e)
        )

        update_status(
            "Scan failed."
        )

    finally:

        root.after(
            0,
            lambda: scan_button.config(
                state="normal"
            )
        )


# ============================================================
# START SCAN
# ============================================================

def start_scan():

    thread = threading.Thread(
        target=scan_network,
        daemon=True
    )

    thread.start()


# ============================================================
# EXPORT CSV
# ============================================================

def export_csv():

    items = tree.get_children()

    if not items:

        messagebox.showwarning(
            "No Data",
            "There are no scan results."
        )

        return

    filename = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[
            ("CSV files", "*.csv"),
            ("All files", "*.*")
        ]
    )

    if not filename:
        return

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP Address",
            "MAC Address",
            "Hostname",
            "Status",
            "Open Ports"
        ])

        for item in items:

            writer.writerow(
                tree.item(
                    item,
                    "values"
                )
            )

    messagebox.showinfo(
        "Export Complete",
        "CSV file created successfully."
    )


# ============================================================
# EXPORT JSON
# ============================================================

def export_json():

    items = tree.get_children()

    if not items:

        messagebox.showwarning(
            "No Data",
            "There are no scan results."
        )

        return

    filename = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[
            ("JSON files", "*.json"),
            ("All files", "*.*")
        ]
    )

    if not filename:
        return

    results = []

    for item in items:

        values = tree.item(
            item,
            "values"
        )

        results.append({
            "ip_address": values[0],
            "mac_address": values[1],
            "hostname": values[2],
            "status": values[3],
            "open_ports": values[4]
        })

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    messagebox.showinfo(
        "Export Complete",
        "JSON file created successfully."
    )


# ============================================================
# GUI
# ============================================================

root = tk.Tk()

root.title(
    "Network Scanner"
)

root.geometry(
    "1100x650"
)

root.minsize(
    900,
    550
)


# ============================================================
# TITLE
# ============================================================

title = tk.Label(
    root,
    text="🔍 NETWORK SCANNER",
    font=("Segoe UI", 22, "bold")
)

title.pack(
    pady=(20, 5)
)


# ============================================================
# NETWORK INFORMATION
# ============================================================

network_label = tk.Label(
    root,
    text="Detecting network...",
    font=("Segoe UI", 11)
)

network_label.pack(
    pady=5
)


# ============================================================
# BUTTONS
# ============================================================

button_frame = tk.Frame(
    root
)

button_frame.pack(
    pady=15
)


scan_button = ttk.Button(
    button_frame,
    text="🔎 Scan Network",
    command=start_scan
)

scan_button.grid(
    row=0,
    column=0,
    padx=5
)


clear_button = ttk.Button(
    button_frame,
    text="🗑 Clear",
    command=clear_results
)

clear_button.grid(
    row=0,
    column=1,
    padx=5
)


csv_button = ttk.Button(
    button_frame,
    text="📄 Export CSV",
    command=export_csv
)

csv_button.grid(
    row=0,
    column=2,
    padx=5
)


json_button = ttk.Button(
    button_frame,
    text="📦 Export JSON",
    command=export_json
)

json_button.grid(
    row=0,
    column=3,
    padx=5
)


# ============================================================
# PROGRESS BAR
# ============================================================

progress = ttk.Progressbar(
    root,
    mode="determinate",
    length=500,
    maximum=100
)

progress.pack(
    pady=5
)


# ============================================================
# RESULTS FRAME
# ============================================================

table_frame = tk.Frame(
    root
)

table_frame.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=10
)


# ============================================================
# TABLE
# ============================================================

columns = (
    "IP",
    "MAC",
    "Hostname",
    "Status",
    "Open Ports"
)

tree = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings"
)


tree.heading(
    "IP",
    text="IP Address"
)

tree.heading(
    "MAC",
    text="MAC Address"
)

tree.heading(
    "Hostname",
    text="Hostname"
)

tree.heading(
    "Status",
    text="Status"
)

tree.heading(
    "Open Ports",
    text="Open Ports"
)


tree.column(
    "IP",
    width=140
)

tree.column(
    "MAC",
    width=180
)

tree.column(
    "Hostname",
    width=230
)

tree.column(
    "Status",
    width=100
)

tree.column(
    "Open Ports",
    width=380
)


scrollbar = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=tree.yview
)

tree.configure(
    yscrollcommand=scrollbar.set
)


tree.pack(
    side="left",
    fill="both",
    expand=True
)

scrollbar.pack(
    side="right",
    fill="y"
)


# ============================================================
# STATUS
# ============================================================

status_label = tk.Label(
    root,
    text="Ready",
    font=("Segoe UI", 10)
)

status_label.pack(
    pady=10
)


# ============================================================
# INITIAL NETWORK DETECTION
# ============================================================

try:

    local_ip, network = get_local_network()

    network_label.config(
        text=f"Network: {network}   |   Your IP: {local_ip}"
    )

except:

    network_label.config(
        text="Network detection failed"
    )


# ============================================================
# START
# ============================================================

root.mainloop()