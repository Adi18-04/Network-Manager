import os
from scapy.all import rdpcap, TCP, UDP, ICMP
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime
import matplotlib.ticker as mticker

# -------------------- Setup Output Folder --------------------

os.makedirs("outputs", exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
run_folder = os.path.join("outputs", f"scan_{timestamp}")
os.makedirs(run_folder, exist_ok=True)
print(f"[+] Results will be saved in: {run_folder}")

# -------------------- User Input --------------------

while True:
    try:
        capture_duration = int(input("Enter capture duration in seconds: "))
        if capture_duration <= 0:
            print("Please enter a positive number.")
            continue
        break
    except ValueError:
        print("Invalid input. Please enter a number.")

interface = "eth0"  # Change if needed

# Define file paths
capture_file = os.path.join(run_folder, "capture.pcap")
summary_file = os.path.join(run_folder, "traffic_summary.csv")
protocol_chart = os.path.join(run_folder, "protocol_usage.png")
top_ips_chart = os.path.join(run_folder, "top_ips.png")
top_ports_chart = os.path.join(run_folder, "top_ports.png")
packet_size_hist = os.path.join(run_folder, "packet_size_hist.png")
packets_over_time_chart = os.path.join(run_folder, "packets_over_time.png")
report_file = os.path.join(run_folder, "network_report.pdf")

# -------------------- Step 1: Capture Traffic --------------------

print(f"[*] Capturing traffic on {interface} for {capture_duration}s...")
os.system(f"sudo timeout {capture_duration} tcpdump -i {interface} -w {capture_file}")
print("[*] Capture complete!")

# -------------------- Step 2: Analyze Traffic --------------------

print("[*] Analyzing capture...")
packets = rdpcap(capture_file)
data = []

for pkt in packets:
    if pkt.haslayer("IP"):
        data.append({
            "time": float(pkt.time),  # Convert Scapy EDecimal to float
            "src": pkt["IP"].src,
            "dst": pkt["IP"].dst,
            "proto": pkt["IP"].proto,
            "length": len(pkt),
            "sport": pkt.sport if hasattr(pkt, "sport") else None,
            "dport": pkt.dport if hasattr(pkt, "dport") else None
        })

df = pd.DataFrame(data)
df.to_csv(summary_file, index=False)
print(f"[*] Summary saved to {summary_file}")

# -------------------- Step 3: Generate Charts --------------------

charts = {}

if not df.empty:
    # Protocol usage
    if 'proto' in df.columns and not df['proto'].empty:
        proto_counts = df['proto'].value_counts()
        if not proto_counts.empty:
            plt.figure(figsize=(6,6))
            proto_counts.plot.pie(autopct="%1.1f%%")
            plt.title("Protocol Usage")
            plt.savefig(protocol_chart)
            plt.close()
            charts['protocol'] = protocol_chart

    # Top IPs
    top_ips = pd.concat([df['src'], df['dst']]).value_counts().head(10)
    if not top_ips.empty:
        plt.figure(figsize=(8,5))
        top_ips.plot.bar(color='salmon')
        plt.title("Top 10 IPs")
        plt.xlabel("IP Address")
        plt.ylabel("Packet Count")
        plt.tight_layout()
        plt.savefig(top_ips_chart)
        plt.close()
        charts['top_ips'] = top_ips_chart

    # Top Ports
    top_sport = df['sport'].dropna().value_counts().head(10)
    top_dport = df['dport'].dropna().value_counts().head(10)
    if not top_dport.empty:
        plt.figure(figsize=(8,5))
        top_dport.plot.bar(color='skyblue')
        plt.title("Top 10 Destination Ports")
        plt.xlabel("Port")
        plt.ylabel("Packet Count")
        plt.tight_layout()
        plt.savefig(top_ports_chart)
        plt.close()
        charts['top_ports'] = top_ports_chart

    # Packet size histogram
    packet_sizes = df['length']
    if not packet_sizes.empty:
        plt.figure(figsize=(8,5))
        plt.hist(packet_sizes, bins=20, color='lightgreen', edgecolor='black')
        plt.title("Packet Size Distribution")
        plt.xlabel("Packet Size (Bytes)")
        plt.ylabel("Frequency")
        plt.tight_layout()
        plt.savefig(packet_size_hist)
        plt.close()
        charts['packet_size'] = packet_size_hist

    # Packets over time
    df['time'] = pd.to_datetime(df['time'], unit='s')
    packets_per_sec = df.set_index('time').resample('1s').count()['src']
    if not packets_per_sec.empty:
        plt.figure(figsize=(10,4))
        packets_per_sec.plot(color='orange')
        plt.title("Packets Over Time")
        plt.xlabel("Time")
        plt.ylabel("Packets per Second")
        plt.tight_layout()
        plt.savefig(packets_over_time_chart)
        plt.close()
        charts['packets_over_time'] = packets_over_time_chart

# -------------------- Step 4: Generate PDF Report --------------------

pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", "B", 16)
pdf.cell(0, 10, "Network Traffic Report", ln=True, align="C")

pdf.set_font("Arial", "", 12)
pdf.ln(10)
pdf.multi_cell(0, 8, f"""
Scan Timestamp: {timestamp}
Interface: {interface}
Capture Duration: {capture_duration} seconds
Total Packets Captured: {len(df)}
""")

# Add charts only if they exist
for title, chart_path in charts.items():
    pdf.ln(5)
    pdf.cell(0, 10, title.replace('_',' ').title(), ln=True)
    pdf.image(chart_path, w=150)

# Summary Tables
if not df.empty:
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0,10,"Summary Tables", ln=True)
    pdf.set_font("Arial", "", 12)
    
    # Packet sizes
    avg_size = df['length'].mean()
    min_size = df['length'].min()
    max_size = df['length'].max()
    pdf.ln(5)
    pdf.multi_cell(0, 8, f"Average Packet Size: {avg_size:.2f} bytes\nMin Packet Size: {min_size} bytes\nMax Packet Size: {max_size} bytes")
    
    # Bytes per protocol
    if 'proto' in df.columns:
        proto_bytes = df.groupby('proto')['length'].sum()
        pdf.ln(5)
        pdf.multi_cell(0, 8, "Bytes per Protocol:\n" + "\n".join([f"{proto}: {size} bytes" for proto, size in proto_bytes.items()]))
    
    # Top Ports
    if not top_sport.empty:
        pdf.ln(5)
        pdf.multi_cell(0, 8, "Top Source Ports:\n" + "\n".join([f"{port}: {count}" for port, count in top_sport.items()]))
    if not top_dport.empty:
        pdf.ln(5)
        pdf.multi_cell(0, 8, "Top Destination Ports:\n" + "\n".join([f"{port}: {count}" for port, count in top_dport.items()]))

pdf.output(report_file)
print(f"[+] Report generated: {report_file}")
print("[✓] Scan completed successfully.")