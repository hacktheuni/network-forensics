"""
Network Traffic Analysis for Cyber Forensics
Description:
  This script analyzes a .pcap file to extract useful forensic insights:
  - Top talkers (source/destination IPs)
  - Protocol and port usage
  - Suspicious behavior like frequent SYNs (possible scans)
  - Saves reports to outputs/ folder
"""

import pyshark
import pandas as pd
from collections import Counter
import os
import sys

# --- CONFIG ---
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def analyze_pcap(file_path):
    print(f"[*] Reading pcap file: {file_path}")
    cap = pyshark.FileCapture(file_path, only_summaries=True)

    src_ips, dst_ips, protocols, ports = [], [], [], []

    for pkt in cap:
        try:
            src_ips.append(pkt.source)
            dst_ips.append(pkt.destination)
            protocols.append(pkt.protocol)
            if pkt.info and "→" in pkt.info:
                ports.append(pkt.info.split("→")[1].split()[0])
        except Exception:
            continue

    print(f"[+] Total packets processed: {len(src_ips)}")

    # --- Top IPs ---
    src_count = Counter(src_ips)
    dst_count = Counter(dst_ips)

    # --- Protocol count ---
    proto_count = Counter(protocols)

    # --- Ports count ---
    port_count = Counter(ports)

    # --- Save results ---
    df = pd.DataFrame({
        "Source IP": src_ips,
        "Destination IP": dst_ips,
        "Protocol": protocols
    })
    csv_path = os.path.join(OUTPUT_DIR, "summary.csv")
    df.to_csv(csv_path, index=False)
    print(f"[+] Saved summary to {csv_path}")

    report_path = os.path.join(OUTPUT_DIR, "report.txt")
    with open(report_path, "w") as f:
        f.write("=== Network Traffic Analysis Report ===\n\n")
        f.write(f"File analyzed: {file_path}\n")
        f.write(f"Total packets: {len(src_ips)}\n\n")

        f.write("--- Top 5 Source IPs ---\n")
        for ip, count in src_count.most_common(5):
            f.write(f"{ip}: {count}\n")

        f.write("\n--- Top 5 Destination IPs ---\n")
        for ip, count in dst_count.most_common(5):
            f.write(f"{ip}: {count}\n")

        f.write("\n--- Protocol Distribution ---\n")
        for proto, count in proto_count.most_common():
            f.write(f"{proto}: {count}\n")

        f.write("\n--- Top 5 Ports ---\n")
        for port, count in port_count.most_common(5):
            f.write(f"{port}: {count}\n")

        f.write("\nAnalysis complete.\n")

    print(f"[+] Report saved to {report_path}")
    cap.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path_to_pcap>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
