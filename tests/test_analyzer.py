import sys
import os
import time
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from capture.sniffer import PacketSniffer
from analysis.parser import parse_packet
from analysis.analyzer import PacketAnalyzer

sniffer  = PacketSniffer(interface=None)
analyzer = PacketAnalyzer()

sniffer.start()
print("Hvatam pakete 10 sekundi...\n")
time.sleep(10)
sniffer.stop()

# Dodaj sve pakete u analyzer
while True:
    packet = sniffer.get_packet(timeout=0.1)
    if packet is None:
        break
    analyzer.add_packet(parse_packet(packet))

# Statistike
stats = analyzer.get_stats()
print("=== STATISTIKE ===")
print(json.dumps(stats, indent=2))

# Port scan detekcija
suspects = analyzer.detect_port_scan()
print("\n=== PORT SCAN DETEKCIJA ===")
if suspects:
    for s in suspects:
        print(f"  SUMNJIVO: {s['ip']} kontaktirao {s['unique_ports']} portova")
        print(f"  Portovi: {s['ports']}")
else:
    print("  Nema sumnjivih aktivnosti.")

# Grafici
print("\nGenerisem grafike...")
analyzer.plot_protocol_chart(save_path="exports/protocol_chart.png")
analyzer.plot_timeline(save_path="exports/timeline.png")

# CSV export
analyzer.export_csv("exports/packets.csv")
