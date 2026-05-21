import sys
import os
import time
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from capture.sniffer import PacketSniffer
from analysis.parser import parse_packet

sniffer = PacketSniffer(interface=None)
sniffer.start()

print("Hvatam pakete 5 sekundi...\n")
time.sleep(5)

sniffer.stop()

parsed = []
while True:
    packet = sniffer.get_packet(timeout=0.1)
    if packet is None:
        break
    parsed.append(parse_packet(packet))

print(f"Ukupno parsiranih paketa: {len(parsed)}\n")

for p in parsed[:5]:
    print(json.dumps(p, indent=2))
    print("-" * 50)
