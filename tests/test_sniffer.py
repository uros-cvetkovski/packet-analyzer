import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from capture.sniffer import PacketSniffer

print("Dostupni interfejsi:")
for iface in PacketSniffer.list_interfaces():
    print(f"  - {iface}")

sniffer = PacketSniffer(interface=None)  # None = default interfejs
sniffer.start()

print("\nHvatam pakete 5 sekundi...\n")
time.sleep(5)

for _ in range(5):
    packet = sniffer.get_packet()
    if packet:
        print(f"Paket: {packet.summary()}")

sniffer.stop()

stats = sniffer.get_stats()
print(f"\nStatistike:")
print(f"  Uhvaceno:  {stats['captured']}")
print(f"  Ispusteno: {stats['dropped']}")
print(f"  Trajanje:  {stats['elapsed_seconds']}s")
