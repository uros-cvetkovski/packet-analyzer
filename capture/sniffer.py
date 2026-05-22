import threading
import queue
import time
from scapy.all import sniff, get_if_list


class PacketSniffer:
    def __init__(self, interface=None, max_queue=1000):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=max_queue)
        self._stop_flag = threading.Event()
        self._thread = None
        self._stats = {
            "captured": 0,
            "dropped": 0,
            "start_time": None,
        }

    def start(self):
        if self._thread and self._thread.is_alive():
            print("Sniffer vec radi.")
            return

        self._stop_flag.clear()
        self._stats["captured"] = 0
        self._stats["dropped"] = 0
        self._stats["start_time"] = time.time()

        self._thread = threading.Thread(target=self._capture, daemon=True)
        self._thread.start()
        print(f"Sniffer pokrenut na interfejsu: {self.interface or 'default'}")

    def stop(self):
        self._stop_flag.set()
        if self._thread:
            self._thread.join(timeout=3)
        print("Sniffer zaustavljen.")

    def _capture(self):
        while not self._stop_flag.is_set():
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_flag.is_set(),
                timeout=1,
            )

    def _handle_packet(self, packet):
        try:
            self.packet_queue.put_nowait(packet)
            self._stats["captured"] += 1
        except queue.Full:
            self._stats["dropped"] += 1

    def get_packet(self, timeout=1):
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stats(self):
        elapsed = 0
        if self._stats["start_time"]:
            elapsed = round(time.time() - self._stats["start_time"], 1)
        return {
            "captured": self._stats["captured"],
            "dropped": self._stats["dropped"],
            "elapsed_seconds": elapsed,
            "queue_size": self.packet_queue.qsize(),
        }

    @staticmethod
    def list_interfaces():
        return get_if_list()
