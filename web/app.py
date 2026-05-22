import sys
import os
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, jsonify, render_template, send_file
from capture.sniffer import PacketSniffer
from analysis.parser import parse_packet
from analysis.analyzer import PacketAnalyzer

app = Flask(__name__)

sniffer  = PacketSniffer(interface=None)
analyzer = PacketAnalyzer()
recent_packets = []

_processor_thread = None
_running = False


# --- Pozadinski thread koji vadi pakete iz queue-a i parsira ih ---

def _process_packets():
    while _running:
        packet = sniffer.get_packet(timeout=0.5)
        if packet:
            parsed = parse_packet(packet)
            analyzer.add_packet(parsed)

            recent_packets.append({
                "protocol": parsed.get("protocol"),
                "src_ip":   parsed.get("ip", {}).get("src") if parsed.get("ip") else None,
                "dst_ip":   parsed.get("ip", {}).get("dst") if parsed.get("ip") else None,
                "service":  (parsed.get("tcp") or parsed.get("udp") or {}).get("service"),
                "flags":    parsed.get("tcp", {}).get("flags") if parsed.get("tcp") else None,
                "dns":      parsed.get("dns", {}).get("query") if parsed.get("dns") else None,
            })

            if len(recent_packets) > 100:
                recent_packets.pop(0)


# --- Rute ---

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start():
    global _processor_thread, _running
    if _running:
        return jsonify({"status": "already_running"})

    _running = True
    sniffer.start()

    _processor_thread = threading.Thread(target=_process_packets, daemon=True)
    _processor_thread.start()

    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def stop():
    global _running
    _running = False
    sniffer.stop()
    # Isprazni queue da ne ostanu zaostali paketi
    while not sniffer.packet_queue.empty():
        try:
            sniffer.packet_queue.get_nowait()
        except Exception:
            break
    return jsonify({"status": "stopped"})


@app.route("/api/stats")
def stats():
    data = analyzer.get_stats()
    data["sniffer"] = sniffer.get_stats()
    data["is_running"] = _running
    return jsonify(data)


@app.route("/api/packets")
def packets():
    return jsonify(list(reversed(recent_packets[-50:])))


@app.route("/api/export/csv")
def export_csv():
    path = os.path.abspath("exports/packets.csv")
    analyzer.export_csv(path)
    return send_file(path, as_attachment=True, download_name="packets.csv")


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=8080)
