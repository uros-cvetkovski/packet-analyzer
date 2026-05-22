# Packet Analyzer

A real-time network packet analyzer built with Python. Captures live traffic from a network interface, decodes protocol layers, and displays statistics in a web dashboard.

---

## Screenshots

### Dashboard — initial state
![Empty dashboard](docs/screenshots/empty.png)

### Active capture
![Active capture](docs/screenshots/active.png)

### Heavy traffic
![Heavy traffic](docs/screenshots/traffic.png)

---

## Features

- **Live packet capture** using Scapy with threading and a queue buffer
- **Protocol parsing** — Ethernet, IPv4, IPv6, TCP, UDP, DNS, ARP
- **Real-time dashboard** that updates every 2 seconds
- **Protocol distribution chart** with color-coded bars
- **Activity timeline** showing packets per second
- **Port scan detection** — flags IPs contacting too many ports
- **CSV export** of captured packet data
- **Start / Stop** capture control with frozen display on stop

---

## Tech Stack

| Layer | Technology |
|---|---|
| Capture | Scapy, threading, queue |
| Parsing | Scapy protocol layers |
| Analysis | pandas |
| Visualization | matplotlib (export), Chart.js (web) |
| Web backend | Flask |
| Web frontend | HTML, CSS, JavaScript |

---

## Project Structure

```
packet-analyzer/
├── capture/
│   └── sniffer.py       # PacketSniffer class
├── analysis/
│   ├── parser.py        # Protocol parser
│   └── analyzer.py      # Statistics and port scan detection
├── web/
│   ├── app.py           # Flask application
│   └── templates/
│       └── index.html   # Dashboard
├── tests/
│   ├── test_sniffer.py
│   ├── test_parser.py
│   └── test_analyzer.py
├── exports/             # CSV output
├── docs/screenshots/
└── requirements.txt
```

---

## Installation

**Requirements:** Python 3.11+, macOS or Linux

```bash
# Clone the repository
git clone https://github.com/uros-cvetkovski/packet-analyzer.git
cd packet-analyzer

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

Packet capture requires root privileges to access the network interface.

```bash
# Start the web dashboard
sudo venv/bin/python web/app.py
```

Open **http://127.0.0.1:8080** in your browser, then click **Start**.

---

## Protocols Supported

| Protocol | Info extracted |
|---|---|
| Ethernet | src/dst MAC, frame type |
| IPv4 | src/dst IP, TTL |
| IPv6 | src/dst IP, hop limit |
| TCP | ports, flags (SYN/ACK/FIN...), service name |
| UDP | ports, length, service name |
| DNS | query domain, response type |
| ARP | request/reply, src/dst IP and MAC |
