import time
from scapy.all import Ether, IP, TCP, UDP, DNS, ARP, DNSQR


def parse_packet(packet) -> dict:
    result = {
        "timestamp": time.time(),
        "protocol": "UNKNOWN",
        "ethernet": None,
        "ip": None,
        "tcp": None,
        "udp": None,
        "dns": None,
        "arp": None,
    }

    # --- Ethernet ---
    if packet.haslayer(Ether):
        eth = packet[Ether]
        result["ethernet"] = {
            "src": eth.src,
            "dst": eth.dst,
            "type": _ether_type(eth.type),
        }

    # --- ARP ---
    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["arp"] = {
            "op": "request" if arp.op == 1 else "reply",
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "src_mac": arp.hwsrc,
            "dst_mac": arp.hwdst,
        }
        return result

    # --- IP ---
    if packet.haslayer(IP):
        ip = packet[IP]
        result["ip"] = {
            "src": ip.src,
            "dst": ip.dst,
            "ttl": ip.ttl,
            "protocol": ip.proto,
        }

        # --- TCP ---
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result["protocol"] = "TCP"
            result["tcp"] = {
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "flags": _tcp_flags(tcp.flags),
                "service": _port_to_service(tcp.dport),
            }

            # --- DNS over TCP (port 53) ---
            if packet.haslayer(DNS):
                result["protocol"] = "DNS"
                result["dns"] = _parse_dns(packet)

        # --- UDP ---
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            result["protocol"] = "UDP"
            result["udp"] = {
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "length": udp.len,
                "service": _port_to_service(udp.dport),
            }

            # --- DNS over UDP (port 53) ---
            if packet.haslayer(DNS):
                result["protocol"] = "DNS"
                result["dns"] = _parse_dns(packet)

    return result


# --- Pomocne funkcije ---

def _parse_dns(packet) -> dict:
    dns = packet[DNS]
    query = None
    if dns.qd and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
    return {
        "id": dns.id,
        "type": "response" if dns.qr else "query",
        "query": query,
        "answer_count": dns.ancount,
    }


def _tcp_flags(flags) -> str:
    flag_map = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
    }
    return " ".join(flag_map[f] for f in str(flags) if f in flag_map) or "NONE"


def _port_to_service(port: int) -> str:
    services = {
        80:   "HTTP",
        443:  "HTTPS",
        53:   "DNS",
        22:   "SSH",
        21:   "FTP",
        25:   "SMTP",
        110:  "POP3",
        143:  "IMAP",
        3306: "MySQL",
        5432: "PostgreSQL",
    }
    return services.get(port, str(port))


def _ether_type(code: int) -> str:
    types = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
    }
    return types.get(code, hex(code))
