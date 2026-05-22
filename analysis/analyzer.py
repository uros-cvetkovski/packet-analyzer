import threading
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


class PacketAnalyzer:
    def __init__(self, port_scan_threshold=15):
        self.port_scan_threshold = port_scan_threshold
        self._rows = []
        self._lock = threading.Lock()

    # --- Dodavanje paketa ---

    def add_packet(self, parsed: dict):
        row = {
            "timestamp": parsed.get("timestamp"),
            "protocol":  parsed.get("protocol", "UNKNOWN"),
            "src_ip":    parsed.get("ip", {}).get("src") if parsed.get("ip") else None,
            "dst_ip":    parsed.get("ip", {}).get("dst") if parsed.get("ip") else None,
            "ttl":       parsed.get("ip", {}).get("ttl") if parsed.get("ip") else None,
            "src_port":  None,
            "dst_port":  None,
            "flags":     None,
            "service":   None,
            "dns_query": parsed.get("dns", {}).get("query") if parsed.get("dns") else None,
        }

        if parsed.get("tcp"):
            row["src_port"] = parsed["tcp"]["src_port"]
            row["dst_port"] = parsed["tcp"]["dst_port"]
            row["flags"]    = parsed["tcp"]["flags"]
            row["service"]  = parsed["tcp"]["service"]
        elif parsed.get("udp"):
            row["src_port"] = parsed["udp"]["src_port"]
            row["dst_port"] = parsed["udp"]["dst_port"]
            row["service"]  = parsed["udp"]["service"]

        with self._lock:
            self._rows.append(row)

    # --- Statistike ---

    def get_stats(self) -> dict:
        df = self._get_df()
        if df.empty:
            return {"error": "Nema paketa"}

        def to_str_keys(series):
            return {str(k): int(v) for k, v in series.items()}

        return {
            "total_packets":    len(df),
            "protocol_counts":  to_str_keys(df["protocol"].value_counts().head(10)),
            "top_src_ips":      to_str_keys(df["src_ip"].value_counts().head(5)),
            "top_dst_ips":      to_str_keys(df["dst_ip"].value_counts().head(5)),
            "top_dst_ports":    to_str_keys(df["dst_port"].value_counts().head(5)),
            "top_services":     to_str_keys(df["service"].value_counts().head(5)),
            "unique_src_ips":   int(df["src_ip"].nunique()),
            "unique_dst_ports": int(df["dst_port"].nunique()),
        }

    # --- Port scan detekcija ---

    def detect_port_scan(self) -> list:
        df = self._get_df()
        if df.empty:
            return []

        tcp_df = df[df["protocol"].isin(["TCP", "TCP6"])].dropna(subset=["src_ip", "dst_port"])
        port_counts = tcp_df.groupby("src_ip")["dst_port"].nunique()
        suspects = port_counts[port_counts >= self.port_scan_threshold]

        result = []
        for ip, count in suspects.items():
            ports = sorted(tcp_df[tcp_df["src_ip"] == ip]["dst_port"].unique().tolist())
            result.append({
                "ip":           ip,
                "unique_ports": int(count),
                "ports":        [int(p) for p in ports[:20]],
            })
        return result

    # --- Grafici ---

    def plot_protocol_chart(self, save_path=None):
        df = self._get_df()
        counts = df["protocol"].value_counts()

        fig, ax = plt.subplots(figsize=(7, 5))
        bars = ax.bar(counts.index, counts.values, color="steelblue", edgecolor="white")

        ax.bar_label(bars, padding=3)
        ax.set_title("Distribucija protokola")
        ax.set_xlabel("Protokol")
        ax.set_ylabel("Broj paketa")
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

    def plot_timeline(self, save_path=None):
        df = self._get_df()
        df = df.dropna(subset=["timestamp"]).copy()
        df["time"] = pd.to_datetime(df["timestamp"], unit="s")
        df = df.set_index("time")

        timeline = df.resample("1s").size()

        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(timeline.index, timeline.values, color="steelblue", linewidth=1.5)
        ax.fill_between(timeline.index, timeline.values, alpha=0.2, color="steelblue")

        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
        plt.xticks(rotation=30)
        ax.set_title("Paketi kroz vreme (po sekundi)")
        ax.set_xlabel("Vreme")
        ax.set_ylabel("Broj paketa")
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

    # --- Export ---

    def export_csv(self, path: str):
        df = self._get_df()
        df.to_csv(path, index=False)
        print(f"Podaci exportovani: {path} ({len(df)} redova)")

    # --- Interni helper ---

    def _get_df(self) -> pd.DataFrame:
        with self._lock:
            rows_copy = list(self._rows)
        df = pd.DataFrame(rows_copy)
        return df
