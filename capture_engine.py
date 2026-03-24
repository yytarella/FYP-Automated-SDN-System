import pyshark
import numpy as np
import logging

logger = logging.getLogger(__name__)


class CaptureEngine:

    def __init__(self, interface="ens37", min_packets=20):
        self.interface = interface
        self.min_packets = min_packets
        self.flows = {}

    def canonical_key(self, p):
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])

        if a <= b:
            return (p["src"], p["dst"], p["sport"], p["dport"], p["proto"]), "fwd"
        else:
            return (p["dst"], p["src"], p["dport"], p["sport"], p["proto"]), "rev"

    def packet_to_dict(self, pkt):
        try:
            host = None

            if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
                host = str(pkt.http.host)

            elif hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                host = str(pkt.tls.handshake_extensions_server_name)

            return {
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "sport": pkt[pkt.transport_layer].srcport,
                "dport": pkt[pkt.transport_layer].dstport,
                "length": int(pkt.length),
                "time": float(pkt.sniff_timestamp),
                "proto": pkt.transport_layer,
                "host": host
            }
        except:
            return None
        
    def compute_stats(self, arr):
        if len(arr) == 0:
            return [0, 0, 0, 0, 0, 0]

        return [
            np.mean(arr),
            np.var(arr) if len(arr) > 1 else 0,
            np.min(arr),
            np.max(arr),
            np.percentile(arr, 25),
            np.percentile(arr, 75)
        ]

    def compute_rate(self, lengths, times):
        if len(times) < 2:
            return [0, 0, 0, 0], [0, 0, 0, 0]

        duration = times[-1] - times[0]

        # prevent explosion
        if duration <= 0:
            duration = 1e-6

        # stabilize duration
        duration = max(duration, 0.1)

        total_bytes = sum(lengths)
        total_packets = len(lengths)

        bps = total_bytes / duration
        pps = total_packets / duration

        # clip extreme values (critical fix)
        bps = min(bps, 1e6)
        pps = min(pps, 1e4)

        return [bps, bps, bps, 0], [pps, pps, pps, 0]

    def build_stats(self, flow):

        f_times = [x[0] for x in flow["fwd"]]
        f_lens = [x[1] for x in flow["fwd"]]

        r_times = [x[0] for x in flow["rev"]]
        r_lens = [x[1] for x in flow["rev"]]

        f_iat = np.diff(f_times) if len(f_times) > 1 else []
        r_iat = np.diff(r_times) if len(r_times) > 1 else []

        f_bps, f_pps = self.compute_rate(f_lens, f_times)
        r_bps, r_pps = self.compute_rate(r_lens, r_times)

        return {
            "forward_pl": self.compute_stats(f_lens),
            "forward_piat": self.compute_stats(f_iat),
            "reverse_pl": self.compute_stats(r_lens),
            "reverse_piat": self.compute_stats(r_iat),

            "forward_bps": f_bps,
            "forward_pps": f_pps,
            "reverse_bps": r_bps,
            "reverse_pps": r_pps,

            "packet_count": len(f_lens) + len(r_lens),
            "flow_duration": flow["last_seen"] - flow["start"]
        }

    def build_features_1cd(self, stats):
        return [
            *stats["forward_pl"],
            *stats["forward_piat"],
            *stats["reverse_pl"],
            *stats["reverse_piat"],
            stats["packet_count"],
            stats["flow_duration"]
        ]

    def build_features_1ab(self, stats):
        features = [
            *stats["forward_bps"],
            *stats["forward_piat"],
            *stats["forward_pl"],
            *stats["forward_pps"],

            *stats["reverse_bps"],
            *stats["reverse_piat"],
            *stats["reverse_pl"],
            *stats["reverse_pps"]
        ]

        # clip all features to avoid model distortion
        features = [min(x, 1e5) for x in features]

        if len(features) < 43:
            features.extend([0] * (43 - len(features)))

        return features

    def capture(self, callback):

        logger.info(f"Starting capture on {self.interface}")
        cap = pyshark.LiveCapture(interface=self.interface)

        for pkt in cap.sniff_continuously():

            p = self.packet_to_dict(pkt)
            if not p:
                continue

            key, direction = self.canonical_key(p)

            if key not in self.flows:
                self.flows[key] = {
                    "start": p["time"],
                    "last_seen": p["time"],
                    "fwd": [],
                    "rev": [],
                    "host": p.get("host")
                }

            flow = self.flows[key]
            flow["last_seen"] = p["time"]

            if p.get("host") and flow.get("host") is None:
                flow["host"] = p["host"]

            if direction == "fwd":
                flow["fwd"].append((p["time"], p["length"]))
            else:
                flow["rev"].append((p["time"], p["length"]))

            total_pkts = len(flow["fwd"]) + len(flow["rev"])
            duration = flow["last_seen"] - flow["start"]

            if total_pkts < 30:
                continue

            if duration < 1.0:
                continue

            if total_pkts % self.min_packets == 0:

                stats = self.build_stats(flow)

                features_1cd = self.build_features_1cd(stats)
                features_1ab = self.build_features_1ab(stats)

                metadata = {
                    "source": flow.get("host") or "unknown"
                }

                callback(features_1cd, features_1ab, metadata)

                flow["fwd"].clear()
                flow["rev"].clear()
                flow["start"] = p["time"]