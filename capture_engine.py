import pyshark
import numpy as np
import logging

logger = logging.getLogger(__name__)


class CaptureEngine:

    def __init__(self, interface="WiFi", min_packets=10):
        self.interface = interface
        self.min_packets = min_packets
        self.flows = {}

    # Flow key bidirectional
    def canonical_key(self, p):
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])

        if a <= b:
            return (p["src"], p["dst"], p["sport"], p["dport"], p["proto"]), "fwd"
        else:
            return (p["dst"], p["src"], p["dport"], p["sport"], p["proto"]), "rev"

    # Packet Parsing
    def packet_to_dict(self, pkt):
        try:
            return {
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "sport": pkt[pkt.transport_layer].srcport,
                "dport": pkt[pkt.transport_layer].dstport,
                "length": int(pkt.length),
                "time": float(pkt.sniff_timestamp),
                "proto": pkt.transport_layer,
                "host": getattr(pkt, "host", "unknown")
            }
        except:
            return None

    # Basic Stats
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

    # Rate Stats (bps / pps)
    def compute_rate_stats(self, lengths, times):

        if len(times) < 2:
            return [0, 0, 0, 0], [0, 0, 0, 0]

        duration = times[-1] - times[0]

        if duration <= 0:
            return [0, 0, 0, 0], [0, 0, 0, 0]

        bps = sum(lengths) / duration
        pps = len(lengths) / duration

        # match training structure: max, mean, min, var
        return [bps, bps, bps, 0], [pps, pps, pps, 0]

    # Build unified stats
    def build_base_stats(self, flow):

        f = flow["fwd"]
        r = flow["rev"]

        f_times = [x[0] for x in f]
        f_lens = [x[1] for x in f]

        r_times = [x[0] for x in r]
        r_lens = [x[1] for x in r]

        duration = flow["last_seen"] - flow["start"]

        f_iat = np.diff(f_times) if len(f_times) > 1 else []
        r_iat = np.diff(r_times) if len(r_times) > 1 else []

        f_bps, f_pps = self.compute_rate_stats(f_lens, f_times)
        r_bps, r_pps = self.compute_rate_stats(r_lens, r_times)

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
            "flow_duration": duration
        }

    # Feature builder for 1cd
    def build_features_1cd(self, stats):

        return [
            *stats["forward_pl"],
            *stats["forward_piat"],
            *stats["reverse_pl"],
            *stats["reverse_piat"],
            stats["packet_count"],
            stats["flow_duration"]
        ]

    # Feature builder for 1ab
    def build_features_1ab(self, stats):

        return [
            *stats["forward_bps"],
            *stats["forward_piat"],
            *stats["forward_pl"],
            *stats["forward_pps"],

            *stats["reverse_bps"],
            *stats["reverse_piat"],
            *stats["reverse_pl"],
            *stats["reverse_pps"]
        ]

    # Main capture loop
    def capture(self, callback):

        logger.info(f"Starting capture on {self.interface}")

        cap = pyshark.LiveCapture(interface=self.interface)

        for pkt in cap.sniff_continuously():

            p = self.packet_to_dict(pkt)
            if p is None:
                continue

            key, direction = self.canonical_key(p)

            if key not in self.flows:
                self.flows[key] = {
                    "start": p["time"],
                    "last_seen": p["time"],
                    "fwd": [],
                    "rev": [],
                    "host": p.get("host", "unknown")
                }

            flow = self.flows[key]
            flow["last_seen"] = p["time"]

            if direction == "fwd":
                flow["fwd"].append((p["time"], p["length"]))
            else:
                flow["rev"].append((p["time"], p["length"]))

            total_pkts = len(flow["fwd"]) + len(flow["rev"])

            if total_pkts >= self.min_packets:

                stats = self.build_base_stats(flow)

                features_1cd = self.build_features_1cd(stats)
                features_1ab = self.build_features_1ab(stats)

                metadata = {
                    "source": flow.get("host", "unknown")
                }

                callback(features_1cd, features_1ab, metadata)

                # clear flow
                del self.flows[key]