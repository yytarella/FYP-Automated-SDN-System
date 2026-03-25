import pyshark
import numpy as np
import logging

logger = logging.getLogger(__name__)


class CaptureEngine:

    def __init__(self, interface="ens37", min_packets=50):
        self.interface = interface
        self.min_packets = min_packets
        self.flows = {}
        self.academic_ip_cache = {}
        self.ip_domain_map = {}

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
            return {
                "mean": 0, "var": 0, "min": 0, "max": 0,
                "q1": 0, "q3": 0
            }

        return {
            "mean": np.mean(arr),
            "var": np.var(arr) if len(arr) > 1 else 0,
            "min": np.min(arr),
            "max": np.max(arr),
            "q1": np.percentile(arr, 25),
            "q3": np.percentile(arr, 75)
        }

    def compute_rate(self, lengths, times):
        if len(times) < 2:
            return {"mean": 0, "var": 0, "min": 0, "max": 0}

        duration = max(times[-1] - times[0], 0.1)

        bps_series = [l / duration for l in lengths]
        pps_series = [1 / duration for _ in lengths]

        return {
            "bps": {
                "mean": np.mean(bps_series),
                "var": np.var(bps_series),
                "min": np.min(bps_series),
                "max": np.max(bps_series)
            },
            "pps": {
                "mean": np.mean(pps_series),
                "var": np.var(pps_series),
                "min": np.min(pps_series),
                "max": np.max(pps_series)
            }
        }

    def build_stats(self, flow):

        f_times = [x[0] for x in flow["fwd"]]
        f_lens = [x[1] for x in flow["fwd"]]

        r_times = [x[0] for x in flow["rev"]]
        r_lens = [x[1] for x in flow["rev"]]

        f_iat = np.diff(f_times) if len(f_times) > 1 else []
        r_iat = np.diff(r_times) if len(r_times) > 1 else []

        return {
            "f_pl": self.compute_stats(f_lens),
            "f_piat": self.compute_stats(f_iat),
            "r_pl": self.compute_stats(r_lens),
            "r_piat": self.compute_stats(r_iat),
            "f_rate": self.compute_rate(f_lens, f_times),
            "r_rate": self.compute_rate(r_lens, r_times),
            "packet_count": len(f_lens) + len(r_lens),
            "flow_duration": flow["last_seen"] - flow["start"]
        }

    # Capture features: tier1cd
    def build_features_1cd(self, s):

        return [
            s["f_pl"]["mean"],
            s["f_pl"]["var"],
            s["f_pl"]["min"],
            s["f_pl"]["max"],
            s["f_pl"]["q1"],
            s["f_pl"]["q3"],

            s["f_piat"]["mean"],
            s["f_piat"]["var"],
            s["f_piat"]["min"],
            s["f_piat"]["max"],
            s["f_piat"]["q1"],
            s["f_piat"]["q3"],

            s["r_pl"]["mean"],
            s["r_pl"]["var"],
            s["r_pl"]["min"],
            s["r_pl"]["max"],
            s["r_pl"]["q1"],
            s["r_pl"]["q3"],

            s["r_piat"]["mean"],
            s["r_piat"]["var"],
            s["r_piat"]["min"],
            s["r_piat"]["max"],
            s["r_piat"]["q1"],
            s["r_piat"]["q3"],

            s["packet_count"],
            s["flow_duration"]
        ]

    # Capture Features: tier1ab
    def build_features_1ab(self, s):

        return [
            s["f_rate"]["bps"]["max"],
            s["f_rate"]["bps"]["mean"],
            s["f_rate"]["bps"]["min"],
            s["f_rate"]["bps"]["var"],

            s["f_piat"]["max"],
            s["f_piat"]["mean"],
            s["f_piat"]["min"],
            s["f_piat"]["q1"],
            s["f_piat"]["q3"],
            s["f_piat"]["var"],

            s["f_pl"]["max"],
            s["f_pl"]["mean"],
            s["f_pl"]["min"],
            s["f_pl"]["q1"],
            s["f_pl"]["q3"],
            s["f_pl"]["var"],

            s["f_rate"]["pps"]["max"],
            s["f_rate"]["pps"]["mean"],
            s["f_rate"]["pps"]["min"],
            s["f_rate"]["pps"]["var"],

            s["r_rate"]["bps"]["max"],
            s["r_rate"]["bps"]["mean"],
            s["r_rate"]["bps"]["min"],
            s["r_rate"]["bps"]["var"],

            s["r_piat"]["max"],
            s["r_piat"]["mean"],
            s["r_piat"]["min"],
            s["r_piat"]["q1"],
            s["r_piat"]["q3"],
            s["r_piat"]["var"],

            s["r_pl"]["max"],
            s["r_pl"]["mean"],
            s["r_pl"]["min"],
            s["r_pl"]["q1"],
            s["r_pl"]["q3"],
            s["r_pl"]["var"],

            s["r_rate"]["pps"]["max"],
            s["r_rate"]["pps"]["mean"],
            s["r_rate"]["pps"]["min"],
            s["r_rate"]["pps"]["var"]
        ]

    def capture(self, callback):

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
                    "host": p.get("host"),
                    "processed": False
                }

            flow = self.flows[key]

            if flow["processed"]:
                continue

            flow["last_seen"] = p["time"]

            if p.get("host"):
                flow["host"] = p["host"]

                self.ip_domain_map[key[1]] = p["host"]

            # host = flow.get("host")
            # dst_ip = key[1]

            # if host:
            #     host_l = host.lower()

            #     academic_keywords = [
            #         "ieee", "acm", "springer", "sciencedirect",
            #         "elsevier", "wiley", "jstor", "arxiv",
            #         "researchgate", "scholar.google"
            #     ]

            #     if any(k in host_l for k in academic_keywords):
            #         self.academic_ip_cache[dst_ip] = True

            if direction == "fwd":
                flow["fwd"].append((p["time"], p["length"]))
            else:
                flow["rev"].append((p["time"], p["length"]))

            total_pkts = len(flow["fwd"]) + len(flow["rev"])
            duration = flow["last_seen"] - flow["start"]

            if total_pkts < self.min_packets or duration < 5.0:
                continue

            stats = self.build_stats(flow)

            features_1cd = self.build_features_1cd(stats)
            features_1ab = self.build_features_1ab(stats)

            metadata = {
                "source": flow.get("host") or "unknown",
                "dst_ip": key[1],
                "mapped_domain": self.ip_domain_map.get(key[1])
            }

            callback(features_1cd, features_1ab, metadata)

            flow["processed"] = True