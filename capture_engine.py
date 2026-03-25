import pyshark
import numpy as np
import logging

logger = logging.getLogger(__name__)

class CaptureEngine:

    def __init__(self, interface="ens37", min_packets=20):
        self.interface = interface
        self.min_packets = min_packets
        self.flows = {}
        # Maps IP strings to Domain names discovered via DNS or SNI
        self.ip_domain_map = {} 
        
        # Academic keywords for hardcoded prioritized matching
        self.academic_keywords = [
            'ieee', 'sciencedirect', 'springer', 'researchgate', 
            'arxiv', 'scholar', 'edu', 'acm', 'mdpi', 'nature',
            'apu.edu.my', 'university', 'scopus'
        ]

    def canonical_key(self, p):
        """Generates a consistent 5-tuple key regardless of traffic direction."""
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])

        if a <= b:
            return (p["src"], p["dst"], p["sport"], p["dport"], p["proto"]), "fwd"
        else:
            return (p["dst"], p["src"], p["dport"], p["sport"], p["proto"]), "rev"

    def packet_to_dict(self, pkt):
        """Converts Pyshark packet into a dictionary and extracts SNI/DNS metadata."""
        try:
            if not hasattr(pkt, 'ip'):
                return None
                
            host = None

            # 1. Extract from HTTP Host header
            if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
                host = str(pkt.http.host)

            # 2. Extract from TLS SNI (Server Name Indication)
            elif hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                host = str(pkt.tls.handshake_extensions_server_name)
            
            # 3. Passive DNS Monitoring to map IP to Domain
            elif hasattr(pkt, "dns") and hasattr(pkt.dns, "a"):
                query_name = pkt.dns.qry_name
                resolved_ip = pkt.dns.a
                self.ip_domain_map[str(resolved_ip)] = str(query_name).rstrip('.')

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
        except Exception:
            return None

    def compute_stats(self, arr):
        """Calculates statistical features for packet lengths and IAT."""
        if len(arr) == 0:
            return {"mean": 0, "var": 0, "min": 0, "max": 0, "q1": 0, "q3": 0}

        return {
            "mean": np.mean(arr),
            "var": np.var(arr) if len(arr) > 1 else 0,
            "min": np.min(arr),
            "max": np.max(arr),
            "q1": np.percentile(arr, 25),
            "q3": np.percentile(arr, 75)
        }

    def compute_rate(self, lengths, times):
        """Calculates Byte-per-second and Packet-per-second rates."""
        if len(times) < 2:
            return {"mean": 0, "var": 0, "min": 0, "max": 0}

        duration = max(times[-1] - times[0], 0.1)
        bps_series = [l / duration for l in lengths]
        pps_series = [1 / duration for _ in lengths]

        return {
            "bps": {"mean": np.mean(bps_series), "var": np.var(bps_series), "min": np.min(bps_series), "max": np.max(bps_series)},
            "pps": {"mean": np.mean(pps_series), "var": np.var(pps_series), "min": np.min(pps_series), "max": np.max(pps_series)}
        }

    def build_stats(self, flow):
        """Aggregates flow data into statistical summaries."""
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

    def build_features_1cd(self, s):
        """Strictly follows the trained model's 1CD feature vector structure."""
        return [
            s["f_pl"]["mean"], s["f_pl"]["var"], s["f_pl"]["min"], s["f_pl"]["max"], s["f_pl"]["q1"], s["f_pl"]["q3"],
            s["f_piat"]["mean"], s["f_piat"]["var"], s["f_piat"]["min"], s["f_piat"]["max"], s["f_piat"]["q1"], s["f_piat"]["q3"],
            s["r_pl"]["mean"], s["r_pl"]["var"], s["r_pl"]["min"], s["r_pl"]["max"], s["r_pl"]["q1"], s["r_pl"]["q3"],
            s["r_piat"]["mean"], s["r_piat"]["var"], s["r_piat"]["min"], s["r_piat"]["max"], s["r_piat"]["q1"], s["r_piat"]["q3"],
            s["packet_count"], s["flow_duration"]
        ]

    def build_features_1ab(self, s):
        """Strictly follows the trained model's 1AB feature vector structure."""
        return [
            s["f_rate"]["bps"]["max"], s["f_rate"]["bps"]["mean"], s["f_rate"]["bps"]["min"], s["f_rate"]["bps"]["var"],
            s["f_piat"]["max"], s["f_piat"]["mean"], s["f_piat"]["min"], s["f_piat"]["q1"], s["f_piat"]["q3"], s["f_piat"]["var"],
            s["f_pl"]["max"], s["f_pl"]["mean"], s["f_pl"]["min"], s["f_pl"]["q1"], s["f_pl"]["q3"], s["f_pl"]["var"],
            s["f_rate"]["pps"]["max"], s["f_rate"]["pps"]["mean"], s["f_rate"]["pps"]["min"], s["f_rate"]["pps"]["var"],
            s["r_rate"]["bps"]["max"], s["r_rate"]["bps"]["mean"], s["r_rate"]["bps"]["min"], s["r_rate"]["bps"]["var"],
            s["r_piat"]["max"], s["r_piat"]["mean"], s["r_piat"]["min"], s["r_piat"]["q1"], s["r_piat"]["q3"], s["r_piat"]["var"],
            s["r_pl"]["max"], s["r_pl"]["mean"], s["r_pl"]["min"], s["r_pl"]["q1"], s["r_pl"]["q3"], s["r_pl"]["var"],
            s["r_rate"]["pps"]["max"], s["r_rate"]["pps"]["mean"], s["r_rate"]["pps"]["min"], s["r_rate"]["pps"]["var"]
        ]

    def is_academic(self, domain):
        """Performs keyword matching to identify academic traffic."""
        if not domain or domain == "unknown": return False
        d_low = domain.lower()
        return any(kw in d_low for kw in self.academic_keywords)

    def capture(self, callback):
        """Starts the sniffing loop and triggers the processing callback."""
        logger.info(f"Sniffing on interface: {self.interface}")
        cap = pyshark.LiveCapture(interface=self.interface)

        for pkt in cap.sniff_continuously():
            p = self.packet_to_dict(pkt)
            if not p: continue

            key, direction = self.canonical_key(p)

            if key not in self.flows:
                self.flows[key] = {
                    "start": p["time"], "last_seen": p["time"],
                    "fwd": [], "rev": [], "host": p.get("host"), "processed": False
                }

            flow = self.flows[key]
            if flow["processed"]: continue

            flow["last_seen"] = p["time"]
            if p.get("host"):
                flow["host"] = p["host"]
                # Cache the mapping for destination IP
                self.ip_domain_map[p["dst"]] = p["host"]

            if direction == "fwd": flow["fwd"].append((p["time"], p["length"]))
            else: flow["rev"].append((p["time"], p["length"]))

            # Trigger condition: sufficient packets and duration
            total_pkts = len(flow["fwd"]) + len(flow["rev"])
            duration = flow["last_seen"] - flow["start"]

            if total_pkts >= self.min_packets and duration >= 2.0:
                stats = self.build_stats(flow)
                
                # Retrieve domain from SNI or DNS cache
                domain_name = flow.get("host") or self.ip_domain_map.get(key[1], "unknown")

                metadata = {
                    "source": domain_name,
                    "mapped_domain": domain_name,
                    "flow_packet_count": total_pkts,
                    "is_academic": self.is_academic(domain_name)
                }

                # Send data to main logic
                callback(self.build_features_1cd(stats), self.build_features_1ab(stats), metadata)
                flow["processed"] = True