import pyshark
import numpy as np
import logging
import threading
import time 

logger = logging.getLogger(__name__)

class CaptureEngine:

    def __init__(self, interfaces=None, min_packets=60, attack_port_min_packets=30):
        """
        Initialize capture engine.
        """
        if interfaces is None:
            interfaces = ['any']
        self.interfaces = interfaces if isinstance(interfaces, list) else [interfaces]
        
        # min packets: minimum packets to collect before analyzing a flow (normal flows)
        self.min_packets = min_packets
        # attack_port_min_packets: lower threshold for flows using known attack ports
        self.attack_port_min_packets = attack_port_min_packets  # <-- new
        self.flows = {}
        self.ip_domain_map = {}

        self.academic_keywords = [
            'ieee', 'sciencedirect', 'springer', 'researchgate',
            'arxiv', 'scholar', 'edu', 'acm', 'mdpi', 'nature',
            'apu.edu.my', 'university', 'scopus', 'oxfordjournals', 
            'cambridge', 'kaggle', 'huggingface', 'moodle', 'microsoft',
            'campus', 'institute', 'schoolof', 'student', 'course', 
            'academy', 'learning', 'stackoverflow', 'tensorflow', 'redhat',
            'cisco', 'kubernetes', 'pytorch', 'school', 'notion', 'grammarly',
            'conference', 'journal', 'citation', 'abstract', 'thesis'
        ]
        # attack ports: known ports often used for exploits (including IRC, FTP, etc.)
        self.attack_ports = {21, 22, 23, 25, 80, 443, 445, 139, 135, 1433, 3306, 5432, 6667, 31337, 4444, 5555, 8080, 8443}
        
        self.flow_timeout = 300 # 5 minutes inactivity cleanup
        self.cleanup_interval = 60 # run cleanup every 60 seconds
        # lock for thread-safe access to shared dictionaries
        self.lock = threading.Lock()
        self._start_flow_cleanup()

    def canonical_key(self, p):
        # generate 5-tuple key for both directions
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])
        if a <= b:
            return (p["src"], p["dst"], p["sport"], p["dport"], p["proto"]), "fwd"
        
        else:
            return (p["dst"], p["src"], p["dport"], p["sport"], p["proto"]), "rev"

    def packet_to_dict(self, pkt):
        # convert pyshark packet to dict, extract source metadata
        try:
            if not hasattr(pkt, 'ip'):
                return None
            host = None
            if hasattr(pkt, "http") and hasattr(pkt.http, "host"):
                host = str(pkt.http.host)
            elif hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                host = str(pkt.tls.handshake_extensions_server_name)
            elif hasattr(pkt, "dns") and hasattr(pkt.dns, "a"):
                query_name = pkt.dns.qry_name
                resolved_ip = pkt.dns.a
                self.ip_domain_map[str(resolved_ip)] = str(query_name).rstrip('.')
            
            # convert ports to int for later comparison
            return {
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "sport": int(pkt[pkt.transport_layer].srcport),
                "dport": int(pkt[pkt.transport_layer].dstport),
                "length": int(pkt.length),
                "time": float(pkt.sniff_timestamp),
                "proto": pkt.transport_layer,
                "host": host
            }
        
        except Exception:
            return None

    def compute_stats(self, arr):
        # basic statistics computation
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
        # calculate bps and pps rates
        if len(times) < 2:
            return {"bps": {"mean": 0, "var": 0, "min": 0, "max": 0},
                    "pps": {"mean": 0, "var": 0, "min": 0, "max": 0}}
        
        duration = max(times[-1] - times[0], 0.1)
        bps_series = [l / duration for l in lengths]
        pps_series = [1 / duration for _ in lengths]
        
        return {
            "bps": {"mean": np.mean(bps_series), "var": np.var(bps_series),
                    "min": np.min(bps_series), "max": np.max(bps_series)},
            "pps": {"mean": np.mean(pps_series), "var": np.var(pps_series),
                    "min": np.min(pps_series), "max": np.max(pps_series)}
        }

    def build_stats(self, flow):
        # aggregate flow data into statistical summary
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
        # return dictionary for tier1cd features (attack detection)
        return {
            "forward_pl_mean": s["f_pl"]["mean"],
            "forward_pl_var": s["f_pl"]["var"],
            "forward_pl_min": s["f_pl"]["min"],
            "forward_pl_max": s["f_pl"]["max"],
            "forward_pl_q1": s["f_pl"]["q1"],
            "forward_pl_q3": s["f_pl"]["q3"],
            "forward_piat_mean": s["f_piat"]["mean"],
            "forward_piat_var": s["f_piat"]["var"],
            "forward_piat_min": s["f_piat"]["min"],
            "forward_piat_max": s["f_piat"]["max"],
            "forward_piat_q1": s["f_piat"]["q1"],
            "forward_piat_q3": s["f_piat"]["q3"],
            "reverse_pl_mean": s["r_pl"]["mean"],
            "reverse_pl_var": s["r_pl"]["var"],
            "reverse_pl_min": s["r_pl"]["min"],
            "reverse_pl_max": s["r_pl"]["max"],
            "reverse_pl_q1": s["r_pl"]["q1"],
            "reverse_pl_q3": s["r_pl"]["q3"],
            "reverse_piat_mean": s["r_piat"]["mean"],
            "reverse_piat_var": s["r_piat"]["var"],
            "reverse_piat_min": s["r_piat"]["min"],
            "reverse_piat_max": s["r_piat"]["max"],
            "reverse_piat_q1": s["r_piat"]["q1"],
            "reverse_piat_q3": s["r_piat"]["q3"],
            "packet_count": s["packet_count"],
            "flow_duration": s["flow_duration"]
        }

    def build_features_1ab(self, s):
        # return dictionary for tier1ab features (behaviour & academic context)
        return {
            "forward_bps_max": s["f_rate"]["bps"]["max"],
            "forward_bps_mean": s["f_rate"]["bps"]["mean"],
            "forward_bps_min": s["f_rate"]["bps"]["min"],
            "forward_bps_var": s["f_rate"]["bps"]["var"],
            "forward_piat_max": s["f_piat"]["max"],
            "forward_piat_mean": s["f_piat"]["mean"],
            "forward_piat_min": s["f_piat"]["min"],
            "forward_piat_q1": s["f_piat"]["q1"],
            "forward_piat_q3": s["f_piat"]["q3"],
            "forward_piat_var": s["f_piat"]["var"],
            "forward_pl_max": s["f_pl"]["max"],
            "forward_pl_mean": s["f_pl"]["mean"],
            "forward_pl_min": s["f_pl"]["min"],
            "forward_pl_q1": s["f_pl"]["q1"],
            "forward_pl_q3": s["f_pl"]["q3"],
            "forward_pl_var": s["f_pl"]["var"],
            "forward_pps_max": s["f_rate"]["pps"]["max"],
            "forward_pps_mean": s["f_rate"]["pps"]["mean"],
            "forward_pps_min": s["f_rate"]["pps"]["min"],
            "forward_pps_var": s["f_rate"]["pps"]["var"],
            "reverse_bps_max": s["r_rate"]["bps"]["max"],
            "reverse_bps_mean": s["r_rate"]["bps"]["mean"],
            "reverse_bps_min": s["r_rate"]["bps"]["min"],
            "reverse_bps_var": s["r_rate"]["bps"]["var"],
            "reverse_piat_max": s["r_piat"]["max"],
            "reverse_piat_mean": s["r_piat"]["mean"],
            "reverse_piat_min": s["r_piat"]["min"],
            "reverse_piat_q1": s["r_piat"]["q1"],
            "reverse_piat_q3": s["r_piat"]["q3"],
            "reverse_piat_var": s["r_piat"]["var"],
            "reverse_pl_max": s["r_pl"]["max"],
            "reverse_pl_mean": s["r_pl"]["mean"],
            "reverse_pl_min": s["r_pl"]["min"],
            "reverse_pl_q1": s["r_pl"]["q1"],
            "reverse_pl_q3": s["r_pl"]["q3"],
            "reverse_pl_var": s["r_pl"]["var"],
            "reverse_pps_max": s["r_rate"]["pps"]["max"],
            "reverse_pps_mean": s["r_rate"]["pps"]["mean"],
            "reverse_pps_min": s["r_rate"]["pps"]["min"],
            "reverse_pps_var": s["r_rate"]["pps"]["var"]
        }

    def is_academic(self, domain):
        # check if domain contains self defined academic keywords
        if not domain or domain == "unknown":
            return False
        
        d_low = domain.lower()
        return any(kw in d_low for kw in self.academic_keywords)

    def _process_packet(self, pkt, callback):
        # process into a single packet (called from each interface thread)
        p = self.packet_to_dict(pkt)
        if not p:
            return

        key, direction = self.canonical_key(p)

        with self.lock:
            if key not in self.flows:
                self.flows[key] = {
                    "start": p["time"], "last_seen": p["time"],
                    "fwd": [], "rev": [], "host": p.get("host"), "processed": False,
                    "retry_count": 0,
                    "original": {
                        "src": p["src"], "dst": p["dst"],
                        "sport": p["sport"], "dport": p["dport"],
                        "proto": p["proto"]
                    }
                }

            flow = self.flows[key]

            if flow["processed"]:
                total_pkts = len(flow["fwd"]) + len(flow["rev"])
                if total_pkts > 200 and flow["retry_count"] == 0:
                    flow["processed"] = False
                    flow["retry_count"] = 1
                    logger.info(f"Retrying flow {key} after {total_pkts} packets")
                else:
                    return

            flow["last_seen"] = p["time"]
            if p.get("host"):
                flow["host"] = p["host"]
                self.ip_domain_map[p["dst"]] = p["host"]

            if direction == "fwd":
                flow["fwd"].append((p["time"], p["length"]))
            
            else:
                flow["rev"].append((p["time"], p["length"]))

            total_pkts = len(flow["fwd"]) + len(flow["rev"])
            duration = flow["last_seen"] - flow["start"]
            has_domain = flow.get("host") is not None or key[1] in self.ip_domain_map
            dst_port = flow["original"]["dport"]  # already int
            is_attack_port = dst_port in self.attack_ports
            is_low_port_without_domain = (dst_port < 1024) and not has_domain
            is_web_without_domain = (dst_port in {80, 443}) and not has_domain
            
            # immediate handling for attack ports (no packet count delay)
            if is_attack_port and not flow["processed"]:
                stats = self.build_stats(flow)
                domain_name = flow.get("host") or self.ip_domain_map.get(key[1], "unknown")
                metadata = {
                    "source": domain_name,
                    "mapped_domain": domain_name,
                    "flow_packet_count": total_pkts,
                    "is_academic": self.is_academic(domain_name),
                    "src_port": flow["original"]["sport"],
                    "dst_port": flow["original"]["dport"],
                    "proto": flow["original"]["proto"],
                    "src_ip": flow["original"]["src"],
                    "dst_ip": flow["original"]["dst"]
                }
                callback(
                    self.build_features_1cd(stats),
                    self.build_features_1ab(stats),
                    metadata
                )
                flow["processed"] = True
                return

            # determine required packet threshold based on flow type
            required_packets = self.min_packets
            if is_attack_port or is_low_port_without_domain or is_web_without_domain:
                required_packets = self.attack_port_min_packets

            if total_pkts >= required_packets and duration >= 2.0 and (has_domain or is_attack_port or is_low_port_without_domain or is_web_without_domain):
                stats = self.build_stats(flow)
                domain_name = flow.get("host") or self.ip_domain_map.get(key[1], "unknown")
                metadata = {
                    "source": domain_name,
                    "mapped_domain": domain_name,
                    "flow_packet_count": total_pkts,
                    "is_academic": self.is_academic(domain_name),
                    "src_port": flow["original"]["sport"],
                    "dst_port": flow["original"]["dport"],
                    "proto": flow["original"]["proto"],
                    "src_ip": flow["original"]["src"],   
                    "dst_ip": flow["original"]["dst"] 
                }

                callback(
                    self.build_features_1cd(stats),
                    self.build_features_1ab(stats),
                    metadata
                )
                flow["processed"] = True

    def capture(self, callback):
        """
        Start sniffing on all interfaces simultaneously.
        Each interface runs in a separate thread.
        """
        logger.info(f"Starting capture on interfaces: {self.interfaces}")

        def sniff_interface(iface):
            logger.info(f"Sniffing on interface: {iface}")
            cap = pyshark.LiveCapture(interface=iface)
            for pkt in cap.sniff_continuously():
                self._process_packet(pkt, callback)

        threads = []
        for iface in self.interfaces:
            t = threading.Thread(target=sniff_interface, args=(iface,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def _start_flow_cleanup(self):
        # periodically remove stale flows to free memory       
        def cleanup_old_flows():
            now = time.time()
            with self.lock:
                to_delete = [k for k, f in self.flows.items()
                             if now - f["last_seen"] > self.flow_timeout]
                for k in to_delete:
                    del self.flows[k]
                if to_delete:
                    logger.info(f"[Cleanup] Removed {len(to_delete)} stale flows")

            # schedule for next cleanup
            threading.Timer(self.cleanup_interval, cleanup_old_flows).start()

        # start the first cleanup after interval seconds
        threading.Timer(self.cleanup_interval, cleanup_old_flows).start()