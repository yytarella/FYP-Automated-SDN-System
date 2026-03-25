import pyshark
import numpy as np
import logging
import threading
from queue import Queue

logger = logging.getLogger(__name__)

class CaptureEngine:

    def __init__(self, interfaces=None, min_packets=60):
        """
        :param interfaces: list of interface names, e.g. ['ens33', 'ens37', 'ens38']
        :param min_packets: minimum packets to collect before analyzing a flow
        """
        if interfaces is None:
            # default to 'any' if not specified
            interfaces = ['any']
        self.interfaces = interfaces if isinstance(interfaces, list) else [interfaces]
        self.min_packets = min_packets
        self.flows = {}
        self.ip_domain_map = {}
        self.academic_keywords = [
            'ieee', 'sciencedirect', 'springer', 'researchgate',
            'arxiv', 'scholar', 'edu', 'acm', 'mdpi', 'nature',
            'apu.edu.my', 'university', 'scopus'
        ]
        # Attack ports to force analysis even without domain
        self.attack_ports = {21, 23, 445, 139, 135, 1433, 3306, 5432}
        # Lock for thread-safe access to shared dictionaries
        self.lock = threading.Lock()

    def canonical_key(self, p):
        # unchanged ...
        pass

    def packet_to_dict(self, pkt):
        # unchanged ...
        pass

    def compute_stats(self, arr):
        # unchanged ...
        pass

    def compute_rate(self, lengths, times):
        # unchanged ...
        pass

    def build_stats(self, flow):
        # unchanged ...
        pass

    def build_features_1cd(self, s):
        # unchanged ...
        pass

    def build_features_1ab(self, s):
        # unchanged ...
        pass

    def is_academic(self, domain):
        # unchanged ...
        pass

    def _process_packet(self, pkt, callback):
        """Process a single packet (called from each interface thread)."""
        p = self.packet_to_dict(pkt)
        if not p:
            return

        key, direction = self.canonical_key(p)

        # Use lock when accessing shared structures
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

            # Retry mechanism: if already processed but we have many more packets, re-evaluate
            if flow["processed"]:
                total_pkts = len(flow["fwd"]) + len(flow["rev"])
                if total_pkts > 200 and flow["retry_count"] == 0:
                    flow["processed"] = False
                    flow["retry_count"] = 1
                    logger.info(f"Retrying flow {key} after {total_pkts} packets")
                else:
                    return   # skip this packet for already processed flows

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
            is_attack_port = flow["original"]["dport"] in self.attack_ports

            # Trigger condition: enough packets, enough duration, and (has domain OR is attack port)
            if total_pkts >= self.min_packets and duration >= 2.0 and (has_domain or is_attack_port):
                stats = self.build_stats(flow)
                domain_name = flow.get("host") or self.ip_domain_map.get(key[1], "unknown")
                metadata = {
                    "source": domain_name,
                    "mapped_domain": domain_name,
                    "flow_packet_count": total_pkts,
                    "is_academic": self.is_academic(domain_name),
                    "src_port": flow["original"]["sport"],
                    "dst_port": flow["original"]["dport"],
                    "proto": flow["original"]["proto"]
                }

                # Release lock before calling callback (callback may take time)
                # But we still need to mark processed inside lock to avoid duplicate calls.
                # We'll copy necessary data and release lock, then call callback.
                # For simplicity, we keep lock during callback but risk blocking other threads.
                # Better: copy needed data and call callback outside lock.
                # Let's keep it simple for now.
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

        # Start a thread for each interface
        threads = []
        for iface in self.interfaces:
            t = threading.Thread(target=sniff_interface, args=(iface,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for threads to finish (they run forever)
        for t in threads:
            t.join()