import subprocess
import logging

logger = logging.getLogger(__name__)

class TrafficShaper:
    def __init__(self, iface='ens37'):
        """
        Initialize traffic shaper.
        :param iface: outgoing interface to apply QoS (e.g., ens33 for internet)
        """
        self.iface = iface
        self.prio_map = {
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 2
        }
        self.chain = "QOS"

    def setup(self):
        """
        Reset all QoS rules and apply base PRIO qdisc.
        Call this once at program startup.
        """
        self._clear_iptables()
        self._setup_prio()
        logger.info("QoS base configuration applied (PRIO with 3 bands).")

    def _clear_iptables(self):
        """Remove all previous iptables rules related to our chain."""
        subprocess.run(f"iptables -t mangle -F {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -D PREROUTING -j {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -X {self.chain} 2>/dev/null", shell=True)

    def _setup_prio(self):
        """Apply PRIO qdisc with 3 bands on the interface."""
        subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True)
        subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: prio bands 3", shell=True)
        # Create iptables chain for classification
        subprocess.run(f"iptables -t mangle -N {self.chain}", shell=True)
        subprocess.run(f"iptables -t mangle -I PREROUTING -j {self.chain}", shell=True)
        logger.info(f"PRIO qdisc on {self.iface} and iptables chain {self.chain} ready.")

    def _rule_exists(self, rule_cmd):
        """
        Check if an iptables rule already exists.
        Returns True if rule exists, False otherwise.
        """
        result = subprocess.run(rule_cmd, shell=True, capture_output=True)
        return result.returncode == 0

    def block_flow(self, metadata):
        """
        Add iptables DROP rule for the attack detected flows.
        """
        src_ip = metadata.get("src_ip")
        dst_ip = metadata.get("dst_ip")
        src_port = metadata.get("src_port")
        dst_port = metadata.get("dst_port")
        proto = metadata.get("proto", "").lower()

        if not all([src_ip, dst_ip, src_port, dst_port, proto]):
            logger.warning("Missing flow info for block rule")
            return

        # Check if rule already exists
        check_cmd = (f"iptables -C FORWARD -p {proto} -s {src_ip} -d {dst_ip} "
                     f"--sport {src_port} --dport {dst_port} -j DROP")

        if not self._rule_exists(check_cmd):
            rule = (f"iptables -I FORWARD -p {proto} -s {src_ip} -d {dst_ip} "
                    f"--sport {src_port} --dport {dst_port} -j DROP")
            subprocess.run(rule, shell=True)
            logger.info(f"Added block rule for {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        else:
            logger.debug(f"Block rule already exists for {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    def mark_flow(self, metadata, priority):
        """
        Add iptables rules to classify the flow into the corresponding PRIO band.
        """
        band = self.prio_map.get(priority, 2)   # default LOW -> 2
        # Use integer mark (1,2,3) for CONNMARK (iptables does not accept colons)
        mark_value = band + 1
        # Classid for tc: 1:1, 1:2, 1:3
        class_id = f"1:{mark_value}"

        src_ip = metadata.get("src_ip")
        dst_ip = metadata.get("dst_ip")
        src_port = metadata.get("src_port")
        dst_port = metadata.get("dst_port")
        proto = metadata.get("proto", "").lower()

        if not all([src_ip, dst_ip, src_port, dst_port, proto]):
            logger.warning("Missing flow info for QoS marking")
            return

        # Rule to mark the connection with integer mark
        mark_rule = (f"iptables -t mangle -A {self.chain} -p {proto} -s {src_ip} -d {dst_ip} "
                     f"--sport {src_port} --dport {dst_port} -j CONNMARK --set-mark {mark_value}")
        check_mark = (f"iptables -t mangle -C {self.chain} -p {proto} -s {src_ip} -d {dst_ip} "
                      f"--sport {src_port} --dport {dst_port} -j CONNMARK --set-mark {mark_value}")

        if not self._rule_exists(check_mark):
            subprocess.run(mark_rule, shell=True)
        else:
            logger.debug(f"CONNMARK rule already exists for {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # Rule to restore mark and classify to tc classid
        classify_rule = (f"iptables -t mangle -A {self.chain} -m connmark --mark {mark_value} "
                         f"-j CLASSIFY --set-class {class_id}")
        check_classify = (f"iptables -t mangle -C {self.chain} -m connmark --mark {mark_value} "
                          f"-j CLASSIFY --set-class {class_id}")

        if not self._rule_exists(check_classify):
            subprocess.run(classify_rule, shell=True)
        else:
            logger.debug(f"CLASSIFY rule already exists for mark {mark_value} -> {class_id}")

        logger.info(f"QoS rule added for {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} -> {priority} (mark {mark_value}, class {class_id})")

    def cleanup(self):
        """Remove all dynamic iptables rules but keep base qdisc."""
        subprocess.run(f"iptables -t mangle -F {self.chain}", shell=True)
        logger.info("Dynamic iptables rules cleared.")