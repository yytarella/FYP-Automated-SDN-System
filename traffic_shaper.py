import subprocess
import logging

logger = logging.getLogger(__name__)

class TrafficShaper:
    def __init__(self, iface='ens37'):
        """
        Initialize traffic shaper.
        :param iface: outgoing interface to apply QoS
        """
        self.iface = iface
        self.prio_map = {
            "HIGH": 10,     # mark value 10 -> classid 1:10
            "MEDIUM": 20,   # mark value 20 -> classid 1:20
            "LOW": 30       # mark value 30 -> classid 1:30
        }
        self.chain = "QOS"

    def setup(self):
        """
        Reset all QoS rules and apply base HTB qdisc.
        Call this once at program startup.
        """
        self._clear_iptables()
        self._setup_htb()
        logger.info("QoS base configuration applied (HTB with 3 classes).")

    def _clear_iptables(self):
        """Remove all previous iptables rules related to our chain."""
        subprocess.run(f"iptables -t mangle -F {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -D PREROUTING -j {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -X {self.chain} 2>/dev/null", shell=True)

    def _setup_htb(self):
        """
        Apply HTB qdisc with 3 classes (HIGH, MEDIUM, LOW) with bandwidth limits.
        Adjust rate/ceil according to your link speed.
        """
        # Remove existing qdisc
        subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True)

        # Root HTB, default class is LOW (1:30)
        subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: htb default 30", shell=True)

        # Total bandwidth assumed 100 Mbit (100000 kbit). Adjust as needed.
        total_rate = 100000   # kbit
        high_rate = 50000
        medium_rate = 30000
        low_rate = 10000

        # Add classes
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate {high_rate}kbit ceil {total_rate}kbit", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:20 htb rate {medium_rate}kbit ceil {total_rate}kbit", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:30 htb rate {low_rate}kbit ceil {total_rate}kbit", shell=True)

        # Add FIFO qdiscs (or use sfq for fairness)
        subprocess.run(f"tc qdisc add dev {self.iface} parent 1:10 handle 10: pfifo limit 1000", shell=True)
        subprocess.run(f"tc qdisc add dev {self.iface} parent 1:20 handle 20: pfifo limit 1000", shell=True)
        subprocess.run(f"tc qdisc add dev {self.iface} parent 1:30 handle 30: pfifo limit 1000", shell=True)

        # Create iptables chain for classification
        subprocess.run(f"iptables -t mangle -N {self.chain}", shell=True)
        subprocess.run(f"iptables -t mangle -I PREROUTING -j {self.chain}", shell=True)

        logger.info(f"HTB qdisc on {self.iface} with rate limits (HIGH:{high_rate}k, MEDIUM:{medium_rate}k, LOW:{low_rate}k).")

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
        Add iptables rules to classify the flow into the corresponding HTB class.
        """
        mark_value = self.prio_map.get(priority, 30)   # integer mark
        class_id = f"1:{mark_value}"                  # classid like 1:10, 1:20, 1:30

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