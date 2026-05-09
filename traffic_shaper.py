import subprocess
import logging
import time

logger = logging.getLogger(__name__)

class TrafficShaper:
    def __init__(self, iface='ens37', log_dir="var/log/qos_system"):
        self.iface = iface
        self.log_dir = log_dir
        self.prio_map = {"HIGH": 10, "MEDIUM": 20, "LOW": 30}
        self.chain = "QOS"

    def setup(self):
        self._clear_iptables()
        self._setup_htb()
        self._setup_filters()
        self._verify_htb_classes()
        logger.info("QoS base configuration applied (HTB with fwmark filters).")

    def _clear_iptables(self):
        subprocess.run(f"iptables -t mangle -F {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -D PREROUTING -j {self.chain} 2>/dev/null", shell=True)
        subprocess.run(f"iptables -t mangle -X {self.chain} 2>/dev/null", shell=True)

    def _setup_htb(self):
        subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True)
        total_rate = 410000   # adjust link speed (kbit)
        high_rate = 330000 # for HIGH prior
        medium_rate = 45000 # for MEDIUM prior
        low_rate = 35000 # for LOW prior

        subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: htb default 30", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate {high_rate}kbit ceil {total_rate}kbit prio 0", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:20 htb rate {medium_rate}kbit ceil {total_rate}kbit prio 1", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:30 htb rate {low_rate}kbit ceil {total_rate}kbit prio 2", shell=True)
        subprocess.run(f"tc qdisc add dev ens37 parent 1:10 handle 10: fq_codel", shell=True)
        subprocess.run(f"tc qdisc add dev ens37 parent 1:20 handle 20: fq_codel", shell=True)
        subprocess.run(f"tc qdisc add dev ens37 parent 1:30 handle 30: fq_codel", shell=True)

    def _setup_filters(self):
        for mark, classid in [(10, "1:10"), (20, "1:20"), (30, "1:30")]:
            subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol all prio 1 handle {mark} fw classid {classid}", shell=True)
        subprocess.run(f"iptables -t mangle -N {self.chain}", shell=True)
        subprocess.run(f"iptables -t mangle -I PREROUTING -j {self.chain}", shell=True)

    def _verify_htb_classes(self):
        for _ in range(5):
            result = subprocess.run(f"tc class show dev {self.iface} | grep -q 'class htb 1:10'", shell=True)
            if result.returncode == 0:
                return
            time.sleep(0.1)
        logger.warning("HTB classes not found, QoS may not work properly.")

    def _rule_exists(self, rule_cmd):
        result = subprocess.run(rule_cmd, shell=True, capture_output=True)
        return result.returncode == 0

    def block_flow(self, metadata, block_mode="source"):
        """
        Block a flow with two possible modes:
        - 'flow'   : drop only packets matching dst_ip+dst_port (connection level)
        - 'source' : additionally block the source IP completely
        """
        dst_ip = metadata.get("dst_ip")
        dst_port = metadata.get("dst_port")
        proto = metadata.get("proto", "").lower()
        src_ip = metadata.get("src_ip")

        if not all([dst_ip, dst_port, proto]):
            logger.warning("Missing dst info for block rule")
            return

        # 1. Always add a rule that drops the specific flow (destination IP+port)
        flow_rule = f"iptables -I FORWARD -p {proto} -d {dst_ip} --dport {dst_port} -j DROP"
        check_flow = f"iptables -C FORWARD -p {proto} -d {dst_ip} --dport {dst_port} -j DROP"
        if not self._rule_exists(check_flow):
            subprocess.run(flow_rule, shell=True)
            logger.info(f"Added flow block rule for {proto} to {dst_ip}:{dst_port}")

        # 2. If block_mode is 'source', also block the source IP entirely
        if block_mode == "source" and src_ip:
            check_ip = f"iptables -C FORWARD -s {src_ip} -j DROP"
            if not self._rule_exists(check_ip):
                subprocess.run(f"iptables -I FORWARD 1 -s {src_ip} -j DROP", shell=True)
                subprocess.run(f"iptables -I INPUT 1 -s {src_ip} -j DROP", shell=True)
                logger.warning(f"[BLOCK-IP] Attacker {src_ip} fully blocked")
                print(f"\nSource IP {src_ip} blocked due to malicious activity.\n")

        # 3. Kill existing conntrack entries to enforce the block immediately
        conntrack_cmd = f"conntrack -D -p {proto} -d {dst_ip} --dport {dst_port}"
        if src_ip:
            conntrack_cmd += f" -s {src_ip}"
        subprocess.run(conntrack_cmd, shell=True, stderr=subprocess.DEVNULL)
        logger.info(f"Killed conntrack entries for {proto} to {dst_ip}:{dst_port}")

        # 4. User-friendly console output
        print("\n================= ATTACK BLOCKED =================")
        print(f"Source (Attacker): {src_ip if src_ip else 'unknown'}")
        print(f"Target: {dst_ip}:{dst_port} ({proto.upper()})")
        print(f"Block mode: {block_mode.upper()}")
        print(f"Action: {'SOURCE IP BLOCKED' if block_mode=='source' else 'FLOW DROPPED'} + CONNECTION TERMINATED")
        print(f"Logs saved to: {self.log_dir}/attacks.log")
        print("===================================================\n")

    def mark_flow(self, metadata, priority):
        mark_value = self.prio_map.get(priority, 30)
        src_ip = metadata.get("src_ip")
        dst_ip = metadata.get("dst_ip")
        src_port = metadata.get("src_port")
        dst_port = metadata.get("dst_port")
        proto = metadata.get("proto", "").lower()
        if not all([src_ip, dst_ip, src_port, dst_port, proto]):
            logger.warning("Missing flow info for QoS marking")
            return

        # Mark the connection
        check_mark = (f"iptables -t mangle -C {self.chain} -p {proto} -s {src_ip} -d {dst_ip} "
                      f"--sport {src_port} --dport {dst_port} -j CONNMARK --set-mark {mark_value}")
        if not self._rule_exists(check_mark):
            mark_rule = (f"iptables -t mangle -A {self.chain} -p {proto} -s {src_ip} -d {dst_ip} "
                         f"--sport {src_port} --dport {dst_port} -j CONNMARK --set-mark {mark_value}")
            subprocess.run(mark_rule, shell=True)

        # Restore mark to each packet
        restore_rule = (f"iptables -t mangle -A {self.chain} -m connmark --mark {mark_value} "
                        f"-j CONNMARK --restore-mark")
        check_restore = (f"iptables -t mangle -C {self.chain} -m connmark --mark {mark_value} "
                         f"-j CONNMARK --restore-mark")
        if not self._rule_exists(check_restore):
            subprocess.run(restore_rule, shell=True)

        logger.info(f"QoS marking added for {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} -> {priority} (mark {mark_value})")

    def cleanup(self):
        subprocess.run(f"iptables -t mangle -F {self.chain}", shell=True)
        logger.info("Dynamic iptables rules cleared.")