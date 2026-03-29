import logging
import os
import time
from capture_engine import CaptureEngine
from ml_engine import MLEngine
from policy_engine import QoSPolicyEngine
from traffic_shaper import TrafficShaper

# logging setup
# create log directory (requires root for /var/log)
LOG_DIR = "/var/log/qos_system"
os.makedirs(LOG_DIR, exist_ok=True)

# main logger
main_logger = logging.getLogger("main")
main_logger.setLevel(logging.INFO)
main_handler = logging.FileHandler(f"{LOG_DIR}/qos.log")
main_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
main_logger.addHandler(main_handler)

# output to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
main_logger.addHandler(console_handler)

# attack logger
attack_logger = logging.getLogger("attack")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler(f"{LOG_DIR}/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
attack_logger.addHandler(attack_handler)
attack_logger.propagate = False   # Do not send to root/main logger

logger = main_logger

# QoS system class
class QoSSystem:
    def __init__(self):
        self.capture_engine = CaptureEngine(
            interfaces=['ens33', 'ens37', 'ens38'],
            min_packets=60,
            attack_port_min_packets=30
        )
        self.ml_engine = MLEngine()
        self.policy_engine = QoSPolicyEngine()
        self.traffic_shaper = TrafficShaper(iface="ens37")   # Apply QoS on client-facing interface
        self.traffic_shaper.setup()   # Initialize tc and iptables base

    def process_flow(self, features_cd_dict, features_ab_dict, metadata):
        try:
            # run inference
            ml_result = self.ml_engine.infer(features_cd_dict, features_ab_dict, metadata)

            # policy decision
            decision = self.policy_engine.decide(
                ml_result,
                source=metadata.get("source"),
                metadata=metadata
            )

            if decision["action"] == "BLOCK":
                # log attack to separate attack log file
                attack_logger.info(f"BLOCKED {metadata.get('source', 'unknown')} | {decision.get('reason', 'Attack')}")
                # drop the flow using iptables
                self.traffic_shaper.block_flow(metadata)
                # print to main logger 
                logger.warning(f"[BLOCKED] {metadata.get('source', 'unknown')} | Reason: {decision.get('reason', 'Attack')}")
            
            else:
                print(f"[REAL-TIME] {metadata.get('source', 'unknown')} -> {decision['priority']} (score={decision['score']})")
                # log normal flow to main logger
                logger.info(
                    f"[FLOW] {metadata.get('source', 'unknown')} | "
                    f"Behaviour={ml_result.get('behaviour', 'unknown')} | "
                    f"Academic={ml_result.get('academic', 0)} | "
                    f"Priority={decision['priority']} | "
                    f"Score={decision['score']}"
                )

                # apply QoS shaping for this flow
                self.traffic_shaper.mark_flow(metadata, decision["priority"])
                
                # user-friendly summary
                logger.info(
                    f"Traffic classification: {metadata.get('source', 'unknown')} → priority {decision['priority']}, "
                    f"behaviour={ml_result.get('behaviour', 'unknown')}, academic={ml_result.get('academic', 0)}"
                )

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)

    def run(self):
        logger.info("Starting QoS ML System...")
        
        try:
            self.capture_engine.capture(self.process_flow)

        except KeyboardInterrupt:
            logger.info("Shutting down QoS System...")
            self.traffic_shaper.cleanup()   # remove dynamic iptables rules

if __name__ == "__main__":
    system = QoSSystem()
    system.run()