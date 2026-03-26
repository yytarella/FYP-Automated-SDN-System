import logging
from capture_engine import CaptureEngine
from ml_engine import MLEngine
from policy_engine import QoSPolicyEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QoSSystem:

    def __init__(self):
        self.capture_engine = CaptureEngine(
            # ens33 -> internet, ens37 -> client, ens38 -> victim
            interfaces=['ens33', 'ens37', 'ens38'], 
            min_packets = 60,
            attack_port_min_packets = 30 
        )
        self.ml_engine = MLEngine()
        self.policy_engine = QoSPolicyEngine()

    def process_flow(self, features_cd_dict, features_ab_dict, metadata):
        try:
            # 1. run inference
            ml_result = self.ml_engine.infer(features_cd_dict, features_ab_dict, metadata)

            # 2. policy engine decide
            decision = self.policy_engine.decide(
                ml_result,
                source=metadata.get("source"),
                metadata=metadata
            )

            # 3. log final action
            if decision["action"] == "BLOCK":
                logger.warning(
                    f"[BLOCKED] {metadata.get('source', 'unknown')} | "
                    f"Reason: {decision.get('reason', 'Attack')}"
                )
            else:
                logger.info(
                    f"[FLOW] {metadata.get('source', 'unknown')} | "
                    f"Behaviour={ml_result.get('behaviour', 'unknown')} | "
                    f"Academic={ml_result.get('academic', 0)} | "
                    f"Priority={decision['priority']} | "
                    f"Score={decision['score']}"
                )

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)

    def run(self):
        logger.info("Starting QoS ML System...")
        self.capture_engine.capture(self.process_flow)

if __name__ == "__main__":
    system = QoSSystem()
    system.run()