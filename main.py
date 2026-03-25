import logging
from capture_engine import CaptureEngine
from ml_engine import MLEngine
from policy_engine import QoSPolicyEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QoSSystem:

    def __init__(self):
        self.capture_engine = CaptureEngine()
        self.ml_engine = MLEngine()
        self.policy_engine = QoSPolicyEngine()

    def process_flow(self, features_cd_dict, features_ab_dict, metadata):
        try:
            ml_result = self.ml_engine.infer(features_cd_dict, features_ab_dict, metadata)

            if ml_result["attack"] == 1:
                logger.warning(f"[ATTACK BLOCKED] Source={metadata.get('source')}")
                return

            behaviour_label = ml_result["behaviour"]

            decision = self.policy_engine.decide(
                {
                    "attack": ml_result["attack"],
                    "behaviour": behaviour_label,
                    "academic": ml_result["academic"],
                    "confidence": ml_result["confidence"]
                },
                source=metadata.get("source"),
                metadata=metadata
            )

            logger.info(
                f"[FLOW] {metadata.get('source', 'unknown')} | "
                f"Behaviour={behaviour_label} | "
                f"Academic={ml_result['academic']} | "
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