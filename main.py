import logging
from capture_engine import CaptureEngine
from ml_engine import MLEngine
from policy_engine import QoSPolicyEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def map_behaviour(label):
    mapping = {
        "0": "chat",
        "1": "media",
        "2": "bulk",
        "3": "interactive",
        "4": "background",
        "5": "stream"
    }
    return mapping.get(str(label), "unknown")


class QoSSystem:

    def __init__(self):
        self.capture_engine = CaptureEngine()
        self.ml_engine = MLEngine()
        self.policy_engine = QoSPolicyEngine()

    def process_flow(self, features_1cd, features_1ab, metadata):

        try:
            ml_result = self.ml_engine.infer(features_1cd, features_1ab)

            if ml_result["attack"] == 1:
                logger.warning(f"[ATTACK BLOCKED] Source={metadata.get('source')}")
                return

            behaviour_label = map_behaviour(ml_result["behaviour"])

            decision = self.policy_engine.decide({
                "attack": ml_result["attack"],
                "behaviour": behaviour_label,
                "academic": ml_result["academic"]
            })

            logger.info(
                f"[FLOW] {metadata.get('source', 'unknown')} | "
                f"Behaviour={behaviour_label} | "
                f"Academic={ml_result['academic']} | "
                f"Priority={decision['priority']} | "
                f"Score={decision['score']}"
            )

        except Exception as e:
            logger.error(f"Pipeline error: {e}")

    def run(self):
        logger.info("Starting QoS ML System...")
        self.capture_engine.capture(self.process_flow)


if __name__ == "__main__":
    system = QoSSystem()
    system.run()