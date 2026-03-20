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

    def process_flow(self, features_1cd, features_1ab, metadata):

        try:
            # 1. Attack detection (Tier1CD)
            attack_pred = self.ml_engine.model_cd.predict([features_1cd])[0]

            if attack_pred == 1:
                logger.warning(f"[ATTACK BLOCKED] Source={metadata.get('source')}")
                return

            # 2. Behaviour + Academic (Tier1A + 1B)
            behaviour = self.ml_engine.model_a.predict([features_1ab])[0]
            academic = self.ml_engine.model_b.predict([features_1ab])[0]

            ml_result = {
                "attack": 0,
                "behaviour": str(behaviour).lower(),
                "academic": int(academic)
            }

            # 3. Policy decision
            decision = self.policy_engine.decide(ml_result)

            # 4. Logging (user-friendly output)
            logger.info(
                f"[FLOW] {metadata.get('source', 'unknown')} | "
                f"Behaviour={ml_result['behaviour']} | "
                f"Academic={ml_result['academic']} | "
                f"Priority={decision['priority']} | "
                f"Score={decision['score']}"
            )

        except Exception as e:
            logger.error(f"Pipeline error: {e}")

    # Run system
    def run(self):

        logger.info("Starting QoS ML System...")

        self.capture_engine.capture(self.process_flow)

# Entry point
if __name__ == "__main__":

    system = QoSSystem()
    system.run()