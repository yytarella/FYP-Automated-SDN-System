import logging
from ml_engine import MLEngine
from policy_engine import QoSPolicyEngine

logger = logging.getLogger(__name__)


class QoSRuntime:

    def __init__(self):
        self.ml_engine = MLEngine()
        self.policy_engine = QoSPolicyEngine()

    def process_flow(self, features, metadata=None):

        ml_result = self.ml_engine.infer(features, metadata)

        decision = self.policy_engine.decide(ml_result)

        self.execute(decision, ml_result)

        return decision

    def execute(self, decision, ml_result):

        if decision["action"] == "BLOCK":
            logger.warning(f"[BLOCK] {ml_result.get('description', '')}")

        else:
            logger.info(
                f"[ALLOW] Priority={decision['priority']} "
                f"| Score={decision['score']}"
            )