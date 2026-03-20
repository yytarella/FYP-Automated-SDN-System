import logging

logger = logging.getLogger(__name__)


class QoSPolicyEngine:

    def __init__(self):

        # adjustable weights (NO hardcode behaviour → priority)
        self.weights = {
            "academic": 3,
            "interactive": 1,
            "background": -2,
            "bulk": -1,
            "media": -3   # <- 你要的更严格
        }

    def compute_score(self, behaviour, academic):

        score = 0

        if academic == 1:
            score += self.weights["academic"]

        if behaviour is None:
            return score

        label = behaviour.lower()

        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]

        if "background" in label:
            score += self.weights["background"]

        if "bulk" in label or "file" in label:
            score += self.weights["bulk"]

        if "media" in label or "video" in label or "stream" in label:
            score += self.weights["media"]

        return score

    def decide(self, ml_result):

        if ml_result["attack"] == 1:
            return {
                "action": "BLOCK",
                "priority": "CRITICAL",
                "bandwidth": 0,
                "reason": "ATTACK"
            }

        score = self.compute_score(
            ml_result["behaviour"],
            ml_result["academic"]
        )

        if score >= 3:
            priority = "HIGH"
            bandwidth = "UNLIMITED"
        elif score >= 1:
            priority = "MEDIUM"
            bandwidth = "MODERATE"
        else:
            priority = "LOW"
            bandwidth = "LIMITED"

        return {
            "action": "ALLOW",
            "priority": priority,
            "bandwidth": bandwidth,
            "score": score,
            "reason": "ADAPTIVE_POLICY"
        }