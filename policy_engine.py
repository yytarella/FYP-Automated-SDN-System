import logging

logger = logging.getLogger(__name__)


class QoSPolicyEngine:

    def __init__(self):

        self.weights = {
            "academic": 4,      
            "interactive": 1,
            "background": -2,
            "bulk": -2,
            "media": -3
        }

    def compute_score(self, behaviour, academic):

        score = 0

        if academic == 1:
            score += self.weights["academic"]

        label = behaviour.lower() if behaviour else ""

        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]

        if "background" in label:
            score += self.weights["background"]

        if "bulk" in label:
            score += self.weights["bulk"]

        if "media" in label or "stream" in label:
            score += self.weights["media"]

        return score

    def decide(self, ml_result):

        if ml_result["attack"] == 1:
            return {
                "action": "BLOCK",
                "priority": "CRITICAL",
                "bandwidth": 0
            }

        score = self.compute_score(
            ml_result["behaviour"],
            ml_result["academic"]
        )

        if score >= 4:
            priority = "HIGH"
        elif score >= 2:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score
        }