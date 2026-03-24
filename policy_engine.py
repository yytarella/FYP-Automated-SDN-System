class QoSPolicyEngine:

    def __init__(self):
        self.weights = {
            "academic": 2,
            "interactive": 2,
            "background": -2,
            "bulk": -2,
            "media": -3
        }

    def compute_score(self, behaviour, academic):

        score = 0
        label = behaviour.lower() if behaviour else ""

        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]

        if "background" in label:
            score += self.weights["background"]

        if "bulk" in label or "file" in label:
            score += self.weights["bulk"]

        if "media" in label or "video" in label or "stream" in label:
            score += self.weights["media"]

        if academic == 1:
            score += self.weights["academic"]

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

        if score >= 4:
            priority = "HIGH"
            bandwidth = "UNLIMITED"
        elif score >= 2:
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
            "reason": "ML_ONLY_POLICY"
        }