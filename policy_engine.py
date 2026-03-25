import logging

logger = logging.getLogger(__name__)

class QoSPolicyEngine:

    def __init__(self):
        self.weights = {
            "academic": 10,
            "interactive": 2,
            "background": -1,
            "bulk": -2,
            "media": -3
        }

        self.academic_keywords = [
            ".edu", ".ac.", "university", "college", "campus", "library",
            "moodle", "blackboard", "canvas", "ieee", "springer",
            "sciencedirect", "researchgate", "scholar", "arxiv", "github",
            "stackoverflow", "w3schools", "coursera", "zoom", "teams"
        ]

        # Domains that are never blocked and also not considered academic by default
        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft',
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate',
            'crazygames', 'youtube', 'netflix', 'twitch', 'spotify'
        ]

    def is_academic_domain(self, source):
        """Check if domain contains academic keywords."""
        if not source or source == "unknown":
            return False
        source_clean = str(source).lower().strip()
        return any(kw in source_clean for kw in self.academic_keywords)

    def compute_score(self, behaviour, is_academic_flag):
        """Calculate QoS score based on behaviour and academic flag."""
        score = 0
        if is_academic_flag:
            score += self.weights["academic"]

        label = str(behaviour).lower()
        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]
        elif "background" in label:
            score += self.weights["background"]
        elif "bulk" in label:
            score += self.weights["bulk"]
        elif "media" in label or "stream" in label:
            score += self.weights["media"]
        elif is_academic_flag and label == "unknown":
            # Fallback: unknown academic flows get interactive priority
            score += self.weights["interactive"]
        return score

    def decide(self, ml_result, source=None, metadata=None):
        # Extract context
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # Determine safe domain (infrastructure, entertainment, etc.)
        is_safe_domain = any(kw in final_source for kw in self.global_safe_list)

        # Academic identification: domain-based has higher trust than ML
        is_edu_domain = self.is_academic_domain(final_source)
        is_edu_ml = ml_result.get("academic", 0) == 1
        # Only consider ML academic if domain is not in safe list (to avoid false positives on YouTube etc.)
        if is_safe_domain:
            final_academic_status = is_edu_domain
        else:
            final_academic_status = is_edu_domain or is_edu_ml

        # --- Early allow for safe domains (no academic bonus unless domain says so) ---
        if is_safe_domain:
            if is_attack == 1:
                logger.info(f"[POLICY] Safe domain overrides attack flag: {final_source}")
            # Compute score using correct academic status (which is false for pure safe domains)
            score = self.compute_score(ml_result.get("behaviour", "unknown"), final_academic_status)
            priority = "HIGH" if score >= 8 else ("MEDIUM" if score >= 1 else "LOW")
            return {
                "action": "ALLOW",
                "priority": priority,
                "score": score,
                "reason": "Safe Domain Override",
                "source_identified": final_source
            }

        # --- Attack handling for non-safe domains ---
        if is_attack == 1:
            # Do not block if immature or low confidence
            if packet_count < 100:
                logger.info(f"[POLICY] Attack flag suppressed (immature flow, {packet_count} pkts): {final_source}")
                is_attack = 0
            elif confidence < 0.99:
                logger.info(f"[POLICY] Attack flag suppressed (low confidence {confidence}): {final_source}")
                is_attack = 0

        if is_attack == 1:
            return {
                "action": "BLOCK",
                "priority": "NONE",
                "reason": f"Verified Threat (Conf: {confidence})"
            }

        # --- Normal QoS scoring ---
        behaviour = ml_result.get("behaviour", "unknown")
        score = self.compute_score(behaviour, final_academic_status)

        if score >= 8:
            priority = "HIGH"
        elif score >= 1:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": "Academic Priority" if final_academic_status else "Standard Traffic",
            "source_identified": final_source,
            "ml_behaviour": behaviour
        }