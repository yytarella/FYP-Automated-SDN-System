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

        # Domains that are never blocked and not considered academic by default
        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft',
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate',
            'crazygames', 'netflix', 'twitch', 'spotify', 'steamstatic',
            'steampowered', 'ytimg', 'googlevideo'
        ]

    def is_academic_domain(self, source):
        """Check if domain contains academic keywords."""
        if not source or source == "unknown":
            return False
        source_clean = str(source).lower().strip()
        return any(kw in source_clean for kw in self.academic_keywords)

    def compute_score(self, behaviour, is_academic_flag):
        """Calculate QoS score."""
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
            score += self.weights["interactive"]  # fallback
        return score

    def decide(self, ml_result, source=None, metadata=None):
        # Extract context
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # ---- SAFE DOMAIN CHECK (ALWAYS ALLOW) ----
        is_safe_domain = any(kw in final_source for kw in self.global_safe_list)

        if is_safe_domain:
            # These domains are always allowed, regardless of attack flag
            if is_attack == 1:
                logger.info(f"[POLICY] Safe domain overrides attack: {final_source}")
            # Determine academic status for safe domains (only domain-based, ignore ML)
            is_edu_domain = self.is_academic_domain(final_source)
            score = self.compute_score(ml_result.get("behaviour", "unknown"), is_edu_domain)
            priority = "HIGH" if score >= 8 else ("MEDIUM" if score >= 1 else "LOW")
            return {
                "action": "ALLOW",
                "priority": priority,
                "score": score,
                "reason": "Safe Domain Override",
                "source_identified": final_source
            }

        # ---- ACADEMIC IDENTIFICATION FOR NON-SAFE DOMAINS ----
        is_edu_domain = self.is_academic_domain(final_source)
        is_edu_ml = ml_result.get("academic", 0) == 1
        final_academic_status = is_edu_domain or is_edu_ml

        # ---- ATTACK HANDLING (only for non-safe domains) ----
        if is_attack == 1:
            # Require high confidence and enough packets to block
            if packet_count < 100:
                logger.info(f"[POLICY] Attack suppressed (immature flow, {packet_count} pkts): {final_source}")
                is_attack = 0
            elif confidence < 0.995:
                logger.info(f"[POLICY] Attack suppressed (low confidence {confidence}): {final_source}")
                is_attack = 0

        if is_attack == 1:
            return {
                "action": "BLOCK",
                "priority": "NONE",
                "reason": f"Verified Threat (Conf: {confidence})"
            }

        # ---- QOS SCORING ----
        behaviour = ml_result.get("behaviour", "unknown")
        score = self.compute_score(behaviour, final_academic_status)
        priority = "HIGH" if score >= 8 else ("MEDIUM" if score >= 1 else "LOW")

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": "Academic Priority" if final_academic_status else "Standard Traffic",
            "source_identified": final_source,
            "ml_behaviour": behaviour
        }