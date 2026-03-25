import logging

logger = logging.getLogger(__name__)

class QoSPolicyEngine:

    def __init__(self):
        # Weighting system for QoS prioritization
        self.weights = {
            "academic": 10,
            "interactive": 2,
            "background": -1,
            "bulk": -2,
            "media": -3,
            "entertainment_penalty": -15  # Strong penalty to override misclassifications
        }

        # Keywords for Tier 1A: Academic Validation
        self.academic_keywords = [
            ".edu", ".ac.", "university", "college", "campus", "library",
            "moodle", "blackboard", "canvas", "ieee", "springer",
            "sciencedirect", "researchgate", "scholar", "arxiv", "github",
            "stackoverflow", "w3schools", "coursera", "zoom", "teams"
        ]

        # Keywords for Tier 1A: Entertainment/Gaming (To prevent priority hijacking)
        self.entertainment_keywords = [
            'crazygames', 'poki', 'steam', 'epicgames', 'roblox', 
            'twitch', 'netflix', 'disney', 'spotify', 'soundcloud',
            'game', 'video', 'movie'
        ]

        # Infrastructure domains that are never blocked
        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft',
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate'
        ] + self.entertainment_keywords

    def is_academic_domain(self, source):
        """Validates if the source domain belongs to academic resources."""
        if not source or source == "unknown":
            return False
        source_clean = str(source).lower().strip()
        return any(kw in source_clean for kw in self.academic_keywords)

    def is_entertainment_domain(self, source):
        """Identifies entertainment or gaming traffic to apply strict QoS limits."""
        if not source or source == "unknown":
            return False
        source_clean = str(source).lower().strip()
        return any(kw in source_clean for kw in self.entertainment_keywords)

    def compute_score(self, behaviour, is_academic_flag, is_entertainment_flag):
        """
        Calculates QoS score with an override for entertainment traffic.
        Even if ML misclassifies gaming as 'chat', the entertainment penalty will drop its score.
        """
        score = 0
        
        # 1. Apply Academic Boost
        if is_academic_flag:
            score += self.weights["academic"]

        # 2. Apply Entertainment Penalty (Override ML misclassification)
        if is_entertainment_flag:
            score += self.weights["entertainment_penalty"]

        # 3. Additive Behavioural Score (Tier 1B)
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
            # Fallback for academic flows that are not yet classified
            score += self.weights["interactive"]
            
        return score

    def decide(self, ml_result, source=None, metadata=None):
        # --- 1. CONTEXT EXTRACTION ---
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # --- 2. MULTI-LAYER IDENTIFICATION ---
        is_safe_domain = any(kw in final_source for kw in self.global_safe_list)
        is_edu_domain = self.is_academic_domain(final_source)
        is_game_domain = self.is_entertainment_domain(final_source)
        
        # Academic status: Domain check has priority over ML to avoid false positives on safe list
        is_edu_ml = ml_result.get("academic", 0) == 1
        final_academic_status = is_edu_domain or (is_edu_ml and not is_safe_domain)

        # --- 3. SECURITY MITIGATION (Anti-False Positive) ---
        if is_attack == 1:
            # Shield safe/infrastructure domains and immature flows from blocking
            if is_safe_domain or final_academic_status:
                logger.info(f"[POLICY] Shielded safe domain: {final_source}")
                is_attack = 0
            elif packet_count < 100 or confidence < 0.995:
                logger.info(f"[POLICY] Suppressed attack flag (Immature/Low Confidence): {final_source}")
                is_attack = 0

        if is_attack == 1:
            return {
                "action": "BLOCK",
                "priority": "NONE",
                "reason": f"Verified Threat (Conf: {confidence})"
            }

        # --- 4. QOS SCORING & FINAL DECISION ---
        behaviour = ml_result.get("behaviour", "unknown")
        score = self.compute_score(behaviour, final_academic_status, is_game_domain)

        # Priority Mapping based on calculated score
        if score >= 8:
            priority = "HIGH"
        elif score >= 1:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        # Final metadata for logging and SDN controller
        reason = "Academic Priority" if final_academic_status else ("Entertainment Limit" if is_game_domain else "Standard")
        
        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": reason,
            "source_identified": final_source,
            "ml_behaviour": behaviour
        }