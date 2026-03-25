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
            "media": -3
        }

        # Optimized keyword list for substring matching
        self.academic_keywords = [
            ".edu", ".ac.", "university", "college", "campus", "library",
            "moodle", "blackboard", "canvas", "ieee", "springer", 
            "sciencedirect", "researchgate", "scholar", "arxiv", "github",
            "stackoverflow", "w3schools", "coursera", "zoom", "teams"
        ]

    def is_academic_domain(self, source):
        """Validates if the source domain belongs to academic resources."""
        if not source or source == "unknown":
            return False

        source_clean = str(source).lower().strip()
        for keyword in self.academic_keywords:
            if keyword in source_clean:
                return True
        return False

    def compute_score(self, behaviour, is_academic_flag):
        """Calculates final QoS score based on behaviour and domain status."""
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
        return score

    def decide(self, ml_result, source=None, metadata=None):
        """Refined decision logic to eliminate false positives on known safe domains."""
    
        # 1. DATA EXTRACTION
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("conf", 0)
        
        # Identify domain from both possible sources
        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # 2. GLOBAL SAFE LIST (Non-negotiable Pass)
        # These domains should NEVER be blocked regardless of ML output
        safe_keywords = ['google', 'ieee', 'youtube', 'sciencedirect', 'akamai', 'github', 'microsoft']
        is_safe_domain = any(kw in final_source for kw in safe_keywords)

        # 3. ACADEMIC IDENTIFICATION
        is_edu = self.is_academic_domain(final_source)
        ml_academic = ml_result.get("academic", 0) == 1
        final_academic_status = is_edu or ml_academic

        # 4. MITIGATION STRATEGY (The "Anti-False-Positive" Shield)
        if is_attack == 1:
            # CONDITION A: If it's a known safe or academic domain, FORCE ALLOW
            if is_safe_domain or final_academic_status:
                logger.info(f"[POLICY] Shielded safe domain from ML misclassification: {final_source}")
                is_attack = 0 # Override ML
            
            # CONDITION B: Only block if flow is mature AND confidence is near absolute
            # Increased packet_count to 100 to ensure we have seen enough of the flow
            elif packet_count < 100 or confidence < 0.99:
                logger.info(f"[POLICY] Suppressed attack flag for immature/uncertain flow: {final_source}")
                is_attack = 0 # Override ML

        # 5. FINAL BLOCK/PASS DECISION
        if is_attack == 1:
            return {
                "action": "BLOCK", 
                "priority": "NONE", 
                "reason": f"Confirmed Threat (Conf: {confidence}, Pkts: {packet_count})"
            }

        # 6. QOS SCORING & PRIORITY
        score = self.compute_score(
            ml_result.get("behaviour", "unknown"),
            final_academic_status
        )

        priority = "LOW"
        if score >= 8: priority = "HIGH"
        elif score >= 1: priority = "MEDIUM"

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": "Academic Priority" if final_academic_status else "Standard Flow",
            "source_identified": final_source
        }