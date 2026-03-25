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
        """Final decision logic for SDN controller with mitigation for false positives."""
        
        # 1. EXTRACT METADATA
        mapped_domain = metadata.get("mapped_domain") if metadata else None
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("conf", 0)
        
        # Check if the domain is academic via our keyword list
        is_edu = self.is_academic_domain(source) or self.is_academic_domain(mapped_domain)

        # 2. ATTACK MITIGATION (False Positive Protection)
        if is_attack == 1:
            # Shielding: Only block if confidence is extremely high AND flow is mature
            if packet_count > 30 and confidence > 0.98:
                # Even if it looks like an attack, if it's a known academic site, we don't block
                if not is_edu:
                    return {
                        "action": "BLOCK", 
                        "priority": "NONE", 
                        "reason": f"Verified Threat (Conf: {confidence})"
                    }
            
            # If not meeting block criteria, we just treat it as a low-priority normal flow
            logger.info(f"[POLICY] Attack flagged but suppressed (Packets: {packet_count}, Conf: {confidence})")

        # 3. QOS SCORING
        # Use ML-detected academic status OR our domain-based check
        ml_academic = ml_result.get("academic", 0) == 1
        final_academic_status = is_edu or ml_academic

        score = self.compute_score(
            ml_result.get("behaviour", "unknown"),
            final_academic_status
        )

        # 4. PRIORITY ASSIGNMENT
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
            "reason": "Academic Priority" if final_academic_status else "Standard Flow",
            "source_identified": source if source != "unknown" else mapped_domain
        }