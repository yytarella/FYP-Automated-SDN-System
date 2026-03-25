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

        # Comprehensive keyword list for Tier 1A (Domain Matching)
        self.academic_keywords = [
            ".edu", ".ac.", "university", "college", "campus", "library",
            "moodle", "blackboard", "canvas", "ieee", "springer", 
            "sciencedirect", "researchgate", "scholar", "arxiv", "github",
            "stackoverflow", "w3schools", "coursera", "zoom", "teams"
        ]
        
        # Domains that should NEVER be blocked (Infrastructure & Research)
        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft', 
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate'
        ]


    def is_academic_domain(self, source):
        """Tier 1A: Hardcoded domain check to guarantee accuracy for known sites."""
        if not source or source == "unknown":
            return False

        source_clean = str(source).lower().strip()
        for keyword in self.academic_keywords:
            if keyword in source_clean:
                return True
        return False

    def compute_score(self, behaviour, is_academic_flag):
        """Calculates QoS score. If ML behaviour is unknown, uses academic status as fallback."""
        score = 0
        
        # 1. Base score from Domain/Academic status
        if is_academic_flag:
            score += self.weights["academic"]

        # 2. Additive score from ML Behaviour
        label = str(behaviour).lower()
        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]
        elif "background" in label:
            score += self.weights["background"]
        elif "bulk" in label:
            score += self.weights["bulk"]
        elif "media" in label or "stream" in label:
            score += self.weights["media"]
        
        # 3. Fallback: If behaviour is unknown but it's academic, 
        # assume it's at least interactive to maintain high priority.
        elif is_academic_flag and label == "unknown":
            score += self.weights["interactive"]

        return score

    def decide(self, ml_result, source=None, metadata=None):
        """
        Main decision logic combining Domain Heuristics (Tier 1A) and ML (Tier 1B).
        Implements high-threshold mitigation to prevent false positive blocks.
        """
        
        # --- 1. CONTEXT EXTRACTION ---
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("conf", 0.0)
        
        # Identify the most reliable source string
        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # --- 2. MULTI-LAYER IDENTIFICATION ---
        # Tier 1A: Domain matching
        is_safe_domain = any(kw in final_source for kw in self.global_safe_list)
        is_edu_domain = self.is_academic_domain(final_source)
        # Tier 1B: ML result
        is_edu_ml = ml_result.get("academic", 0) == 1
        # Final status: Academic if EITHER layer detects it
        final_academic_status = is_edu_domain or is_edu_ml
        # Check against global infrastructure whitelist
        is_safe_infra = any(kw in final_source for kw in self.global_safe_list)

        if is_safe_domain or final_academic_status:
            if is_attack == 1:
                logger.info(f"[POLICY] Shielded safe domain from ML misclassification: {final_source}")
            score = self.compute_score(ml_result.get("behaviour", "unknown"), final_academic_status)
            priority = "HIGH" if score >= 8 else ("MEDIUM" if score >= 1 else "LOW")
            return {
                "action": "ALLOW",
                "priority": priority,
                "score": score,
                "reason": "Safe Domain Override",
                "source_identified": final_source
            }
        
        # --- 3. SECURITY MITIGATION (Anti-False Positive) ---
        if is_attack == 1:
            # SHIELD 1: Don't block known safe or academic sites
            if is_safe_infra or final_academic_status:
                logger.info(f"[POLICY] ML Attack Flag Ignored: Safe Domain ({final_source})")
                is_attack = 0
            
            # SHIELD 2: Don't block immature flows (give more time for feature stability)
            # Increased threshold to 80 packets to reduce handshake misclassification
            elif packet_count < 80:
                logger.info(f"[POLICY] ML Attack Flag Suppressed: Immature Flow ({packet_count} pkts)")
                is_attack = 0
            
            # SHIELD 3: Only block if confidence is near absolute
            elif confidence < 0.995:
                logger.info(f"[POLICY] ML Attack Flag Suppressed: Low Confidence ({confidence})")
                is_attack = 0

        # --- 4. EXECUTION ---
        if is_attack == 1:
            return {
                "action": "BLOCK", 
                "priority": "NONE", 
                "reason": f"Verified Threat (Conf: {confidence})"
            }

        # Scoring Logic
        behaviour = ml_result.get("behaviour", "unknown")
        score = self.compute_score(behaviour, final_academic_status)

        # Priority Mapping
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