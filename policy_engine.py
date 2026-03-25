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

        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft',
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate',
            'crazygames', 'netflix', 'twitch', 'spotify', 'steamstatic',
            'steampowered', 'ytimg', 'googlevideo'
        ]

        # Known safe ports (common services)
        self.safe_ports = {80, 443, 53, 123, 993, 995, 22, 3389}
        # Known attack ports (to block)
        self.attack_ports = {21, 23, 445, 139, 135, 1433, 3306, 5432}

    def is_academic_domain(self, source):
        if not source or source == "unknown":
            return False
        source_clean = str(source).lower().strip()
        return any(kw in source_clean for kw in self.academic_keywords)

    def compute_score(self, behaviour, is_academic_flag):
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
            score += self.weights["interactive"]
        return score

    def _is_attack_likely_false_positive(self, ml_result, metadata):
        """
        Heuristics to determine if the attack flag is likely a false positive.
        Returns True if we believe it's a false positive.
        """
        # 1. Packet count too low
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        if packet_count < 100:
            logger.debug(f"Low packet count ({packet_count}) -> treat as FP")
            return True

        # 2. Confidence too low
        confidence = ml_result.get("confidence", 0.0)
        if confidence < 0.98:
            logger.debug(f"Low confidence ({confidence}) -> treat as FP")
            return True

        # 3. Destination port is safe
        dst_port = metadata.get("dst_port", 0) if metadata else 0
        if dst_port in self.safe_ports:
            logger.debug(f"Safe port {dst_port} -> treat as FP")
            return True

        # 4. Domain is likely safe (CDN, cloud, static)
        source = metadata.get("source", "") if metadata else ""
        if source:
            source_lower = source.lower()
            if any(kw in source_lower for kw in ['cdn', 'cloud', 'static', 'akamai', 'fastly']):
                logger.debug(f"CDN/cloud domain {source} -> treat as FP")
                return True

        # 5. Behaviour classification says normal (chat, media, interactive)
        behaviour = ml_result.get("behaviour", "").lower()
        if behaviour in ["chat", "media", "interactive"]:
            logger.debug(f"Normal behaviour {behaviour} -> treat as FP")
            return True

        # 6. Default: not a false positive
        return False

    def decide(self, ml_result, source=None, metadata=None):
        # Extract context
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)
        dst_port = metadata.get("dst_port", 0) if metadata else 0

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # ---- 1. PORT-BASED ATTACK DETECTION (direct block) ----
        if dst_port in self.attack_ports:
            logger.warning(f"[POLICY] Known attack port {dst_port} from {final_source} -> BLOCK")
            return {
                "action": "BLOCK",
                "priority": "NONE",
                "reason": f"Attack port {dst_port}",
                "source_identified": final_source
            }

        # ---- 2. SAFE DOMAIN CHECK (always allow) ----
        is_safe_domain = any(kw in final_source for kw in self.global_safe_list)
        if is_safe_domain:
            if is_attack == 1:
                logger.info(f"[POLICY] Safe domain overrides attack: {final_source}")
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

        # ---- 3. ACADEMIC IDENTIFICATION FOR NON-SAFE DOMAINS ----
        is_edu_domain = self.is_academic_domain(final_source)
        is_edu_ml = ml_result.get("academic", 0) == 1
        final_academic_status = is_edu_domain or is_edu_ml

        # ---- 4. INTELLIGENT ATTACK HANDLING (with false positive reduction) ----
        if is_attack == 1:
            # Suppress if immature flow
            if packet_count < 100:
                logger.info(f"[POLICY] Attack suppressed (immature flow, {packet_count} pkts): {final_source}")
                is_attack = 0
            elif confidence < 0.99:
                logger.info(f"[POLICY] Attack suppressed (low confidence {confidence}): {final_source}")
                is_attack = 0
            else:
                # Check for likely false positives
                if self._is_attack_likely_false_positive(ml_result, metadata):
                    logger.info(f"[POLICY] Attack flag overridden by false positive heuristics: {final_source}")
                    is_attack = 0
                else:
                    # True positive block
                    return {
                        "action": "BLOCK",
                        "priority": "NONE",
                        "reason": f"Verified Threat (Conf: {confidence})"
                    }

        # ---- 5. QOS SCORING (if not blocked) ----
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