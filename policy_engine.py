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
            ".edu", ".ac.", ".gov", "university", "college", "campus", "library",
            "moodle", "blackboard", "canvas", "ieee", "springer",
            "sciencedirect", "researchgate", "scholar", "arxiv", "github",
            "stackoverflow", "w3schools", "coursera", "zoom", "zoom.us", "teams", "teams.live",
            'google-classroom', 'scopus', 'library', 'thesis', 'conference',
            'journal', 'journals', 'mdpi', 'college', 'nature', 'science', 'mendeley',
            'article', 'meet.google', 'colab', "mail.google"
        ]

        self.global_safe_list = [
            'google', 'gstatic', 'akamai', 'cloudfront', 'microsoft',
            'github', 'youtube', 'ieee', 'sciencedirect', 'researchgate',
            'crazygames', 'netflix', 'twitch', 'spotify', 'steamstatic',
            'steampowered', 'ytimg', 'googlevideo', 'chatgpt', 'gemini',
            'deepseek', 'perplexity', 'grok', 'weibo', 'bilibili', 'facebook', 'instagram',
            'reddit', 'rednote', 'fortinet', 'cisco', 'kaggle', 'datahub',
            'dailymotion', 'notion', 'plex', 'primevideo', 'trivago', 'airbnb',
            'aws', 'whatsapp', 'tiktok', 'dropbox', 'twitter', 'outlook', 'gmail'
        ]

        # Known attack ports – used ONLY as a SUSPICIOUS FEATURE, not decisive alone.
        self.attack_ports = {21, 22, 23, 25, 445, 139, 135, 1433, 3306, 5432, 6667, 31337, 4444, 5555}
        # Safe/common ports (no forced action, but may affect decision thresholds)
        self.safe_ports = {80, 443, 53, 123, 993, 995, 22, 3389}
        # Web ports (80,443,8080,8443) – treat with extra care to avoid false IP blocks
        self.web_ports = {80, 443, 8080, 8443}

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

    def _block(self, block_type, reason, metadata):
        """Helper to create a BLOCK decision with a specific granularity.
        block_type: 'flow' – drop only this connection (dst IP+port)
                    'source' – block the source IP entirely
        """
        return {
            "action": "BLOCK",
            "block_type": block_type,
            "priority": "NONE",
            "reason": reason,
            "source_identified": metadata.get("src_ip", "unknown")
        }

    def decide(self, ml_result, source=None, metadata=None):
        # Extract context
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)
        dst_port = metadata.get("dst_port", 0) if metadata else 0
        src_ip = metadata.get("src_ip")
        proto = metadata.get("proto", "")

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()
        has_domain = (final_source != "unknown" and not all(c.isdigit() or c == '.' for c in final_source))
        is_web_port = dst_port in self.web_ports
        is_suspicious_port = dst_port in self.attack_ports

        # 1. Safe domain list always allowed
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

        # 2. Academic identification (only for named domains, never for raw IPs)
        if final_source == "unknown":
            final_academic_status = False
        else:
            is_edu_domain = self.is_academic_domain(final_source)
            is_edu_ml = ml_result.get("academic", 0) == 1
            final_academic_status = is_edu_domain or is_edu_ml

        # 3. Attack handling – no unconditional port block!
        if is_attack == 1:
            # For web ports, be extremely conservative: even high confidence -> flow block, not source block
            if is_web_port:
                if confidence >= 0.95 and packet_count >= 100:
                    logger.warning(f"[POLICY] High confidence attack on web port {dst_port}, but using FLOW block (no IP block): {final_source}")
                    return self._block("flow", f"High-confidence web threat (conf={confidence:.2f})", metadata)
                elif confidence >= 0.80:
                    # Still suspicious – drop only the flow
                    logger.info(f"[POLICY] Medium confidence web attack -> flow block: {final_source}")
                    return self._block("flow", f"Medium-confidence web attack (conf={confidence:.2f})", metadata)
                else:
                    # Low confidence – allow and let QoS handle it (maybe low priority)
                    logger.info(f"[POLICY] Attack flag ignored for low confidence web traffic: {final_source}")
                    # fall through to normal QoS

            # Non‑web ports (including FTP, SSH, etc.)
            else:
                # For non‑web, we can be more decisive, but still require high confidence
                if confidence >= 0.95 and packet_count >= 50:
                    logger.warning(f"[POLICY] Verified attack on non‑web port {dst_port} -> SOURCE block for {src_ip}")
                    return self._block("source", f"High-confidence attack (conf={confidence:.2f})", metadata)
                elif confidence >= 0.80:
                    logger.warning(f"[POLICY] Moderate confidence attack on {dst_port} -> FLOW block")
                    return self._block("flow", f"Medium-confidence attack (conf={confidence:.2f})", metadata)
                else:
                    # Very low confidence: allow but give low priority
                    logger.info(f"[POLICY] Attack flag insufficient, allowing as low priority: {final_source}")

        # 4. Additional check: direct IP access to web ports without any domain – treat as suspicious but only flow block
        if not has_domain and is_web_port and packet_count < 20:
            # Likely a scan or a simple HTTP request to an IP. Do not block IP, just low priority.
            logger.info(f"[POLICY] Direct IP web access -> low priority, no IP block: {final_source}")
            return {
                "action": "ALLOW",
                "priority": "LOW",
                "score": -3,
                "reason": "Direct IP web access (low confidence)",
                "source_identified": final_source
            }

        # 5. Normal QoS scoring
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