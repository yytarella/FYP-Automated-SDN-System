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

        # Ports that are often used for attacks (only these will trigger immediate block)
        self.attack_ports = {21, 22, 23, 25, 445, 139, 135, 1433, 3306, 5432, 6667, 31337, 4444, 5555}
        # Web ports - never block based on port alone, let QoS/ML decide
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

        # 2. Immediate port-based blocking (only for truly dangerous ports)
        # These ports are rarely used for legitimate traffic and are common attack vectors.
        if dst_port in self.attack_ports:
            logger.warning(f"[POLICY] Attack port {dst_port} from {final_source} -> BLOCK (source)")
            return {
                "action": "BLOCK",
                "block_type": "source",
                "priority": "NONE",
                "reason": f"Attack port {dst_port}",
                "source_identified": final_source
            }

        # NOTE: Web ports (80,443,8080,8443) are NOT blocked here, even without a domain.
        # They will be handled by QoS/ML logic below.

        # 3. Academic identification (only for named domains, never for raw IPs)
        if final_source == "unknown":
            final_academic_status = False
        else:
            is_edu_domain = self.is_academic_domain(final_source)
            is_edu_ml = ml_result.get("academic", 0) == 1
            final_academic_status = is_edu_domain or is_edu_ml

        # 4. Attack handling (ML based)
        if is_attack == 1:
            # For web ports: flow block only, even if ML says attack (to avoid IP blocking)
            if is_web_port:
                if confidence >= 0.95 and packet_count >= 100:
                    logger.warning(f"[POLICY] High confidence attack on web port {dst_port}, using FLOW block: {final_source}")
                    return {
                        "action": "BLOCK",
                        "block_type": "flow",
                        "priority": "NONE",
                        "reason": f"High-confidence web threat (conf={confidence:.2f})",
                        "source_identified": final_source
                    }
                elif confidence >= 0.80:
                    logger.info(f"[POLICY] Medium confidence web attack -> flow block: {final_source}")
                    return {
                        "action": "BLOCK",
                        "block_type": "flow",
                        "priority": "NONE",
                        "reason": f"Medium-confidence web attack (conf={confidence:.2f})",
                        "source_identified": final_source
                    }
                else:
                    logger.info(f"[POLICY] Attack flag ignored for low confidence web traffic: {final_source}")
                    # fall through to normal QoS
            else:
                # Non‑web ports: use source block for high confidence attacks
                if confidence >= 0.95 and packet_count >= 50:
                    logger.warning(f"[POLICY] Verified attack on non‑web port {dst_port} -> SOURCE block for {src_ip}")
                    return {
                        "action": "BLOCK",
                        "block_type": "source",
                        "priority": "NONE",
                        "reason": f"High-confidence attack (conf={confidence:.2f})",
                        "source_identified": final_source
                    }
                elif confidence >= 0.80:
                    logger.warning(f"[POLICY] Moderate confidence attack on {dst_port} -> FLOW block")
                    return {
                        "action": "BLOCK",
                        "block_type": "flow",
                        "priority": "NONE",
                        "reason": f"Medium-confidence attack (conf={confidence:.2f})",
                        "source_identified": final_source
                    }
                else:
                    logger.info(f"[POLICY] Attack flag insufficient, allowing as low priority: {final_source}")

        # 5. Direct IP access to web ports – low priority but no block
        if not has_domain and is_web_port and packet_count < 20:
            logger.info(f"[POLICY] Direct IP web access -> low priority, no IP block: {final_source}")
            return {
                "action": "ALLOW",
                "priority": "LOW",
                "score": -3,
                "reason": "Direct IP web access (low confidence)",
                "source_identified": final_source
            }

        # 6. Normal QoS scoring
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