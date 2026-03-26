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
            "stackoverflow", "w3schools", "coursera", "zoom", "teams", 
            'google-classroom', 'scopus', 'library', 'thesis', 'conference',
            'journal', 'journals', 'mdpi', 'college', 'nature', 'science', 'mendeley',
            'article', 'meet.google', 'colab'
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

        # known safe ports (common services)
        self.safe_ports = {80, 443, 53, 123, 993, 995, 22, 3389}
        # known attack ports (to block)
        self.attack_ports = {21, 22, 23, 25, 445, 139, 135, 1433, 3306, 5432, 6667, 31337, 4444, 5555, 8080, 8443}

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
        # extract context
        mapped_domain = metadata.get("mapped_domain", "unknown") if metadata else "unknown"
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        is_attack = ml_result.get("attack", 0)
        confidence = ml_result.get("confidence", 0.0)
        dst_port = metadata.get("dst_port", 0) if metadata else 0

        final_source = str(source if source and source != "unknown" else mapped_domain).lower()

        # 1. port-based attack detection (direct block) 
        if dst_port in self.attack_ports:
            logger.warning(f"[POLICY] Known attack port {dst_port} from {final_source} -> BLOCK")
            return {
                "action": "BLOCK",
                "priority": "NONE",
                "reason": f"Attack port {dst_port}",
                "source_identified": final_source
            }
        
        # 2. web scan detection (ports 80/443 & no domain)
        # check if source is an IP address (when no domain)
        is_ip_source = final_source == "unknown" or all(c.isdigit() or c == '.' for c in final_source)
        
        if dst_port in {80, 443} and is_ip_source:
            if ml_result.get("attack", 0) == 1 or packet_count >= 50:
                logger.warning(f"[POLICY] Suspicious web traffic (IP only) from {final_source} -> BLOCK")
                return {
                    "action": "BLOCK",
                    "priority": "NONE",
                    "reason": "Web scan without domain"
                }

        # 3. safe domain checking (always allow)
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

        # 4. academic identification for non safe domains
        # for unknown sources, never trust ML academic result (avoid IP flows gaining priority)
        if final_source == "unknown":
            final_academic_status = False
        
        else:
            is_edu_domain = self.is_academic_domain(final_source)
            is_edu_ml = ml_result.get("academic", 0) == 1
            final_academic_status = is_edu_domain or is_edu_ml

        # 5. attack handling (distinguish domain vs IP)
        if is_attack == 1:
            # check if flow has a domain name (not an IP address)
            has_domain = (final_source != "unknown" and not all(c.isdigit() or c == '.' for c in final_source))
            
            if has_domain:
                # for flows with domain names (normal web, academic), require very high confidence
                # and enough packets to avoid blocking during handshake phase
                if confidence >= 0.999 and packet_count >= 100:
                    logger.warning(f"[POLICY] Verified high-confidence domain attack: {final_source} (conf={confidence:.3f}, pkts={packet_count}) -> BLOCK")
                    return {
                        "action": "BLOCK",
                        "priority": "NONE",
                        "reason": f"Domain-based threat (Conf: {confidence:.3f})"
                    }
                else:
                    # suppress the attack flag & treat as false positive (handshake phase)
                    logger.info(f"[POLICY] Attack flag suppressed for domain flow (conf={confidence:.3f}, pkts={packet_count}): {final_source}")
                    is_attack = 0
            else:
                # for flows without domain (IP-based, typical for attacks like Medusa, MSF)
                # use a lower threshold to respond quickly
                if confidence >= 0.90 and packet_count >= 20:
                    logger.warning(f"[POLICY] Verified anonymous attack: {final_source} (conf={confidence:.3f}, pkts={packet_count}) -> BLOCK")
                    return {
                        "action": "BLOCK",
                        "priority": "NONE",
                        "reason": f"Anonymous attack (Conf: {confidence:.3f})"
                    }
                else:
                    # not confident enough, but since it's IP-based, give low priority (not block)
                    # to avoid wasting bandwidth
                    logger.info(f"[POLICY] Unverified anonymous flow, setting low priority: {final_source}")
                    # instead of allowing normal QoS, return a low-priority allow
                    # this bypasses the later QoS scoring to ensure it gets LOW
                    return {
                        "action": "ALLOW",
                        "priority": "LOW",
                        "score": -5,
                        "reason": "Unverified Anonymous Flow",
                        "source_identified": final_source
                    }

        # 6. QoS Scoring System (if not blocked)
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