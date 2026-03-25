import logging

# Standard logger setup
logger = logging.getLogger(__name__)

class QoSPolicyEngine:

    def __init__(self):
        # Weighting system for QoS prioritization
        self.weights = {
            "academic": 10,     # Increased weight to ensure it dominates scoring
            "interactive": 2,
            "background": -1,
            "bulk": -2,
            "media": -3
        }

        # Optimized keyword list (removed spaces, simplified for substring matching)
        self.academic_keywords = [
            ".edu", ".ac.", "edu.", "ac.", 
            "university", "college", "campus", "faculty", "student", "library",
            "moodle", "blackboard", "canvas", "brightspace", "d2l", "schoology",
            "classroom", "googleclassroom", "coursera", "edx", "udemy", "udacity",
            "futurelearn", "khanacademy", "openlearning", "ieee", "acm", "springer",
            "sciencedirect", "elsevier", "wiley", "tandfonline", "jstor", "sagepub",
            "oxfordacademic", "cambridge", "nature", "researchgate", "academia.edu",
            "scholar", "arxiv", "dblp", "refworks", "mendeley", "zotero",
            "docs.google", "drive.google", "slides.google", "forms.google",
            "teams", "zoom", "meet.google", "webex", "github", "gitlab",
            "stackoverflow", "stackexchange", "geeksforgeeks", "w3schools",
            "leetcode", "hackerrank", "alison", "skillshare", "turnitin",
            "quizlet", "chegg", "scribd"
        ]

    def is_academic_domain(self, source):
        """
        Validates if the source domain belongs to academic resources.
        """
        if not source or source == "unknown":
            return False

        # Clean string for consistent matching
        source = source.lower().strip()
        logger.info(f"[ACADEMIC CHECK] Testing source: {source}")

        for keyword in self.academic_keywords:
            if keyword in source:
                logger.info(f"[ACADEMIC MATCH] Found keyword: {keyword}")
                return True

        return False

    def compute_score(self, behaviour, academic_flag):
        """
        Calculates the final QoS score based on ML behaviour and academic status.
        """
        score = 0

        # High priority boost for academic content
        if academic_flag >= 1:
            score += self.weights["academic"]

        label = behaviour.lower() if behaviour else ""

        # Adjust score based on traffic type
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
        """
        Final decision logic for the SDN controller.
        """
        # 1. DOMAIN IDENTIFICATION & OVERRIDE
        # Check both the raw source and the mapped domain from TrafficProcessor
        mapped_domain = metadata.get("mapped_domain") if metadata else None
        packet_count = metadata.get("flow_packet_count", 0) if metadata else 0
        
        # Use either mapped domain or raw source to identify academic traffic
        is_edu = self.is_academic_domain(mapped_domain) or self.is_academic_domain(source)
        
        if is_edu:
            ml_result["academic"] = 1
            logger.info(f"[POLICY] Academic status confirmed for: {source or mapped_domain}")

        # 2. ATTACK MITIGATION & INITIAL CONNECTION LOGIC
        if ml_result.get("attack") == 1:
            # Prevent blocking during the TCP handshake or early flow stages
            if packet_count < 10:
                logger.info(f"[POLICY] Ignoring early flow attack misclassification. Packets: {packet_count}")
            # Do not block unknown sources unless confidence is very high
            elif source == "unknown" or source is None:
                return {
                    "action": "ALLOW",
                    "priority": "LOW",
                    "reason": "POTENTIAL_ATTACK_MONITORING"
                }
            else:
                return {
                    "action": "BLOCK",
                    "priority": "CRITICAL",
                    "reason": "CONFIRMED_THREAT_BLOCK"
                }

        # 3. SCORING & PRIORITY ASSIGNMENT
        score = self.compute_score(
            ml_result.get("behaviour", "unknown"),
            ml_result.get("academic", 0)
        )

        # Thresholds for priority queues
        if score >= 8: # Likely Academic or Critical Interactive
            priority = "HIGH"
        elif score >= 1: # Standard Interactive
            priority = "MEDIUM"
        else: # Bulk / Background / Unknown
            priority = "LOW"

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": "DOMAIN_AWARE_ADAPTIVE_QOS",
            "source_identified": source if source != "unknown" else mapped_domain
        }