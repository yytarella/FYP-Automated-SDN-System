import logging

logger = logging.getLogger(__name__)


class QoSPolicyEngine:

    def __init__(self):

        self.weights = {
            "academic": 4,
            "interactive": 1,
            "background": -2,
            "bulk": -2,
            "media": -3
        }

        self.academic_keywords = [

        # education domain patterns
        ".edu",
        ".ac.",
        "edu.",
        "ac.",

        # universities / institutions (generic)
        "university",
        "college",
        "campus",
        "faculty",
        "student",
        "library",

        # LMS / e-learning platforms
        "moodle",
        "blackboard",
        "canvas",
        "brightspace",
        "d2l",
        "schoology",
        "classroom",
        "googleclassroom",

        # online learning platforms
        "coursera",
        "edx",
        "udemy",
        "udacity",
        "futurelearn",
        "khanacademy",
        "openlearning",

        # research / academic platforms
        "ieee",
        "acm",
        "springer",
        "sciencedirect",
        "elsevier",
        "wiley",
        "tandfonline",
        "jstor",
        "sagepub",
        "oxfordacademic",
        "cambridge",
        "nature",
        "researchgate",
        "academia.edu",
        "semantic scholar",
        "arxiv",
        "dblp",

        # search / academic tools
        "scholar.google",
        "google scholar",
        "refworks",
        "mendeley",
        "zotero",

        # cloud / docs used in learning
        "docs.google",
        "drive.google",
        "slides.google",
        "forms.google",

        # communication / collaboration (education usage)
        "teams",
        "microsoft teams",
        "zoom",
        "meet.google",
        "google meet",
        "webex",

        # coding / technical learning platforms
        "github",
        "gitlab",
        "stackoverflow",
        "stackexchange",
        "geeksforgeeks",
        "w3schools",
        "leetcode",
        "hackerrank",
        
        # MOOCs / certification
        "alison",
        "skillshare",

        # misc education services
        "turnitin",
        "quizlet",
        "chegg",
        "scribd",
        "drive"
    ]

    def is_academic_domain(self, source):

        logger.info(f"[ACADEMIC CHECK] raw source = {source}")

        source = source.lower().strip()

        if ":" in source:
            source = source.split(":")[0]

        if not source or source == "unknown":
            return False

        source = source.lower()

        for keyword in self.academic_keywords:
            if keyword in source:
                return True

        return False

    def compute_score(self, behaviour, academic):

        score = 0

        if academic == 1:
            score += self.weights["academic"]

        label = behaviour.lower() if behaviour else ""

        if "chat" in label or "interactive" in label:
            score += self.weights["interactive"]

        if "background" in label:
            score += self.weights["background"]

        if "bulk" in label:
            score += self.weights["bulk"]

        if "media" in label or "stream" in label:
            score += self.weights["media"]

        return score

    def decide(self, ml_result, source=None):

        # -------------------------
        # CONTEXT OVERRIDE (key fix)
        # -------------------------
        if self.is_academic_domain(source):
            ml_result["academic"] = 1

        # -------------------------
        # ATTACK
        # -------------------------
        if ml_result["attack"] == 1:
            return {
                "action": "BLOCK",
                "priority": "CRITICAL",
                "bandwidth": 0,
                "reason": "ATTACK"
            }

        # -------------------------
        # NORMAL SCORING
        # -------------------------
        score = self.compute_score(
            ml_result["behaviour"],
            ml_result["academic"]
        )

        if score >= 4:
            priority = "HIGH"
        elif score >= 2:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return {
            "action": "ALLOW",
            "priority": priority,
            "score": score,
            "reason": "ADAPTIVE_POLICY"
        }