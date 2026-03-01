#keyword_detector.py
from main_helpers import PHISHING_KEYWORDS

# Keywords that are very common in legitimate transactional / account emails
# and should carry almost no weight by themselves.
LOW_WEIGHT_KEYWORDS = {
    "account", "login", "verify", "secure", "password", "customer care",
    "net banking", "mobile banking", "bank alert", "security alert",
    "confirm", "update", "click here",
}

def detect_keywords(text, brand_verified=False):
    found = []
    score = 0.0
    lowered = text.lower()

    for k in PHISHING_KEYWORDS:
        if k in lowered:
            found.append(k)

            # FIX: Low-weight keywords score less even without brand verification
            if k in LOW_WEIGHT_KEYWORDS:
                score += 0.05   # was 0.1
            else:
                score += 0.2    # was 0.3

    # FIX: Stronger dampening when sender is a verified brand (was 0.4)
    if brand_verified:
        score *= 0.2

    return found, min(score, 2.0)
