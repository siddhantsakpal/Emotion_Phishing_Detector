#false_positive_guard.py
from emotion_detector import emotion_risk_boost


def suppress_false_positive(decision_data, ml_probs, brand_info, links, emotions):
    """
    Final safety net — adjusts scores AFTER collaborative scoring.
    Much lighter touch now since layers already voted together.
    Only applies meaningful adjustments, never overrides verified brand.
    """
    phishing   = decision_data.get("phishing",   0.0)
    legitimate = decision_data.get("legitimate", 0.0)
    suspicious = decision_data.get("suspicious", 0.0)

    if phishing   > 1: phishing   /= 100.0
    if legitimate > 1: legitimate /= 100.0
    if suspicious > 1: suspicious /= 100.0

    adjustments = []

    brand_verified      = brand_info and brand_info.get("status") == "verified"
    brand_impersonation = brand_info and brand_info.get("status") == "impersonation"
    no_suspicious_links = not any(l.get("status") == "Suspicious" for l in links)
    all_links_safe      = all(l.get("status") == "Safe" for l in links) if links else True

    # ── 1. Verified brand + all safe links → maximize legitimate ──
    if brand_verified and no_suspicious_links:
        phishing    = min(phishing * 0.3, 0.05)
        legitimate  = max(legitimate, 0.90)
        suspicious  = 1.0 - phishing - legitimate
        adjustments.append("Verified brand — scores suppressed toward legitimate.")

    # ── 2. Impersonation → maximize phishing ──
    elif brand_impersonation:
        phishing   = max(phishing, 0.85)
        legitimate = min(legitimate, 0.05)
        suspicious = 1.0 - phishing - legitimate
        adjustments.append("Brand impersonation detected — phishing score maximized.")

    # ── 3. Unknown sender + all links safe + low emotions → reduce phishing ──
    elif not brand_verified and all_links_safe:
        boost = emotion_risk_boost(emotions)

        if boost < 0.05:
            phishing   = min(phishing, 0.45)
            adjustments.append("Safe links + neutral emotion — phishing score capped.")

        elif boost > 0.10:
            # FIX: Only boost if keywords ALSO agree — prevents footer words
            # from causing emotion boost on clean legitimate emails
            rule_score = ml_probs.get("rule_score", 0) if ml_probs else 0
            keyword_also_risky = rule_score > 0.15

            if keyword_also_risky:
                phishing *= (1.0 + boost * 0.5)
                adjustments.append(f"Emotion+keyword risk boost: +{round(boost * 0.5, 3)}")
            else:
                # Emotion triggered but keywords say clean — ignore emotion boost
                adjustments.append("Emotion signal ignored — keywords show no risk.")

    # ── 4. Suspicious links present + no brand → boost phishing ──
    elif not brand_verified and not no_suspicious_links:
        phishing = min(phishing * 1.2, 0.95)
        adjustments.append("Suspicious links detected — phishing score boosted.")

    # ── 5. Recalculate suspicious ──
    suspicious = max(0.0, 1.0 - phishing - legitimate)

    # ── 6. Normalize ──
    total = phishing + suspicious + legitimate
    if total > 0:
        phishing   /= total
        suspicious /= total
        legitimate /= total

    return {
        "phishing":    round(phishing,   3),
        "suspicious":  round(suspicious, 3),
        "legitimate":  round(legitimate, 3),
        "adjustments": adjustments,
    }
