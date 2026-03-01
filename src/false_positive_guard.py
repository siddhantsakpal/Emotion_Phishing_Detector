# STEP 4: Now imports emotion_risk_boost instead of using manual if/else
from emotion_detector import emotion_risk_boost


def suppress_false_positive(decision_data, ml_probs, brand_info, links, emotions):

    phishing   = decision_data.get("phishing",   decision_data.get("phishing_pct",   0))
    legitimate = decision_data.get("legitimate", decision_data.get("legit_pct",      0))

    if phishing   > 1: phishing   /= 100.0
    if legitimate > 1: legitimate /= 100.0

    suspicious  = 1.0 - (phishing + legitimate)
    adjustments = []

    brand_verified      = brand_info and brand_info.get("status") == "verified"
    no_suspicious_links = not any(l.get("status") == "Suspicious" for l in links)

    # -----------------------------
    # 1️⃣ Strong Brand Protection
    # -----------------------------
    if brand_verified and no_suspicious_links:
        phishing   *= 0.4
        legitimate += 0.25
        adjustments.append("Strong verified brand protection applied.")

    # -----------------------------
    # 2️⃣ STEP 4: Use emotion_risk_boost instead of manual threshold
    # Cleaner, uses all emotions not just fear/surprise
    # -----------------------------
    if not brand_verified:
        boost = emotion_risk_boost(emotions)
        if boost > 0.05:   # only apply if meaningful
            phishing  *= (1.0 + boost)
            adjustments.append(f"Emotion risk boost applied: +{boost}")

    # -----------------------------
    # 3️⃣ Recalculate suspicious
    # -----------------------------
    suspicious = max(0.0, 1.0 - (phishing + legitimate))

    # -----------------------------
    # 4️⃣ Normalize
    # -----------------------------
    total = phishing + suspicious + legitimate
    if total > 0:
        phishing   /= total
        suspicious /= total
        legitimate /= total

    return {
        "phishing":    round(phishing,   3),
        "suspicious":  round(suspicious, 3),
        "legitimate":  round(legitimate, 3),
        "adjustments": adjustments
    }
