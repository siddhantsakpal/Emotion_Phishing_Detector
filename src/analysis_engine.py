#analysis_engine.py
from database import log_analysis
from link_analyzer import extract_links, detect_link_intent
from emotion_detector import detect_emotion
from keyword_detector import detect_keywords
from phishing_models import ml_predict
from trained_model import trained_ml_predict
from preprocess import clean_text
from main_helpers import (
    get_sender_domain,
    TRUSTED_BRAND_PROFILES,
)
from false_positive_guard import suppress_false_positive
import tldextract


# -------------------------------
# Utility Functions
# -------------------------------

def gauge_to_text(risk_score):
    if risk_score >= 0.7:
        return "High"
    elif risk_score >= 0.4:
        return "Medium"
    else:
        return "Low"


def emotion_to_text(emotions):
    if not emotions:
        return "No emotional patterns were detected."
    dominant = max(emotions, key=emotions.get)
    if emotions[dominant] < 0.4:
        return "The email tone appears neutral."
    else:
        return f"The email shows signs of {dominant}, which may influence user behavior."


# -------------------------------
# Brand Integrity Check
# -------------------------------

def tldextract_safe(domain):
    parts = tldextract.extract(domain)
    return (parts.subdomain + "." + parts.domain).lower()


def get_brand_integrity(sender_domain, links):
    for brand, profile in TRUSTED_BRAND_PROFILES.items():
        sender_ok = sender_domain and any(
            sender_domain.lower().endswith(d.lower())
            for d in profile["sender_domains"]
        )
        if links:
            link_ok = any(
                any(
                    l["registered_domain"].lower().endswith(d.lower())
                    for d in profile["link_domains"]
                )
                for l in links
            )
        else:
            link_ok = True

        if sender_ok and link_ok:
            return {"brand": brand, "status": "verified"}

    # Impersonation pass
    for brand, profile in TRUSTED_BRAND_PROFILES.items():
        sender_ok = sender_domain and any(
            sender_domain.lower().endswith(d.lower())
            for d in profile["sender_domains"]
        )
        if sender_ok:
            continue

        if sender_domain:
            parts = tldextract_safe(sender_domain)
            if brand.lower() in parts and not sender_domain.lower().endswith(
                tuple(d.lower() for d in profile["sender_domains"])
            ):
                return {"brand": brand, "status": "impersonation"}

        if links:
            for l in links:
                domain_only = l["registered_domain"]
                if brand.lower() in domain_only.lower() and not any(
                    domain_only.lower().endswith(d.lower())
                    for d in profile["link_domains"]
                ):
                    return {"brand": brand, "status": "impersonation"}

    return {"brand": None, "status": "none"}


# -------------------------------
# Detect brand from body text
# -------------------------------

def detect_brand_from_body(text):
    lowered = text.lower()
    body_brand_map = {
        "team snapchat":  "snapchat.com",
        "snapchat":       "snapchat.com",
        "team netflix":   "netflix.com",
        "netflix":        "netflix.com",
        "team spotify":   "spotify.com",
        "spotify":        "spotify.com",
        "uber":           "uber.com",
        "swiggy":         "swiggy.com",
        "zomato":         "zomato.com",
        "whatsapp":       "whatsapp.com",
        "instagram":      "instagram.com",
        "youtube":        "youtube.com",
        "linkedin":       "linkedin.com",
        "twitter":        "twitter.com",
        "microsoft":      "microsoft.com",
        "apple":          "apple.com",
        "amazon":         "amazon.com",
        "paypal":         "paypal.com",
        "google":         "google.com",
        "hdfc bank":      "hdfcbank.com",
        "hdfcbank":       "hdfcbank.com",
        "icici bank":     "icicibank.com",
        "icicibank":      "icicibank.com",
        "state bank":     "sbi.co.in",
        "sbi":            "sbi.co.in",
        "axis bank":      "axisbank.com",
        "kotak":          "kotak.com",
        "fampay":         "fampay.in",
        "famapp":         "famapp.in",
    }
    for keyword in sorted(body_brand_map, key=len, reverse=True):
        if keyword in lowered:
            return body_brand_map[keyword]
    return None


# -------------------------------
# Unknown Sender Result
# -------------------------------

def unknown_sender_result(text):
    return {
        "email_content":     text,
        "decision":          "Unknown",
        "risk_score":        0.0,
        "phishing_pct":      0.0,
        "suspicious_pct":    0.0,
        "legit_pct":         0.0,
        "rule_score":        0.0,
        "huggingface_probs": {"phishing": 0.0, "suspicious": 0.0, "legitimate": 0.0},
        "trained_probs":     {"phishing": 0.0, "suspicious": 0.0, "legitimate": 0.0},
        "ml_probs_combined": {"phishing": 0.0, "suspicious": 0.0, "legitimate": 0.0},
        "keywords":          [],
        "links":             [],
        "emotions":          {},
        "brand_verified":    "Unknown Sender",
        "note": (
            "⚠️ Sender domain not recognized. "
            "This email is from an unknown source — "
            "exercise caution but it may still be legitimate."
        ),
        "explain": ["Sender domain not found in trusted brand profiles."]
    }


# -------------------------------
# Body-only brand result
# -------------------------------

def body_brand_result(text, detected_domain):
    return {
        "email_content":     text,
        "decision":          "Suspicious",
        "risk_score":        0.4,
        "phishing_pct":      15.0,
        "suspicious_pct":    70.0,
        "legit_pct":         15.0,
        "rule_score":        0.0,
        "huggingface_probs": {"phishing": 0.15, "suspicious": 0.70, "legitimate": 0.15},
        "trained_probs":     {"phishing": 0.15, "suspicious": 0.70, "legitimate": 0.15},
        "ml_probs_combined": {"phishing": 0.15, "suspicious": 0.70, "legitimate": 0.15},
        "keywords":          [],
        "links":             [],
        "emotions":          {},
        "brand_verified":    f"Unverified — claims to be {detected_domain}",
        "note": (
            f"⚠️ This email claims to be from {detected_domain} but no sender "
            f"header was found. Paste it WITH the 'From: noreply@{detected_domain}' "
            f"line for accurate analysis. Could be legitimate or a scam."
        ),
        "explain": [
            "Brand name detected in email body only.",
            "No @sender domain header found — cannot verify authenticity.",
            "Scammers can copy brand names — always verify the actual sender address."
        ]
    }


# -------------------------------
# Core Email Analysis
# -------------------------------

def analyze_email(text):

    cleaned = clean_text(text)

    # 1️⃣ Extract Links
    links = extract_links(text)

    # 2️⃣ Get sender domain from headers
    sender_domain = get_sender_domain(text)

    # If no @domain header found, check body for brand name
    if sender_domain is None:
        body_detected_domain = detect_brand_from_body(text)
        if body_detected_domain:
            return body_brand_result(text, body_detected_domain)

    # 3️⃣ Brand Verification
    brand_info = get_brand_integrity(sender_domain, links)

    # Unknown sender — no header, no body brand detected
    if brand_info["status"] == "none" and sender_domain is None:
        return unknown_sender_result(text)

    # Also Unknown if sender domain exists but not trusted AND no suspicious links
    if brand_info["status"] == "none":
        all_trusted_domains = set()
        for profile in TRUSTED_BRAND_PROFILES.values():
            for d in profile["sender_domains"]:
                all_trusted_domains.add(d.lower())

        domain_is_unknown = not any(
            sender_domain.lower().endswith(d) for d in all_trusted_domains
        )
        no_suspicious_links = not any(l["status"] == "Suspicious" for l in links)

        if domain_is_unknown and no_suspicious_links:
            return unknown_sender_result(text)

    # 4️⃣ Keyword Detection
    keywords, rule_score = detect_keywords(
        cleaned,
        brand_verified=(brand_info["status"] == "verified")
    )

    # 5️⃣ Emotion Detection
    emotions = detect_emotion(cleaned)

    # 6️⃣ ML Predictions
    hf_probs      = ml_predict(cleaned)
    trained_probs = trained_ml_predict(cleaned)

    trained_probs = {k: float(v) for k, v in trained_probs.items()}
    trained_probs["suspicious"] = max(
        0.0,
        1.0 - trained_probs["phishing"] - trained_probs["legitimate"]
    )

    # Combine ML (trained dominates)
    final_probs = trained_probs.copy()
    for k in final_probs:
        final_probs[k] = round(
            0.8 * final_probs[k] + 0.2 * hf_probs[k], 3
        )

    # Boost phishing if impersonation
    if brand_info["status"] == "impersonation":
        final_probs["phishing"] = min(final_probs["phishing"] + 0.2, 1.0)

    # Normalize
    total = sum(final_probs.values())
    if total > 0:
        for k in final_probs:
            final_probs[k] /= total

    # 7️⃣ False Positive Guard
    decision_data = {
        "phishing":   final_probs["phishing"],
        "suspicious": final_probs["suspicious"],
        "legitimate": final_probs["legitimate"],
    }

    guarded = suppress_false_positive(
        decision_data=decision_data,
        ml_probs=final_probs,
        brand_info=brand_info,
        links=links,
        emotions=emotions
    )

    phishing   = guarded["phishing"]
    suspicious = guarded["suspicious"]
    legitimate = guarded["legitimate"]

    # -------------------------------------------------------
    # HARD OVERRIDE — ONLY for verified brands, NEVER impersonation
    # FIX: Added explicit check brand_info["status"] == "verified"
    # and also checked suspicious_links — bit.ly now correctly
    # flagged as Suspicious so impersonation emails won't pass
    # -------------------------------------------------------
    suspicious_links = [l for l in links if l["status"] == "Suspicious"]

    if (
        brand_info["status"] == "verified"          # FIX: never fires for impersonation
        and brand_info.get("brand") is not None     # FIX: extra safety — brand must exist
        and not suspicious_links                    # FIX: bit.ly now flagged → won't pass
    ):
        phishing   = 0.02
        suspicious = 0.03
        legitimate = 0.95
        decision   = "Legitimate"
        note       = "Verified official brand email. No malicious indicators found."
    else:
        # FIX: Lowered threshold for impersonation emails
        # so 74% phishing score correctly triggers Phishing decision
        if phishing > 0.65 or brand_info["status"] == "impersonation" and phishing > 0.4:
            decision = "Phishing"
            note     = "Multiple high-risk indicators detected."
        elif suspicious >  0.65:
            decision = "Suspicious"
            note     = "Some indicators look suspicious."
        else:
            decision = "Legitimate"
            note     = "No significant anomalies detected."

    phishing_pct   = round(phishing   * 100, 1)
    suspicious_pct = round(suspicious * 100, 1)
    legit_pct      = round(legitimate * 100, 1)

    brand_text = (
        f"{brand_info['brand'].title()} ({brand_info['status']})"
        if brand_info.get("brand")
        else "No brand verified"
    )

    result = {
        "email_content":     text,
        "decision":          decision,
        "risk_score":        phishing,
        "phishing_pct":      phishing_pct,
        "suspicious_pct":    suspicious_pct,
        "legit_pct":         legit_pct,
        "rule_score":        round(rule_score, 2),
        "huggingface_probs": hf_probs,
        "trained_probs":     trained_probs,
        "ml_probs_combined": final_probs,
        "keywords":          keywords,
        "links":             links,
        "emotions":          emotions,
        "brand_verified":    brand_text,
        "note":              note,
        "explain":           guarded.get("adjustments", []),
    }

    return result
