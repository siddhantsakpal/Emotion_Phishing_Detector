#analysis_engine.py
from link_analyzer import extract_links, detect_link_intent
from emotion_detector import detect_emotion
from keyword_detector import detect_keywords
from phishing_models import ml_predict
from trained_model import trained_ml_predict
from preprocess import clean_text, clean_for_emotion
from main_helpers import get_sender_domain, TRUSTED_BRAND_PROFILES
from false_positive_guard import suppress_false_positive
import tldextract


# ───────────────────────────────────────────
# Utility
# ───────────────────────────────────────────

def gauge_to_text(risk_score):
    if risk_score >= 0.7:   return "High"
    elif risk_score >= 0.4: return "Medium"
    else:                   return "Low"


def emotion_to_text(emotions):
    if not emotions:
        return "No emotional patterns were detected."
    dominant = max(emotions, key=emotions.get)
    if emotions[dominant] < 0.4:
        return "The email tone appears neutral."
    return f"The email shows signs of {dominant}, which may influence user behavior."


# ───────────────────────────────────────────
# Brand Integrity Check
# ───────────────────────────────────────────

def tldextract_safe(domain):
    parts = tldextract.extract(domain)
    return (parts.subdomain + "." + parts.domain).lower()


def get_brand_integrity(sender_domain, links):
    # Pass 1 — verified
    for brand, profile in TRUSTED_BRAND_PROFILES.items():
        sender_ok = sender_domain and any(
            sender_domain.lower().endswith(d.lower())
            for d in profile["sender_domains"]
        )
        link_ok = (not links) or any(
            any(l["registered_domain"].lower().endswith(d.lower())
                for d in profile["link_domains"])
            for l in links
        )
        if sender_ok and link_ok:
            return {"brand": brand, "status": "verified"}

    # Pass 2 — impersonation
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


# ───────────────────────────────────────────
# Detect brand from body text
# ───────────────────────────────────────────

def detect_brand_from_body(text):
    lowered = text.lower()
    body_brand_map = {
        "team snapchat": "snapchat.com", "snapchat":  "snapchat.com",
        "team netflix":  "netflix.com",  "netflix":   "netflix.com",
        "team spotify":  "spotify.com",  "spotify":   "spotify.com",
        "uber":          "uber.com",     "swiggy":    "swiggy.com",
        "zomato":        "zomato.com",   "whatsapp":  "whatsapp.com",
        "instagram":     "instagram.com","youtube":   "youtube.com",
        "linkedin":      "linkedin.com", "twitter":   "twitter.com",
        "microsoft":     "microsoft.com","apple":     "apple.com",
        "amazon":        "amazon.com",   "paypal":    "paypal.com",
        "google":        "google.com",   "hdfc bank": "hdfcbank.com",
        "hdfcbank":      "hdfcbank.com", "icici bank":"icicibank.com",
        "icicibank":     "icicibank.com","state bank": "sbi.co.in",
        "sbi":           "sbi.co.in",    "axis bank": "axisbank.com",
        "kotak":         "kotak.com",    "fampay":    "fampay.in",
        "famapp":        "famapp.in",
    }
    for keyword in sorted(body_brand_map, key=len, reverse=True):
        if keyword in lowered:
            return body_brand_map[keyword]
    return None


# ───────────────────────────────────────────
# Static result helpers
# ───────────────────────────────────────────

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
        "keywords":  [],
        "links":     [],
        "emotions":  {},
        "brand_verified": "Unknown Sender",
        "note": (
            "⚠️ Sender domain not recognized. "
            "This email is from an unknown source — "
            "exercise caution but it may still be legitimate."
        ),
        "explain": ["Sender domain not found in trusted brand profiles."]
    }


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
        "keywords":  [],
        "links":     [],
        "emotions":  {},
        "brand_verified": f"Unverified — claims to be {detected_domain}",
        "note": (
            f"⚠️ This email claims to be from {detected_domain} but no sender "
            f"header was found. Paste WITH 'From: noreply@{detected_domain}' "
            f"line for accurate analysis."
        ),
        "explain": [
            "Brand name detected in email body only.",
            "No @sender domain header found — cannot verify authenticity.",
            "Scammers can copy brand names — always verify the actual sender address."
        ]
    }


# ───────────────────────────────────────────
# COLLABORATIVE LAYER SCORING
# Converts a raw signal into a 3-class probability dict
# ───────────────────────────────────────────

def _rule_signal(rule_score):
    """Keyword rule score → probability signal."""
    if rule_score < 0.05:
        return {"phishing": 0.05, "suspicious": 0.05, "legitimate": 0.90}
    elif rule_score < 0.15:
        return {"phishing": 0.20, "suspicious": 0.35, "legitimate": 0.45}
    elif rule_score < 0.35:
        return {"phishing": 0.40, "suspicious": 0.35, "legitimate": 0.25}
    else:
        return {"phishing": 0.75, "suspicious": 0.15, "legitimate": 0.10}


def _emotion_signal(emotions):
    """Emotion scores → probability signal."""
    phishing_emotion = (
        emotions.get("fear",     0) * 0.50 +
        emotions.get("anger",    0) * 0.30 +
        emotions.get("surprise", 0) * 0.20
    )
    legit_emotion = (
        emotions.get("neutral", 0) +
        emotions.get("joy",     0) * 0.5
    )

    if legit_emotion > 0.55:
        return {"phishing": 0.05, "suspicious": 0.10, "legitimate": 0.85}
    elif phishing_emotion > 0.45:
        return {"phishing": 0.65, "suspicious": 0.25, "legitimate": 0.10}
    else:
        return {"phishing": 0.25, "suspicious": 0.40, "legitimate": 0.35}


def _link_signal(links):
    """Link analysis → probability signal."""
    if not links:
        return {"phishing": 0.08, "suspicious": 0.17, "legitimate": 0.75}

    total      = len(links)
    suspicious = sum(1 for l in links if l["status"] == "Suspicious")
    ratio      = suspicious / total

    # Lookalike or shortener present → very suspicious
    has_lookalike  = any(l.get("is_lookalike")  for l in links)
    has_shortener  = any(l.get("registered_domain", "") in
                         {"bit.ly","tinyurl.com","goo.gl","ow.ly",
                          "buff.ly","rebrand.ly","cutt.ly","is.gd",
                          "tiny.cc","rb.gy","clck.ru"}
                         for l in links)
    has_redirect   = any(l.get("redirect_detected") for l in links)

    if has_lookalike or (has_shortener and has_redirect):
        return {"phishing": 0.80, "suspicious": 0.15, "legitimate": 0.05}
    elif has_shortener or has_redirect:
        return {"phishing": 0.55, "suspicious": 0.35, "legitimate": 0.10}
    elif ratio == 0:
        return {"phishing": 0.05, "suspicious": 0.10, "legitimate": 0.85}
    elif ratio <= 0.3:
        return {"phishing": 0.20, "suspicious": 0.45, "legitimate": 0.35}
    elif ratio <= 0.6:
        return {"phishing": 0.45, "suspicious": 0.40, "legitimate": 0.15}
    else:
        return {"phishing": 0.70, "suspicious": 0.20, "legitimate": 0.10}


def _brand_signal(brand_info):
    """Brand verification → probability signal."""
    status = brand_info.get("status", "none")
    if status == "verified":
        return {"phishing": 0.02, "suspicious": 0.03, "legitimate": 0.95}
    elif status == "impersonation":
        return {"phishing": 0.85, "suspicious": 0.10, "legitimate": 0.05}
    else:
        return {"phishing": 0.20, "suspicious": 0.40, "legitimate": 0.40}


def _combine_signals(ml_probs, rule_score, emotions, links, brand_info):
    """
    Combines all 5 layers with weights.
    No single layer dominates — all vote together.

    Weights:
      ML model  : 35%  — important but not king
      Brand     : 30%  — very reliable when available
      Links     : 20%  — highly reliable signal
      Keywords  : 10%  — supporting signal
      Emotions  :  5%  — context signal
    """
    signals = {
        "ml":      (ml_probs,                  0.35),
        "brand":   (_brand_signal(brand_info),  0.30),
        "link":    (_link_signal(links),         0.20),
        "rule":    (_rule_signal(rule_score),    0.10),
        "emotion": (_emotion_signal(emotions),   0.05),
    }

    combined = {"phishing": 0.0, "suspicious": 0.0, "legitimate": 0.0}
    for signal, weight in signals.values():
        for k in combined:
            combined[k] += weight * signal[k]

    # Normalize
    total = sum(combined.values())
    if total > 0:
        combined = {k: round(v / total, 3) for k, v in combined.items()}

    return combined


# ───────────────────────────────────────────
# CORE EMAIL ANALYSIS
# ───────────────────────────────────────────

def analyze_email(text):

    cleaned = clean_text(text)

    # ── Step 1: Extract Links ──
    links = extract_links(text)

    # ── Step 2: Sender Domain ──
    sender_domain = get_sender_domain(text)

    # No sender header — check body for brand mention
    if sender_domain is None:
        body_detected_domain = detect_brand_from_body(text)
        if body_detected_domain:
            return body_brand_result(text, body_detected_domain)

    # ── Step 3: Brand Verification ──
    brand_info = get_brand_integrity(sender_domain, links)

    # No sender at all — unknown
    if brand_info["status"] == "none" and sender_domain is None:
        return unknown_sender_result(text)

    # Unknown domain with no suspicious links — unknown sender
    if brand_info["status"] == "none":
        all_trusted = set()
        for profile in TRUSTED_BRAND_PROFILES.values():
            for d in profile["sender_domains"]:
                all_trusted.add(d.lower())

        domain_unknown      = not any(sender_domain.lower().endswith(d) for d in all_trusted)
        no_suspicious_links = not any(l["status"] == "Suspicious" for l in links)

        if domain_unknown and no_suspicious_links:
            return unknown_sender_result(text)

    # ── Step 4: Keywords ──
    keywords, rule_score = detect_keywords(
        cleaned,
        brand_verified=(brand_info["status"] == "verified")
    )

    # ── Step 5: Emotions ──
    emotion_text = clean_for_emotion(cleaned)
    emotions = detect_emotion(emotion_text)

    # ── Step 6: Dual ML Models ──
    hf_probs      = ml_predict(cleaned)
    trained_probs = trained_ml_predict(cleaned)

    trained_probs = {k: float(v) for k, v in trained_probs.items()}
    trained_probs["suspicious"] = max(
        0.0,
        1.0 - trained_probs["phishing"] - trained_probs["legitimate"]
    )

    # ML combined (equal weight — brand signal handles trust separately)
    ml_combined = {}
    for k in trained_probs:
        ml_combined[k] = round(
            0.65 * trained_probs[k] + 0.35 * hf_probs[k], 3
        )

    # Normalize ml_combined
    ml_total = sum(ml_combined.values())
    if ml_total > 0:
        ml_combined = {k: round(v / ml_total, 3) for k, v in ml_combined.items()}

    # ── Step 7: COLLABORATIVE SCORING — all layers vote together ──
    final_probs = _combine_signals(
        ml_probs   = ml_combined,
        rule_score = rule_score,
        emotions   = emotions,
        links      = links,
        brand_info = brand_info,
    )

    # ── Step 8: False Positive Guard ──
    guarded = suppress_false_positive(
        decision_data = final_probs,
        ml_probs      = ml_combined,
        brand_info    = brand_info,
        links         = links,
        emotions      = emotions,
    )

    phishing   = guarded["phishing"]
    suspicious = guarded["suspicious"]
    legitimate = guarded["legitimate"]

    # ── Step 9: HARD OVERRIDE — verified brand always wins ──
    suspicious_links = [l for l in links if l["status"] == "Suspicious"]

    if (
        brand_info["status"] == "verified"
        and brand_info.get("brand") is not None
        and not suspicious_links
    ):
        phishing   = 0.02
        suspicious = 0.03
        legitimate = 0.95
        decision   = "Legitimate"
        note       = "Verified official brand email. No malicious indicators found."

    elif brand_info["status"] == "impersonation":
        # Impersonation — always phishing regardless of ML score
        phishing   = max(phishing, 0.85)
        suspicious = 0.10
        legitimate = 0.05
        decision   = "Phishing"
        note       = "Brand impersonation detected. Sender domain does not match official domain."

    else:
        # Normal threshold decision
        if phishing >= 0.65:
            decision = "Phishing"
            note     = "Multiple high-risk indicators detected."
        elif phishing >= 0.45 or suspicious >= 0.55:
            decision = "Suspicious"
            note     = "Some indicators look suspicious. Proceed with caution."
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

    return {
        "email_content":     text,
        "decision":          decision,
        "risk_score":        round(phishing, 3),
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
