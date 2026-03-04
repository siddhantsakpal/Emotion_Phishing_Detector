from main_helpers import PHISHING_KEYWORDS

# ---------------------------------------------------------------
# Keywords that are very common in legitimate transactional /
# account emails and should carry almost no weight by themselves.
# ---------------------------------------------------------------
LOW_WEIGHT_KEYWORDS = {
    # Account related
    "account", "login", "verify", "secure", "password",
    "confirm", "update", "click here", "security alert",
    "customer care", "net banking", "mobile banking", "bank alert",

    # Transactional — very common in legitimate billing emails
    "bill", "billing", "invoice", "payment", "subscription",
    "order", "receipt", "transaction", "statement", "amount",
    "charge", "purchase", "refund", "due", "balance",

    # Delivery — common in legitimate courier emails
    "delivery", "delivered", "shipment", "tracking", "package",
    "dispatch", "courier", "shipping",

    # Notification — common in legitimate system emails
    "notification", "reminder", "alert", "notice", "information",
    "newsletter", "update your", "new message",
}

# ---------------------------------------------------------------
# Keywords that are STRONG phishing indicators — high weight
# These rarely appear in legitimate emails
# ---------------------------------------------------------------
HIGH_WEIGHT_KEYWORDS = {
    "urgent", "suspend", "suspended", "unusual activity",
    "account locked", "account temporarily blocked",
    "verify your account", "confirm identity",
    "atm block", "atm blocked", "debit card blocked",
    "credit card blocked", "share otp", "otp",
    "kyc update", "kyc pending", "verify kyc",
    "unusual transaction", "password reset",
    "update billing", "login required",
    "delivery issue", "update your order",
}

def detect_keywords(text, brand_verified=False):
    found  = []
    score  = 0.0
    lowered = text.lower()

    for k in PHISHING_KEYWORDS:
        if k in lowered:
            found.append(k)

            if k in HIGH_WEIGHT_KEYWORDS:
                # Strong phishing signal
                score += 0.20

            elif k in LOW_WEIGHT_KEYWORDS:
                # Very common in legitimate emails — minimal weight
                score += 0.02

            else:
                # Medium weight
                score += 0.08

    # ── Brand dampening ──
    # If sender is a verified brand — keyword score is nearly irrelevant
    # because we trust the brand more than individual words
    if brand_verified:
        score *= 0.05  # reduce to 5% — almost zero for verified brands

    return found, min(score, 2.0)
