import re
from urllib.parse import urlparse
import tldextract
from main_helpers import SAFE_DOMAINS, TRUSTED_BRAND_PROFILES

# ---------------------------------------------------------------
# Build comprehensive trusted domain set from TRUSTED_BRAND_PROFILES
# ---------------------------------------------------------------
def _build_all_trusted_domains():
    domains = set(SAFE_DOMAINS)
    for profile in TRUSTED_BRAND_PROFILES.values():
        for d in profile.get("link_domains", []):
            domains.add(d.lower())
        for d in profile.get("sender_domains", []):
            domains.add(d.lower())
    return domains

ALL_TRUSTED_DOMAINS = _build_all_trusted_domains()

# ---------------------------------------------------------------
# URL shorteners — always suspicious, no exceptions
# ---------------------------------------------------------------
SUSPICIOUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl",
    "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "is.gd", "tiny.cc", "bl.ink",
    "rb.gy", "clck.ru", "urlshrt.io", "shorte.st",
    "adf.ly", "bc.vc", "sh.st", "ouo.io",
}

# ---------------------------------------------------------------
# Trusted path prefixes — these paths are always safe on trusted domains
# e.g. google.com/notifications, microsoft.com/billing
# ---------------------------------------------------------------
TRUSTED_PATHS = {
    "/notifications", "/notification",
    "/billing", "/invoice", "/orders",
    "/account", "/myaccount", "/profile",
    "/settings", "/security", "/activity",
    "/help", "/support", "/contact",
    "/privacy", "/terms",
    "/signin", "/login",           # safe on trusted domains only
    "/verify",                     # safe on trusted domains only
    "/unsubscribe",
    "/dashboard", "/home",
    "/tracking", "/order",
    "/receipt", "/statement",
}


# ---------------------------------------------------------------
# detect_redirect_chain
# FIX: Only checks URL path and query — NOT the domain name
# FIX: Removed "account", "secure", "verify", "login", "signin",
#      "update", "confirm" — too common in legitimate URLs
# FIX: Skips check entirely for trusted domains
# Only truly suspicious redirect/injection patterns remain
# ---------------------------------------------------------------
def detect_redirect_chain(url: str, is_trusted: bool = False) -> bool:
    """
    Returns True only if the URL path contains a true redirect trap.
    Never fires for trusted domains unless a hard redirect parameter exists.
    """
    # Trusted domains never get redirect-flagged unless they have
    # a redirect parameter pointing to an external URL
    try:
        parsed  = urlparse(url if url.startswith("http") else "http://" + url)
        path    = parsed.path.lower()
        query   = parsed.query.lower()
        path_q  = path + "?" + query

        # Hard redirect parameters — suspicious even on trusted domains
        # e.g. google.com/redirect?url=evil.com
        hard_redirect_patterns = [
            "url=http",
            "next=http",
            "returnurl=http",
            "redirect=http",
            "goto=http",
            "dest=http",
            "target=http",
            "link=http",
        ]
        if any(p in path_q for p in hard_redirect_patterns):
            return True

        # For trusted domains — stop here, no further checks
        if is_trusted:
            return False

        # For untrusted domains — check for injection/exploit patterns
        untrusted_patterns = [
            "webscr",
            "cmd=",
            "exec=",
            "authenticate",
            "token=",
            "session=",
            "phish",
            "steal",
            "harvest",
        ]
        return any(p in path_q for p in untrusted_patterns)

    except Exception:
        return False


# ---------------------------------------------------------------
# _is_trusted_domain
# Checks if registered domain matches any trusted domain.
# Supports suffix matching: mail.google.com → trusts google.com
# ---------------------------------------------------------------
def _is_trusted_domain(registered_domain: str) -> bool:
    rd = registered_domain.lower()

    # Shorteners are never trusted
    if rd in SUSPICIOUS_SHORTENERS:
        return False

    for trusted in ALL_TRUSTED_DOMAINS:
        if rd == trusted or rd.endswith("." + trusted):
            return True
    return False


# ---------------------------------------------------------------
# _is_lookalike_domain
# Catches domains that LOOK like trusted brands but aren't
# e.g. paypa1.com, g00gle.com, amazon-secure.com
# ---------------------------------------------------------------
def _is_lookalike_domain(registered_domain: str) -> bool:
    rd = registered_domain.lower()

    # Common character substitutions used in lookalike domains
    normalized = (
        rd.replace("0", "o")
          .replace("1", "l")
          .replace("3", "e")
          .replace("@", "a")
          .replace("5", "s")
          .replace("vv", "w")
    )

    brand_keywords = [
        "google", "microsoft", "amazon", "paypal", "apple",
        "facebook", "instagram", "netflix", "spotify",
        "twitter", "linkedin", "whatsapp", "uber",
        "hdfc", "icici", "sbi", "kotak", "axis",
        "swiggy", "zomato", "flipkart", "paytm",
        "github", "dropbox", "slack", "zoom",
        "razorpay", "stripe", "adobe",
    ]

    for brand in brand_keywords:
        # If normalized domain contains brand name
        # but is NOT in trusted list → it's a lookalike
        if brand in normalized and not _is_trusted_domain(rd):
            return True

    return False


# ---------------------------------------------------------------
# extract_links
# Finds all URLs in email text and classifies each as Safe/Suspicious
# ---------------------------------------------------------------
def extract_links(text):
    # Convert obfuscated [.] to real dots
    text = text.replace("[.]", ".")

    url_pattern = (
        r'(?:https?://|www\.)[^\s<>"\)\]]+' 
        r'|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.(?:com|org|net|edu|gov|io|co|us|uk|in|biz|info|me)[^\s<>"\)\]]*'
    )

    urls     = re.findall(url_pattern, text, re.IGNORECASE)
    links    = []
    seen_urls = set()

    for u in urls:
        u = u.rstrip(".,;:)")

        if u in seen_urls:
            continue
        seen_urls.add(u)

        try:
            parse_url    = u if u.startswith("http") else "http://" + u
            parsed       = urlparse(parse_url)
            domain_parts = tldextract.extract(parsed.netloc)

            if not domain_parts.suffix:
                continue

            registered_domain = f"{domain_parts.domain}.{domain_parts.suffix}".lower()
            is_trusted        = _is_trusted_domain(registered_domain)
            is_lookalike      = _is_lookalike_domain(registered_domain)
            has_redirect      = detect_redirect_chain(u, is_trusted=is_trusted)

            # ── Classification logic ──
            if registered_domain in SUSPICIOUS_SHORTENERS:
                # Shortener — always suspicious
                status = "Suspicious"
                reason = "URL shortener detected"

            elif is_lookalike:
                # Lookalike domain — always suspicious
                status = "Suspicious"
                reason = "Lookalike/impersonation domain"

            elif has_redirect:
                # Hard redirect to external URL — suspicious even on trusted domains
                status = "Suspicious"
                reason = "Redirect to external URL detected"

            elif is_trusted:
                # Trusted domain, no redirect → always safe
                status = "Safe"
                reason = "Verified trusted domain"

            else:
                # Unknown domain — suspicious
                status = "Suspicious"
                reason = "Unknown/untrusted domain"

            links.append({
                "url":               u,
                "full_domain":       parsed.netloc.lower(),
                "registered_domain": registered_domain,
                "status":            status,
                "reason":            reason,
                "redirect_detected": has_redirect,
                "is_trusted":        is_trusted,
                "is_lookalike":      is_lookalike,
            })

        except Exception:
            continue

    return links


# ---------------------------------------------------------------
# detect_link_intent
# Calculates a risk score based on links and email text context
# FIX: Action words now require urgency words to score high
# FIX: Prevents legitimate security notifications from scoring high
# ---------------------------------------------------------------
def detect_link_intent(text, links, brand_info):
    intent  = 0.0
    lowered = text.lower()

    # FIX: Action words ALONE don't score high anymore
    # They must appear WITH urgency words to be meaningful
    action_words  = ["kyc", "password reset", "share otp", "atm block"]
    urgency_words = [
        "urgent", "immediately", "suspended", "blocked",
        "expires", "expire", "act now", "limited time",
        "within 24 hours", "account will be closed",
    ]

    has_action  = any(w in lowered for w in action_words)
    has_urgency = any(w in lowered for w in urgency_words)

    if has_action and has_urgency:
        intent += 0.3    # both present — strong phishing signal
    elif has_action:
        intent += 0.05   # action alone — very weak signal
    elif has_urgency:
        intent += 0.1    # urgency alone — mild signal

    if not links:
        return intent

    brand  = brand_info.get("brand")  if brand_info else None
    status = brand_info.get("status") if brand_info else None

    # FIX: Removed flat +0.2 base risk for having links
    # Legitimate emails always have links — this was causing false positives

    if brand and status == "verified":
        # Verified brand — only flag if links go outside brand domains
        allowed_domains = TRUSTED_BRAND_PROFILES[brand]["link_domains"]
        for l in links:
            if not any(
                l["registered_domain"].endswith(d)
                for d in allowed_domains
            ):
                intent += 0.3   # link outside verified brand domain
    elif brand and status == "impersonation":
        intent += 0.5           # brand impersonation — high intent

    # Hard redirect to external URL detected
    if any(l.get("redirect_detected") for l in links):
        intent += 0.3

    # Shortener links
    if any(l["registered_domain"] in SUSPICIOUS_SHORTENERS for l in links):
        intent += 0.3

    # Lookalike domains
    if any(l.get("is_lookalike") for l in links):
        intent += 0.4

    return min(intent, 1.0)
