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

# URL shorteners and suspicious redirect domains always flagged
SUSPICIOUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "is.gd", "tiny.cc", "bl.ink",
    "rb.gy", "clck.ru", "urlshrt.io"
}

# ---------------------------------------------------------------
# STEP 3: detect_redirect_chain — wired in from decision_engine.py
# Catches phishing URLs that use redirects or login pages
# ---------------------------------------------------------------
def detect_redirect_chain(url: str) -> bool:
    """
    Returns True if the URL looks like a redirect or login trap.
    Catches patterns scammers use to disguise malicious destinations.
    """
    lowered = url.lower()
    suspicious_patterns = [
        "redirect", "login", "signin", "verify", "secure",
        "account", "update", "confirm", "authenticate",
        "webscr", "cmd=", "session=", "token=",
    ]
    return any(pattern in lowered for pattern in suspicious_patterns)


def _is_trusted_domain(registered_domain: str) -> bool:
    """
    Returns True if registered_domain matches any trusted domain.
    Supports suffix matching: 'mail.google.com' → trusts 'google.com'.
    URL shorteners are NEVER trusted even if somehow in the list.
    """
    rd = registered_domain.lower()

    # Shorteners are always suspicious — check first
    if rd in SUSPICIOUS_SHORTENERS:
        return False

    for trusted in ALL_TRUSTED_DOMAINS:
        if rd == trusted or rd.endswith("." + trusted):
            return True
    return False


def extract_links(text):
    # Convert obfuscated [.] to real dots
    text = text.replace("[.]", ".")

    url_pattern = (
        r'(?:https?://|www\.)[^\s<>"]+'
        r'|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.(?:com|org|net|edu|gov|io|co|us|uk|in|biz|info|me)[^\s<>"]*'
    )

    urls = re.findall(url_pattern, text, re.IGNORECASE)
    links = []
    seen_urls = set()

    for u in urls:
        u = u.rstrip(".,;:)")

        if u in seen_urls:
            continue
        seen_urls.add(u)

        try:
            parse_url = u if u.startswith("http") else "http://" + u
            parsed = urlparse(parse_url)

            domain_parts = tldextract.extract(parsed.netloc)

            if not domain_parts.suffix:
                continue

            registered_domain = f"{domain_parts.domain}.{domain_parts.suffix}".lower()

            # STEP 3: Check redirect chain FIRST — catches login/verify traps
            # even on domains that look legitimate
            if registered_domain in SUSPICIOUS_SHORTENERS:
                status = "Suspicious"
            elif not _is_trusted_domain(registered_domain):
                status = "Suspicious"
            elif detect_redirect_chain(u):
                # Domain is trusted but URL path looks like a redirect trap
                # e.g. google.com/redirect?url=evil.com
                status = "Suspicious"
            else:
                status = "Safe"

            links.append({
                "url":               u,
                "full_domain":       parsed.netloc.lower(),
                "registered_domain": registered_domain,
                "status":            status,
                "redirect_detected": detect_redirect_chain(u),  # extra info for report
            })
        except Exception:
            continue

    return links


def detect_link_intent(text, links, brand_info):
    intent = 0.0
    lowered = text.lower()

    action_words = ["login", "verify", "update", "confirm", "password", "kyc"]
    if any(w in lowered for w in action_words):
        intent += 0.2

    if not links:
        return intent

    brand  = brand_info.get("brand")  if brand_info else None
    status = brand_info.get("status") if brand_info else None

    intent += 0.2  # Base risk for having links

    if brand and status == "verified":
        allowed_domains = TRUSTED_BRAND_PROFILES[brand]["link_domains"]
        for l in links:
            if not any(l["registered_domain"].endswith(d) for d in allowed_domains):
                intent += 0.4
    elif brand and status == "impersonation":
        intent += 0.5

    # STEP 3: Boost intent if redirect chain detected in any link
    if any(l.get("redirect_detected") for l in links):
        intent += 0.3

    if any(
        kw in l["url"].lower()
        for l in links
        for kw in ["login", "verify", "secure", "account"]
    ):
        intent += 0.2

    return min(intent, 1.0)
