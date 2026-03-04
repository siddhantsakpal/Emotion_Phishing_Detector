#main_helpers.py
import re

SAFE_DOMAINS = {
    # Google
    "google.com", "accounts.google.com", "myaccount.google.com",
    "googleusercontent.com", "gstatic.com", "googleapis.com",
    "mail.google.com", "gmail.com", "google.co.in",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "office365.com", "microsoftonline.com", "azure.com",
    "account.microsoft.com", "signup.microsoft.com",
    "microsoft.mail.com", "protection.outlook.com",
    # Apple
    "apple.com", "icloud.com", "appleid.apple.com",
    # Amazon
    "amazon.com", "amazon.in", "amazonaws.com",
    "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazon-adsystem.com", "media-amazon.com",
    # PayPal
    "paypal.com", "paypal.me",
    # Meta
    "facebookmail.com", "facebook.com", "fb.com",
    "instagram.com", "meta.com", "messenger.com",
    # Twitter / X
    "twitter.com", "x.com", "t.co",
    # LinkedIn
    "linkedin.com", "licdn.com",
    # Snapchat
    "snapchat.com", "snap.com",
    # Indian banks
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "kotakbank.com",
    "paytm.com", "phonepe.com", "gpay.com",
    # FamPay / FamApp
    "fampay.in", "fampay.com", "famapp.in",
    # Tech / Services
    "github.com", "gitlab.com", "stackoverflow.com",
    "netflix.com", "spotify.com",
    "youtube.com", "youtu.be",
    "whatsapp.com", "uber.com", "ola.com",
    "swiggy.com", "zomato.com",
    "flipkart.com", "myntra.com",
    "razorpay.com", "stripe.com",
    "dropbox.com", "slack.com", "zoom.us",
    "atlassian.com", "jira.com", "confluence.com",
    "adobe.com", "canva.com",
    "notion.so", "trello.com",
}

TRUSTED_BRAND_PROFILES = {

    "google": {
        "sender_domains": [
            "google.com", "gmail.com", "accounts.google.com",
            "mail.google.com", "google.co.in", "no-reply.google.com",
        ],
        "link_domains": [
            "google.com", "googleusercontent.com", "gstatic.com",
            "myaccount.google.com", "googleapis.com", "mail.google.com",
            "google.co.in",
        ],
    },

    "microsoft": {
        "sender_domains": [
            "microsoft.com", "outlook.com", "office.com",
            "account.microsoft.com", "microsoftonline.com",
            "azure.com", "signup.microsoft.com",
            "microsoft.mail.com", "protection.outlook.com",
            "mails.microsoft.com", "email.microsoft.com",
        ],
        "link_domains": [
            "microsoft.com", "live.com", "office.com",
            "office365.com", "microsoftonline.com",
            "account.microsoft.com", "azure.com",
            "outlook.com", "sharepoint.com",
        ],
    },

    "amazon": {
        "sender_domains": [
            "amazon.com", "amazon.in", "amazon.co.uk",
            "amazon.de", "amazon.co.jp",
            "marketplace.amazon.com", "m.amazon.com",
        ],
        "link_domains": [
            "amazon.com", "amazon.in", "amazonaws.com",
            "amazon.co.uk", "media-amazon.com",
            "amazon-adsystem.com",
        ],
    },

    "apple": {
        "sender_domains": [
            "apple.com", "icloud.com", "appleid.apple.com",
            "email.apple.com",
        ],
        "link_domains": [
            "apple.com", "icloud.com", "appleid.apple.com",
        ],
    },

    "paypal": {
        "sender_domains": ["paypal.com", "e.paypal.com"],
        "link_domains":   ["paypal.com", "paypal.me"],
    },

    "meta": {
        "sender_domains": [
            "facebookmail.com", "facebook.com",
            "instagram.com", "meta.com",
        ],
        "link_domains": [
            "facebook.com", "fb.com", "instagram.com",
            "meta.com", "messenger.com",
        ],
    },

    "twitter": {
        "sender_domains": ["twitter.com", "x.com"],
        "link_domains":   ["twitter.com", "x.com", "t.co"],
    },

    "linkedin": {
        "sender_domains": ["linkedin.com", "e.linkedin.com"],
        "link_domains":   ["linkedin.com", "licdn.com"],
    },

    "snapchat": {
        "sender_domains": ["snapchat.com", "snap.com"],
        "link_domains":   ["snapchat.com", "snap.com"],
    },

    "netflix": {
        "sender_domains": ["netflix.com", "mailer.netflix.com"],
        "link_domains":   ["netflix.com", "help.netflix.com"],
    },

    "youtube": {
        "sender_domains": ["youtube.com", "google.com"],
        "link_domains":   ["youtube.com", "youtu.be"],
    },

    "instagram": {
        "sender_domains": ["instagram.com", "facebookmail.com"],
        "link_domains":   ["instagram.com"],
    },

    "whatsapp": {
        "sender_domains": ["whatsapp.com"],
        "link_domains":   ["whatsapp.com"],
    },

    "spotify": {
        "sender_domains": ["spotify.com", "email.spotify.com"],
        "link_domains":   ["spotify.com"],
    },

    "uber": {
        "sender_domains": ["uber.com", "email.uber.com"],
        "link_domains":   ["uber.com"],
    },

    "swiggy": {
        "sender_domains": ["swiggy.com"],
        "link_domains":   ["swiggy.com"],
    },

    "zomato": {
        "sender_domains": ["zomato.com"],
        "link_domains":   ["zomato.com"],
    },

    "github": {
        "sender_domains": ["github.com", "noreply.github.com"],
        "link_domains":   ["github.com", "githubusercontent.com"],
    },

    "razorpay": {
        "sender_domains": ["razorpay.com"],
        "link_domains":   ["razorpay.com"],
    },

    "stripe": {
        "sender_domains": ["stripe.com"],
        "link_domains":   ["stripe.com"],
    },

    "dropbox": {
        "sender_domains": ["dropbox.com"],
        "link_domains":   ["dropbox.com"],
    },

    "slack": {
        "sender_domains": ["slack.com"],
        "link_domains":   ["slack.com"],
    },

    "zoom": {
        "sender_domains": ["zoom.us"],
        "link_domains":   ["zoom.us"],
    },

    "flipkart": {
        "sender_domains": ["flipkart.com"],
        "link_domains":   ["flipkart.com"],
    },

    "adobe": {
        "sender_domains": ["adobe.com", "email.adobe.com"],
        "link_domains":   ["adobe.com"],
    },

    "sbi": {
        "sender_domains": ["sbi.co.in"],
        "link_domains":   ["sbi.co.in", "onlinesbi.sbi"],
    },

    "hdfc": {
        "sender_domains": ["hdfcbank.com"],
        "link_domains":   ["hdfcbank.com"],
    },

    "icici": {
        "sender_domains": ["icicibank.com"],
        "link_domains":   ["icicibank.com"],
    },

    "axis": {
        "sender_domains": ["axisbank.com"],
        "link_domains":   ["axisbank.com"],
    },

    "kotak": {
        "sender_domains": ["kotak.com", "kotakbank.com"],
        "link_domains":   ["kotak.com", "kotakbank.com"],
    },

    "paytm": {
        "sender_domains": ["paytm.com"],
        "link_domains":   ["paytm.com"],
    },

    "phonepe": {
        "sender_domains": ["phonepe.com"],
        "link_domains":   ["phonepe.com"],
    },

    "famapp": {
        "sender_domains": ["famapp.in"],
        "link_domains":   ["famapp.in"],
    },

    "fampay": {
        "sender_domains": ["fampay.in", "fampay.com"],
        "link_domains":   ["fampay.in", "fampay.com"],
    },
}

# ---------------------------------------------------------------
# Phishing keywords — used by keyword_detector.py
# Only include words that genuinely indicate phishing intent
# ---------------------------------------------------------------
PHISHING_KEYWORDS = [
    # High risk — strong phishing signals
    "urgent", "suspend", "suspended", "unusual activity",
    "account locked", "account temporarily blocked",
    "verify your account", "confirm identity",
    "atm block", "atm blocked", "debit card blocked",
    "credit card blocked", "share otp", "otp",
    "kyc update", "kyc pending", "verify kyc",
    "unusual transaction", "password reset",
    "login required", "delivery issue",
    "update your order", "security alert",

    # Medium risk
    "verify", "account", "password", "login", "secure",
    "confirm", "update billing", "click here",
    "net banking", "mobile banking", "bank alert",
    "customer care",

    # Low risk — common in both phishing and legitimate
    "bill", "billing", "invoice", "payment", "subscription",
    "order", "receipt", "transaction", "statement", "amount",
    "delivery", "delivered", "shipment", "tracking", "package",
]


def get_sender_domain(text):
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
    return match.group(1).lower() if match else None
