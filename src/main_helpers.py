#main_helpers.py
import re

SAFE_DOMAINS = {
    # Google
    "google.com", "accounts.google.com", "myaccount.google.com",
    "googleusercontent.com", "gstatic.com", "googleapis.com",
    "mail.google.com", "gmail.com",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "office365.com", "microsoftonline.com", "azure.com",
    "account.microsoft.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon
    "amazon.com", "amazon.in", "amazonaws.com",
    # PayPal
    "paypal.com",
    # Meta
    "facebookmail.com", "facebook.com", "fb.com", "instagram.com", "meta.com",
    # Twitter / X
    "twitter.com", "x.com",
    # LinkedIn
    "linkedin.com",
    # Snapchat
    "snapchat.com", "snap.com",
    # Indian banks
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "kotakbank.com",
    # FamPay / FamApp
    "fampay.in", "fampay.com", "famapp.in",
    # Others
    "netflix.com", "spotify.com",
    "youtube.com", "youtu.be",
    "whatsapp.com", "uber.com",
    "swiggy.com", "zomato.com",
}

TRUSTED_BRAND_PROFILES = {

    "google": {
        "sender_domains": ["google.com", "gmail.com", "accounts.google.com"],
        "link_domains": [
            "google.com", "googleusercontent.com", "gstatic.com",
            "myaccount.google.com", "googleapis.com", "mail.google.com",
        ],
    },

    "famapp": {
        "sender_domains": ["famapp.in"],
        "link_domains": ["famapp.in"],
    },

    "microsoft": {
        "sender_domains": ["microsoft.com", "outlook.com", "office.com"],
        "link_domains": [
            "microsoft.com", "live.com", "office.com",
            "office365.com", "microsoftonline.com", "account.microsoft.com",
        ],
    },

    "amazon": {
        "sender_domains": ["amazon.com", "amazon.in"],
        "link_domains": ["amazon.com", "amazon.in", "amazonaws.com"],
    },

    "apple": {
        "sender_domains": ["apple.com", "icloud.com"],
        "link_domains": ["apple.com", "icloud.com"],
    },

    "paypal": {
        "sender_domains": ["paypal.com"],
        "link_domains": ["paypal.com"],
    },

    "meta": {
        "sender_domains": ["facebookmail.com", "facebook.com"],
        "link_domains": ["facebook.com", "fb.com", "instagram.com", "meta.com"],
    },

    "twitter": {
        "sender_domains": ["twitter.com", "x.com"],
        "link_domains": ["twitter.com", "x.com"],
    },

    "linkedin": {
        "sender_domains": ["linkedin.com"],
        "link_domains": ["linkedin.com"],
    },

    "snapchat": {
        "sender_domains": ["snapchat.com", "snap.com"],
        "link_domains": ["snapchat.com", "snap.com"],
    },

    "netflix": {
        "sender_domains": ["netflix.com"],
        "link_domains": ["netflix.com", "help.netflix.com"],
    },

    "youtube": {
        "sender_domains": ["youtube.com", "google.com"],
        "link_domains": ["youtube.com", "youtu.be"],
    },

    "instagram": {
        "sender_domains": ["instagram.com", "facebookmail.com"],
        "link_domains": ["instagram.com"],
    },

    "whatsapp": {
        "sender_domains": ["whatsapp.com"],
        "link_domains": ["whatsapp.com"],
    },

    "spotify": {
        "sender_domains": ["spotify.com"],
        "link_domains": ["spotify.com"],
    },

    "uber": {
        "sender_domains": ["uber.com"],
        "link_domains": ["uber.com"],
    },

    "swiggy": {
        "sender_domains": ["swiggy.com"],
        "link_domains": ["swiggy.com"],
    },

    "zomato": {
        "sender_domains": ["zomato.com"],
        "link_domains": ["zomato.com"],
    },

    "sbi": {
        "sender_domains": ["sbi.co.in"],
        "link_domains": ["sbi.co.in", "onlinesbi.sbi"],
    },

    "hdfc": {
        "sender_domains": ["hdfcbank.com"],
        "link_domains": ["hdfcbank.com"],
    },

    "icici": {
        "sender_domains": ["icicibank.com"],
        "link_domains": ["icicibank.com"],
    },

    "axis": {
        "sender_domains": ["axisbank.com"],
        "link_domains": ["axisbank.com"],
    },

    "kotak": {
        "sender_domains": ["kotak.com", "kotakbank.com"],
        "link_domains": ["kotak.com", "kotakbank.com"],
    },

    "fampay": {
        "sender_domains": ["fampay.in", "fampay.com"],
        "link_domains": ["fampay.in", "fampay.com"],
    },
}

PHISHING_KEYWORDS = [
    "verify", "urgent", "account", "password", "login", "secure",
    "suspend", "unusual activity", "confirm", "delivery issue",
    "package delivery", "update your order", "account locked",
    "click here", "password reset", "atm block", "bank update",
    "security alert", "confirm identity", "verify your account",
    "update billing", "login required", "kyc update", "kyc pending",
    "atm blocked", "debit card blocked", "credit card blocked",
    "net banking", "mobile banking", "otp", "share otp",
    "customer care", "account temporarily blocked",
    "unusual transaction", "verify kyc", "bank alert",
]


def get_sender_domain(text):
    match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
    return match.group(1).lower() if match else None


