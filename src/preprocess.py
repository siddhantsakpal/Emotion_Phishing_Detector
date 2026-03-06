#preprocess.py
import re
import string
from bs4 import BeautifulSoup

def clean_text(text):
    # safety check
    if not isinstance(text, str):
        return ""

    # Remove HTML safely
    soup = BeautifulSoup(text, "html.parser")
    text = soup.get_text(separator=" ")

    # lowercase
    text = text.lower()

    # handle common phishing obfuscation
    text = re.sub(r'\[\s*\.\s*\]', '.', text)   # [.] → .
    text = re.sub(r'\(\s*\.\s*\)', '.', text)   # (.) → .

    # remove urls
    text = re.sub(r'http\S+|www\S+', '', text)

    # remove newlines
    text = text.replace('\n', ' ')

    # remove punctuation except dots
    punctuation = string.punctuation.replace('.', '')
    text = text.translate(str.maketrans('', '', punctuation))

    # normalize spaces
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def clean_for_emotion(text):
    """
    Strips email footers, disclaimers, signatures, and legal boilerplate
    BEFORE emotion analysis so the model only reads the actual email body.
    Does NOT affect clean_text — only used for emotion detection.
    """
    if not isinstance(text, str):
        return ""

    lowered = text.lower()

    noise_patterns = [
        # Google footers
        r"does this item look suspicious.*",
        r"block sender.*",
        r"google llc.*?usa\.?",
        r"you have received this email because.*",
        r"©\s*\d{4}\s*google.*",
        r"you received this email to let you know.*",

        # General unsubscribe
        r"to unsubscribe.*",
        r"click here to unsubscribe.*",
        r"manage your (email )?preferences.*",
        r"you('re| are) receiving this (email|mail) because.*",
        r"if you no longer wish.*",
        r"remove (me |yourself )?from.*",
        r"opt.?out.*",

        # Legal disclaimers
        r"this (email|message) (and any attachments )?is (intended only for|confidential).*",
        r"if you (are not|were not) the intended recipient.*",
        r"any (unauthorized|unauthorised) (use|disclosure|copying).*",
        r"this communication is for informational purposes.*",
        r"privileged.*?confidential.*",

        # Privacy policies
        r"read our privacy (policy|guidelines).*",
        r"view our privacy policy.*",
        r"privacy policy.*terms.*",

        # Address boilerplate
        r"\d+\s+\w+\s+(street|avenue|road|parkway|blvd|way).*",
        r"p\.?o\.?\s*box\s*\d+.*",
        r"all rights reserved.*",
        r"copyright.*\d{4}.*",

        # Email threading noise
        r"on .{5,80} wrote:.*",
        r"----+\s*original message\s*----+.*",

        # Social sharing
        r"share this (email|message|newsletter).*",
        r"forward this email.*",
        r"view (this email|in browser).*",
    ]

    for pattern in noise_patterns:
        lowered = re.sub(pattern, " ", lowered,
                         flags=re.IGNORECASE | re.DOTALL)

    # Only use first 500 words — actual content is always at the top
    words = lowered.split()[:500]
    lowered = " ".join(words)

    # Normalize spaces
    lowered = re.sub(r'\s+', ' ', lowered).strip()

    return lowered
