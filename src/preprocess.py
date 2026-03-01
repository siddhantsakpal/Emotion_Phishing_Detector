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
