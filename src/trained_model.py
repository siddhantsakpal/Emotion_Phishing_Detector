#trained_model.py
import pickle
import os
from preprocess import clean_text

# ------------------- LOAD TRAINED MODEL -------------------
_trained_model = None
_trained_vectorizer = None


def load_local_model():
    global _trained_model, _trained_vectorizer

    if _trained_model is not None:
        return True

    try:
        # FIX: Try multiple possible locations so the file is always found
        candidates = [
            os.path.join(os.path.dirname(__file__), "phishing_model.pkl"),
            os.path.join(os.path.dirname(__file__), "..", "web", "phishing_model.pkl"),
            os.path.join(os.path.dirname(__file__), "..", "phishing_model.pkl"),
        ]
        for model_path in candidates:
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    _trained_model, _trained_vectorizer = pickle.load(f)
                return True

        print("Warning: phishing_model.pkl not found in any expected location.")
        return False
    except Exception as e:
        print(f"Warning: Could not load trained model: {e}")
        return False


def normalize_probs(probs):
    total = sum(probs.values())
    if total == 0:
        return probs
    return {k: round(v / total, 3) for k, v in probs.items()}


def smooth_probs(probs, alpha=0.7):
    smoothed = {k: v ** alpha for k, v in probs.items()}
    return normalize_probs(smoothed)


def trained_ml_predict(text, chunk_size=1000):
    if not load_local_model():
        return {"phishing": 0.0, "suspicious": 1.0, "legitimate": 0.0}

    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    phishing_scores = []
    legitimate_scores = []

    for chunk in chunks:
        cleaned = clean_text(chunk)
        if not cleaned:
            continue

        try:
            X = _trained_vectorizer.transform([cleaned])
            prob_legit, prob_phish = _trained_model.predict_proba(X)[0]
            phishing_scores.append(prob_phish)
            legitimate_scores.append(prob_legit)
        except Exception:
            continue

    if not phishing_scores:
        return {"phishing": 0.0, "suspicious": 1.0, "legitimate": 0.0}

    phishing   = sum(phishing_scores)   / len(phishing_scores)
    legitimate = sum(legitimate_scores) / len(legitimate_scores)
    suspicious = max(0.0, 1.0 - phishing - legitimate)

    probs = {
        "phishing":   phishing,
        "suspicious": suspicious,
        "legitimate": legitimate,
    }

    return normalize_probs(probs)
