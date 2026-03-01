from transformers import pipeline

# Global variable for Lazy Loading
_emotion_pipeline = None


def get_emotion_pipeline():
    global _emotion_pipeline
    if _emotion_pipeline is None:
        print("Loading Emotion Detection Model...")
        _emotion_pipeline = pipeline(
            "text-classification",
            model="j-hartmann/emotion-english-distilroberta-base",
            return_all_scores=True
        )
    return _emotion_pipeline


def detect_emotion(text):
    if not text.strip():
        return {"neutral": 1.0, "fear": 0.0, "anger": 0.0, "surprise": 0.0}

    emotion_pipeline = get_emotion_pipeline()

    # Chunking to avoid token limits
    chunks = [text[i:i + 1000] for i in range(0, len(text), 1000)]
    aggregated = {}

    for chunk in chunks:
        try:
            results = emotion_pipeline(chunk)
            # Handle potential nested lists
            if isinstance(results, list) and isinstance(results[0], list):
                results = results[0]

            for r in results:
                aggregated.setdefault(r["label"], []).append(r["score"])
        except Exception:
            continue

    if not aggregated:
        return {"neutral": 1.0}

    # Average scores
    emotions = {k: sum(v) / len(v) for k, v in aggregated.items()}

    # Normalize so total = 1.0
    total = sum(emotions.values())
    if total > 0:
        emotions = {k: v / total for k, v in emotions.items()}

    return emotions


# ---------------------------------------------------------------
# STEP 4: emotion_risk_boost — wired in from dead code
# Converts emotion scores into a single risk boost number.
# Cleaner than the manual if/else in false_positive_guard.py
# ---------------------------------------------------------------
def emotion_risk_boost(emotions: dict) -> float:
    """
    Returns a risk boost float (0.0 → 0.3) based on detected emotions.
    High fear/anger/surprise = higher phishing risk.
    High neutral = lower risk.
    Used by false_positive_guard.py instead of manual thresholds.
    """
    boost = 0.0
    boost += emotions.get("fear",     0) * 0.25
    boost += emotions.get("anger",    0) * 0.20
    boost += emotions.get("surprise", 0) * 0.15
    boost -= emotions.get("neutral",  0) * 0.10
    return round(max(boost, 0.0), 3)
