#phishing_models.py
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from trained_model import smooth_probs
# Global variables for Lazy Loading
_phishing_pipeline = None

def get_phishing_pipeline():
    """
    Lazy loads the heavy ML model only when first needed.
    Prevents the script from freezing on startup.
    """
    global _phishing_pipeline
    if _phishing_pipeline is None:
        print("Loading Phishing Detection Model... (this may take a moment)")
        model_name = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        ml_tokenizer = AutoTokenizer.from_pretrained(model_name)
        ml_model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
        _phishing_pipeline = pipeline(
            "text-classification",
            model=ml_model,
            tokenizer=ml_tokenizer,
            top_k=True
        )
    return _phishing_pipeline

def normalize_hf_output(hf_result):
    """
    Normalizes Hugging Face output to:
    phishing / legitimate / suspicious
    Compatible with LABEL_0 / LABEL_1 models
    """

    scores = {
        "phishing": 0.0,
        "legitimate": 0.0,
        "suspicious": 0.0
    }

    if not hf_result:
        return scores

    for r in hf_result:
        label = r["label"]
        score = float(r["score"])

        # Most phishing models:
        # LABEL_1 -> phishing
        # LABEL_0 -> legitimate
        if label in ["LABEL_1", "1"]:
            scores["phishing"] = score
        elif label in ["LABEL_0", "0"]:
            scores["legitimate"] = score

    # If both are zero, keep suspicious high
    if scores["phishing"] == 0 and scores["legitimate"] == 0:
        scores["suspicious"] = 1.0
    else:
        scores["suspicious"] = max(
            0.0,
            1.0 - (scores["phishing"] + scores["legitimate"])
        )

    return scores

def ml_predict(text, chunk_size=512):
    phishing_pipeline = get_phishing_pipeline()
    
    chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
    aggregated = {"phishing": 0.0, "suspicious": 0.0, "legitimate": 0.0}

    if not text.strip():
        return aggregated

    for chunk in chunks:
        try:
            result = phishing_pipeline(chunk)

            if isinstance(result, list) and len(result) == 1 and isinstance(result[0], list):
                result = result[0]

            normalized = normalize_hf_output(result)

            for k in aggregated:
                aggregated[k] += normalized[k]

        except Exception as e:
            print(f"Hugging Face Error: {e}")
            continue

    n = len(chunks)
    if n > 0:
        for k in aggregated:
            aggregated[k] = round(aggregated[k] / n, 3)

    return smooth_probs(aggregated, alpha=0.7)
