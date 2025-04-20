from transformers import pipeline
import os
import joblib

def load_classifier():
    cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".cache")
    os.makedirs(cache_dir, exist_ok=True)
    
    cache_path = os.path.join(cache_dir, "sentiment_classifier.joblib")
    
    if os.path.exists(cache_path):
        try:
            return joblib.load(cache_path)
        except:
            pass
    
    classifier = pipeline(
        "sentiment-analysis", 
        model="distilbert-base-uncased-finetuned-sst-2-english",
        local_files_only=False
    )
    
    joblib.dump(classifier, cache_path)
    
    return classifier