from transformers import pipeline
import os
import pickle

def load_classifier():
    # Check if model is cached on disk
    cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "text_classifier.pkl")
    
    # Try to load from disk cache
    if os.path.exists(cache_file):
        try:
            print("Loading text classifier from cache")
            with open(cache_file, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading cached classifier: {e}")
    
    # If not cached or error, create a new one
    print("Creating new text classifier (will be cached)")
    classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
    
    # Cache for future use
    try:
        with open(cache_file, "wb") as f:
            pickle.dump(classifier, f)
    except Exception as e:
        print(f"Failed to cache classifier: {e}")
    
    return classifier