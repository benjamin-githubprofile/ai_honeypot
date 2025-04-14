from transformers import pipeline

def load_classifier():
    classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
    return classifier