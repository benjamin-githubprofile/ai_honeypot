from transformers import pipeline
from utils.credential_storage import CredentialStorage

_password_analyzer = None
_credential_storage = None

def get_password_analyzer():
    global _password_analyzer
    if _password_analyzer is None:
        _password_analyzer = pipeline("text-classification", model="distilbert-base-uncased")
    return _password_analyzer

def get_credential_storage():
    global _credential_storage
    if _credential_storage is None:
        _credential_storage = CredentialStorage()
    return _credential_storage

def analyze_login_attempt(username, password):
    analysis = {
        "risk_score": 0.0,
        "attack_type": "unknown",
        "common_pattern": False,
        "password_strength": "unknown"
    }
    
    common_usernames = ["admin", "root", "user", "test", "guest"]
    if username.lower() in common_usernames:
        analysis["risk_score"] += 0.3
        analysis["common_pattern"] = True
    
    # Only load the model when needed
    password_analyzer = get_password_analyzer()
    password_analysis = password_analyzer(password)
    
    if len(password) < 8:
        analysis["password_strength"] = "weak"
        analysis["risk_score"] += 0.2
    
    if username == password:
        analysis["attack_type"] = "identical_credentials"
        analysis["risk_score"] += 0.5
    elif password.lower() in ["password", "123456", "qwerty", "admin"]:
        analysis["attack_type"] = "common_password"
        analysis["risk_score"] += 0.4
    
    analysis["risk_score"] = min(analysis["risk_score"], 1.0)
    
    return analysis

def update_credential_model():
    return get_credential_storage().update_model()

def get_credential_statistics():
    return get_credential_storage().get_statistics()