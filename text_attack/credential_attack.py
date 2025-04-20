from transformers import pipeline
from utils.credential_storage import CredentialStorage

password_analyzer = pipeline("text-classification", model="distilbert-base-uncased")
credential_storage = CredentialStorage()

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
    """Update the machine learning model for credential attack detection.
    
    Returns:
        tuple: (success, message) where success is a boolean and message is a string
    """
    return credential_storage.update_model()

def get_credential_statistics():
    """Get statistics about credential attacks.
    
    Returns:
        dict: Statistics about credential attacks
    """
    return credential_storage.get_statistics()