# attacks/credential_attack.py
from transformers import pipeline

# Load AI model for password analysis
password_analyzer = pipeline("text-classification", model="distilbert-base-uncased")

def analyze_login_attempt(username, password):
    """
    Analyzes a login attempt using AI to detect potential credential stuffing.
    
    Returns:
        dict: Analysis results including risk score and attack type
    """
    # Basic analysis
    analysis = {
        "risk_score": 0.0,
        "attack_type": "unknown",
        "common_pattern": False,
        "password_strength": "unknown"
    }
    
    # Check for common username patterns
    common_usernames = ["admin", "root", "user", "test", "guest"]
    if username.lower() in common_usernames:
        analysis["risk_score"] += 0.3
        analysis["common_pattern"] = True
    
    # Use the model to analyze password characteristics
    password_analysis = password_analyzer(password)
    
    # Basic password strength checks
    if len(password) < 8:
        analysis["password_strength"] = "weak"
        analysis["risk_score"] += 0.2
    
    # Detect common credential stuffing patterns
    if username == password:
        analysis["attack_type"] = "identical_credentials"
        analysis["risk_score"] += 0.5
    elif password.lower() in ["password", "123456", "qwerty", "admin"]:
        analysis["attack_type"] = "common_password"
        analysis["risk_score"] += 0.4
    
    # Normalize risk score
    analysis["risk_score"] = min(analysis["risk_score"], 1.0)
    
    return analysis