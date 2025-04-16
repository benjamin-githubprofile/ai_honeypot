from phishing.email_simulation import get_sample_emails, get_email_templates, generate_custom_phishing_email
from phishing.detector import detect_phishing, get_phishing_detector
from phishing.logger import log_phishing_attempt, get_phishing_logs
from phishing.url_analyzer import analyze_url, get_url_risk_score
from phishing.utils import render_email, extract_urls_from_email, get_email_risk_score, sanitize_email
from phishing.ai_honeypot import (
    get_ai_honeypot, generate_honeypot_scenarios, record_honeypot_interaction,
    simulate_attacker_interactions, train_honeypot_ai, analyze_honeypot_data
)

__all__ = [
    'get_sample_emails',
    'get_email_templates',
    'generate_custom_phishing_email',
    'detect_phishing',
    'get_phishing_detector',
    'log_phishing_attempt',
    'get_phishing_logs',
    'analyze_url',
    'get_url_risk_score',
    'render_email',
    'extract_urls_from_email',
    'get_email_risk_score',
    'sanitize_email',
    'get_ai_honeypot',
    'generate_honeypot_scenarios',
    'record_honeypot_interaction',
    'simulate_attacker_interactions',
    'train_honeypot_ai',
    'analyze_honeypot_data'
]