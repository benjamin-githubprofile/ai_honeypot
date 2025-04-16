import re
import random
import string
from urllib.parse import urlparse

nltk_available = False
try:
    import nltk
    from nltk.tokenize import word_tokenize
    try:
        nltk.data.find('tokenizers/punkt')
        nltk_available = True
    except LookupError:
        try:
            nltk.download('punkt', quiet=True)
            nltk_available = True
        except:
            pass
except ImportError:
    pass

def simple_tokenize(text):
    for punct in string.punctuation:
        text = text.replace(punct, ' ')
    return [word for word in text.split() if word]

class PhishingDetector:
    def __init__(self):
        self.suspicious_domains = [
            "secure-verification", "account-verify", "login-secure",
            "secure-login", "customer-portal", "account-update",
            "banking-secure", "verification-center", "secure-auth",
            "auth-verify", "bank-secure", "paypal-secure",
            "payment-secure", "microsoft-verify", "apple-verify",
            "google-secure", "amazon-account", "netflix-billing"
        ]
        
        self.trusted_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "paypal.com", "facebook.com", "twitter.com", "instagram.com",
            "linkedin.com", "github.com", "netflix.com", "spotify.com"
        ]
        
        self.phishing_keywords = [
            "urgent", "verify", "suspended", "account", "update", "confirm",
            "security", "unusual", "access", "click", "link", "information",
            "password", "credit card", "ssn", "social security", "expire",
            "limited", "validate", "immediately", "attention", "required"
        ]
        
        self.urgency_phrases = [
            "immediate action", "urgent", "action required", "act now",
            "limited time", "expire", "24 hours", "immediately",
            "urgent notice", "final notice", "last chance", "warning"
        ]
        
        self.model_loaded = True
    
    def extract_urls(self, text):
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(url_pattern, text)
        
        markdown_links = re.findall(r'\[.*?\]\((https?://[^)]+)\)', text)
        urls.extend(markdown_links)
        
        html_links = re.findall(r'href=["\'](https?://[^\'"]+)["\']', text)
        urls.extend(html_links)
        
        return list(set(urls))
    
    def check_domain_mismatch(self, from_address, urls):
        if not from_address or '@' not in from_address:
            return True
        
        sender_domain = from_address.split('@')[1].lower()
        
        for url in urls:
            try:
                url_domain = urlparse(url).netloc.lower()
                
                for trusted_domain in self.trusted_domains:
                    if trusted_domain in sender_domain and trusted_domain not in url_domain:
                        return True
                    
                    if trusted_domain in sender_domain and self._levenshtein_distance(trusted_domain, url_domain) <= 2:
                        return True
            except:
                continue
                
        return False
    
    def check_suspicious_url(self, url):
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return True
            
            for suspicious in self.suspicious_domains:
                if suspicious in domain:
                    return True
            
            url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd']
            if any(shortener in domain for shortener in url_shorteners):
                return True
            
            unusual_tlds = ['.tk', '.top', '.xyz', '.ml', '.ga', '.cf', '.gq']
            if any(domain.endswith(tld) for tld in unusual_tlds):
                return True
            
            if domain.count('.') > 3:
                return True
            
            for trusted in self.trusted_domains:
                if trusted.split('.')[0] in domain and not domain.endswith(trusted):
                    return True
                    
            return False
        except:
            return True
    
    def analyze_text_content(self, text):
        if not text:
            return 0.0
            
        text = text.lower()
        
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in text)
        
        if nltk_available:
            try:
                words = word_tokenize(text)
            except:
                words = simple_tokenize(text)
        else:
            words = simple_tokenize(text)
            
        word_count = max(len(words), 1)
        keyword_density = keyword_count / word_count
        
        urgency_score = sum(1 for phrase in self.urgency_phrases if phrase in text) / len(self.urgency_phrases)
        
        personal_info_terms = ['password', 'credit card', 'account number', 'ssn', 'social security', 'banking']
        personal_info_score = sum(1 for term in personal_info_terms if term in text) / len(personal_info_terms)
        
        has_grammar_issues = False
        common_errors = ['your account have been', 'we need you details', 'kindly verify', 'valued customer']
        for error in common_errors:
            if error in text:
                has_grammar_issues = True
                break
        
        grammar_score = 0.5 if has_grammar_issues else 0.0
        
        content_score = (
            keyword_density * 0.3 +
            urgency_score * 0.3 +
            personal_info_score * 0.3 +
            grammar_score * 0.1
        )
        
        return min(content_score, 1.0)
    
    def _levenshtein_distance(self, s1, s2):
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def detect(self, email_data):
        if not email_data:
            return {"is_phishing": False, "confidence": 0.0, "indicators": []}
        
        from_address = email_data.get("from", "")
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        
        full_text = f"{subject} {body}"
        urls = self.extract_urls(full_text)
        
        indicators = []
        
        suspicious_sender = any(susp in from_address.lower() for susp in self.suspicious_domains)
        if suspicious_sender:
            indicators.append({
                "type": "suspicious_sender",
                "description": "Email is from a suspicious domain",
                "severity": "high"
            })
        
        domain_mismatch = self.check_domain_mismatch(from_address, urls)
        if domain_mismatch:
            indicators.append({
                "type": "domain_mismatch",
                "description": "The sender domain doesn't match URL domains in the email",
                "severity": "high"
            })
        
        suspicious_urls = []
        for url in urls:
            if self.check_suspicious_url(url):
                suspicious_urls.append(url)
        
        if suspicious_urls:
            indicators.append({
                "type": "suspicious_urls",
                "description": f"Contains {len(suspicious_urls)} suspicious URLs",
                "urls": suspicious_urls[:5],
                "severity": "critical"
            })
        
        content_score = self.analyze_text_content(full_text)
        if content_score > 0.5:
            indicators.append({
                "type": "suspicious_content",
                "description": "Email content contains phishing indicators",
                "severity": "medium" if content_score < 0.7 else "high"
            })
        
        subject_urgency = any(urgent in subject.lower() for urgent in self.urgency_phrases)
        if subject_urgency:
            indicators.append({
                "type": "urgency_subject",
                "description": "Subject line creates a false sense of urgency",
                "severity": "medium"
            })
        
        score_components = [
            0.7 if suspicious_sender else 0.0,
            0.8 if domain_mismatch else 0.0,
            0.9 if suspicious_urls else 0.0,
            content_score,
            0.5 if subject_urgency else 0.0
        ]
        
        max_score = max(score_components)
        avg_score = sum(score_components) / len(score_components)
        
        confidence = max_score * 0.7 + avg_score * 0.3
        
        is_phishing = confidence > 0.5
        
        phishing_type = None
        if is_phishing:
            if "bank" in full_text.lower() or "account" in full_text.lower():
                phishing_type = "banking_phishing"
            elif "password" in full_text.lower() or "login" in full_text.lower():
                phishing_type = "credential_phishing"
            elif "package" in full_text.lower() or "delivery" in full_text.lower():
                phishing_type = "delivery_phishing"
            elif "tax" in full_text.lower() or "refund" in full_text.lower():
                phishing_type = "tax_phishing"
            elif "microsoft" in full_text.lower() or "office" in full_text.lower():
                phishing_type = "microsoft_phishing"
            elif "apple" in full_text.lower() or "icloud" in full_text.lower():
                phishing_type = "apple_phishing"
            elif "google" in full_text.lower():
                phishing_type = "google_phishing"
            else:
                phishing_type = "general_phishing"
        
        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "type": phishing_type,
            "indicators": indicators
        }

_detector = None

def get_phishing_detector():
    global _detector
    if _detector is None:
        _detector = PhishingDetector()
    return _detector

def detect_phishing(email_data):
    detector = get_phishing_detector()
    return detector.detect(email_data)
