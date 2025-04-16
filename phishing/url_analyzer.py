import re
import random
from urllib.parse import urlparse, parse_qs

def analyze_url(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query
        query_params = parse_qs(query)
        
        indicators = []
        
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            indicators.append({
                "type": "ip_address_url",
                "description": "URL uses an IP address instead of a domain name",
                "severity": "high"
            })
        
        suspicious_tlds = ['.tk', '.top', '.xyz', '.ml', '.ga', '.cf', '.gq']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            indicators.append({
                "type": "suspicious_tld",
                "description": f"Domain uses suspicious TLD: {domain.split('.')[-1]}",
                "severity": "medium"
            })
        
        url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly']
        if any(shortener in domain for shortener in url_shorteners):
            indicators.append({
                "type": "url_shortener",
                "description": "URL uses a shortening service",
                "severity": "medium"
            })
        
        if domain.count('.') > 3:
            indicators.append({
                "type": "excessive_subdomains",
                "description": f"Domain has an unusually high number of subdomains ({domain.count('.') + 1})",
                "severity": "medium"
            })
        
        popular_domains = [
            "google", "microsoft", "apple", "amazon", "facebook", 
            "paypal", "netflix", "bank", "secure", "login"
        ]
        
        for popular in popular_domains:
            if popular in domain and not any(domain.endswith(f"{popular}.com") for popular in popular_domains):
                indicators.append({
                    "type": "lookalike_domain",
                    "description": f"Domain may be impersonating {popular}",
                    "severity": "high"
                })
                break
        
        sensitive_keywords = [
            "login", "signin", "account", "password", "pwd", "security", "secure",
            "update", "verify", "validation", "authenticate", "wallet", "ssn",
            "banking", "confirm", "credential"
        ]
        
        path_and_query = f"{path}?{query}".lower()
        matching_keywords = [keyword for keyword in sensitive_keywords if keyword in path_and_query]
        
        if matching_keywords:
            indicators.append({
                "type": "sensitive_keywords",
                "description": f"URL contains sensitive keywords: {', '.join(matching_keywords[:3])}",
                "keywords": matching_keywords,
                "severity": "medium"
            })
        
        suspicious_params = ["account", "password", "email", "ssn", "card", "token"]
        found_params = [param for param in suspicious_params if param in query_params]
        
        if found_params:
            indicators.append({
                "type": "suspicious_parameters",
                "description": f"URL requests sensitive information: {', '.join(found_params)}",
                "parameters": found_params,
                "severity": "high"
            })
        
        if len(url) > 100:
            indicators.append({
                "type": "long_complex_url",
                "description": f"Unusually long URL ({len(url)} characters)",
                "severity": "low"
            })
        
        risk_score = calculate_url_risk_score(indicators)
        
        return {
            "url": url,
            "domain": domain,
            "risk_score": risk_score,
            "is_suspicious": risk_score > 0.5,
            "indicators": indicators
        }
    
    except Exception as e:
        return {
            "url": url,
            "domain": None,
            "risk_score": 0.9,  # High risk for unparseable URLs
            "is_suspicious": True,
            "indicators": [{
                "type": "parse_error",
                "description": f"Could not parse URL: {str(e)}",
                "severity": "high"
            }]
        }

def calculate_url_risk_score(indicators):
    """Calculate risk score based on indicators"""
    if not indicators:
        return 0.0
    
    # Weight by severity
    severity_weights = {
        "low": 0.3,
        "medium": 0.6,
        "high": 0.9,
        "critical": 1.0
    }
    
    # Calculate weighted score
    total_weight = 0
    weighted_sum = 0
    
    for indicator in indicators:
        severity = indicator.get("severity", "medium")
        weight = severity_weights.get(severity, 0.5)
        
        total_weight += weight
        weighted_sum += weight
    
    if total_weight == 0:
        return 0.0
    
    return weighted_sum / total_weight

def get_url_risk_score(url):
    analysis = analyze_url(url)
    return analysis["risk_score"]
