import re
import random
import html
import hashlib
import json
from datetime import datetime

def sanitize_html(input_text):
    return html.escape(input_text)

def get_dummy_web_context():
    return {
        "comment_section": {
            "description": "User comments on an article",
            "unsafe_example": "<div class='comment'>USER_INPUT</div>",
            "safe_example": "<div class='comment'>SANITIZED_INPUT</div>",
            "comments": [
                {"user": "John", "text": "Great article, very informative!"},
                {"user": "Sarah", "text": "I disagree with point #3."},
                {"user": "Mike", "text": "Thanks for sharing this information."}
            ]
        },
        "search_box": {
            "description": "Search results showing the user's query",
            "unsafe_example": "Results for: USER_INPUT",
            "safe_example": "Results for: SANITIZED_INPUT",
            "recent_searches": ["product reviews", "discount code", "how to fix error"]
        },
        "profile_page": {
            "description": "User profile information displayed on a page",
            "unsafe_example": "<h2>USER_INPUT's Profile</h2><div>Bio: USER_INPUT</div>",
            "safe_example": "<h2>SANITIZED_INPUT's Profile</h2><div>Bio: SANITIZED_INPUT</div>",
            "user_data": {
                "name": "Sample User",
                "bio": "Web developer with 5 years experience",
                "location": "New York",
                "website": "https://example.com"
            }
        },
        "url_parameters": {
            "description": "URL parameters reflected in the page",
            "unsafe_example": "https://example.com/page?message=USER_INPUT",
            "safe_example": "https://example.com/page?message=SANITIZED_INPUT",
            "current_params": {"page": "1", "sort": "newest"}
        }
    }

def render_web_context(context_name, user_input, sanitize=True):
    contexts = get_dummy_web_context()
    if context_name not in contexts:
        return {"error": f"Context '{context_name}' not found"}
    
    context = contexts[context_name]
    
    sanitized_input = sanitize_html(user_input) if sanitize else user_input
    
    unsafe_output = context["unsafe_example"].replace("USER_INPUT", user_input)
    safe_output = context["safe_example"].replace("SANITIZED_INPUT", sanitized_input)
    
    if context_name == "url_parameters":
        base_url = "https://example.com/page?message="
        unsafe_output = base_url + user_input
        safe_output = base_url + sanitized_input
    
    return {
        "description": context["description"],
        "unsafe_output": unsafe_output,
        "safe_output": safe_output,
        "sanitized_input": sanitized_input,
        "raw_input": user_input
    }

def simulate_web_impact(xss_payload, context_name):
    from xss.detector import detect_xss
    detection = detect_xss(xss_payload)
    
    impacts = []
    
    if "<script>" in xss_payload.lower():
        impacts.append({
            "severity": "high",
            "type": "arbitrary_javascript",
            "description": "Allows execution of arbitrary JavaScript code"
        })
    
    if "document.cookie" in xss_payload.lower():
        impacts.append({
            "severity": "critical",
            "type": "cookie_theft",
            "description": "Could steal user session cookies allowing account takeover"
        })
        
    if "fetch(" in xss_payload.lower() or "xmlhttp" in xss_payload.lower():
        impacts.append({
            "severity": "critical",
            "type": "data_exfiltration",
            "description": "Could send sensitive data to an attacker-controlled server"
        })
    
    if "location" in xss_payload.lower():
        impacts.append({
            "severity": "high",
            "type": "redirection",
            "description": "Could redirect users to malicious websites"
        })
    
    if "onerror" in xss_payload.lower() or "onload" in xss_payload.lower():
        impacts.append({
            "severity": "high",
            "type": "event_trigger",
            "description": "Executes JavaScript when specific events occur"
        })
    
    if context_name == "comment_section":
        impacts.append({
            "severity": "high",
            "type": "stored_xss",
            "description": "Payload could affect all users viewing the comments"
        })
    elif context_name == "search_box":
        impacts.append({
            "severity": "medium",
            "type": "reflected_xss",
            "description": "Payload affects users who click malicious links"
        })
    elif context_name == "profile_page":
        impacts.append({
            "severity": "high",
            "type": "persistent_xss",
            "description": "Payload remains in the profile and affects visitors"
        })
    elif context_name == "url_parameters":
        impacts.append({
            "severity": "medium",
            "type": "reflected_xss",
            "description": "Payload in URL could be shared and affect others"
        })
    
    overall_severity = "low"
    if any(impact["severity"] == "critical" for impact in impacts):
        overall_severity = "critical"
    elif any(impact["severity"] == "high" for impact in impacts):
        overall_severity = "high"
    elif any(impact["severity"] == "medium" for impact in impacts):
        overall_severity = "medium"
    
    return {
        "overall_severity": overall_severity,
        "impacts": impacts,
        "is_xss": detection["is_xss"],
        "detection": detection
    }