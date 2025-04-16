import re
import html
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from phishing.url_analyzer import analyze_url

def sanitize_email(email_content):
    if not email_content:
        return ""
    
    try:
        soup = BeautifulSoup(email_content, 'html.parser')
        
        for tag in soup.find_all(['script', 'iframe', 'embed', 'object', 'applet']):
            tag.decompose()
        
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                if attr.startswith('on'):
                    del tag.attrs[attr]
                # Remove javascript: URLs
                if attr == 'href' or attr == 'src':
                    if tag.attrs[attr].lower().startswith('javascript:'):
                        tag.attrs[attr] = '#'
        
        return str(soup)
    except:
        return html.escape(email_content)

def extract_urls_from_email(email_data):
    if not email_data:
        return []
    
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    
    full_text = f"{subject} {body}"
    
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, full_text)
    
    markdown_links = re.findall(r'\[.*?\]\((https?://[^)]+)\)', full_text)
    urls.extend(markdown_links)
    
    html_links = re.findall(r'href=["\'](https?://[^\'"]+)["\']', full_text)
    urls.extend(html_links)
    
    return list(set(urls))

def get_email_risk_score(email_data):
    from phishing.detector import detect_phishing
    
    if not email_data:
        return 0.0
    
    detection_result = detect_phishing(email_data)
    phishing_score = detection_result["confidence"]
    
    urls = extract_urls_from_email(email_data)
    url_scores = []
    
    for url in urls:
        analysis = analyze_url(url)
        url_scores.append(analysis["risk_score"])
    
    avg_url_score = sum(url_scores) / len(url_scores) if url_scores else 0.0
    
    combined_score = phishing_score * 0.7 + avg_url_score * 0.3
    
    return combined_score

def render_email(email_data, sanitize=True):
    if not email_data:
        return {"error": "No email data provided"}
    
    from_address = email_data.get("from", "Unknown Sender")
    subject = email_data.get("subject", "No Subject")
    body = email_data.get("body", "")
    
    if sanitize:
        body = sanitize_email(body)
    
    rendered = {
        "from": from_address,
        "subject": subject,
        "body": body,
        "sanitized": sanitize,
        "urls": extract_urls_from_email(email_data),
        "is_html": bool(re.search(r'<[a-z]+>', body, re.IGNORECASE))
    }
    
    return rendered
