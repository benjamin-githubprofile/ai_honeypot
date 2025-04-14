import re
import random

class XSSDetector:
    def __init__(self):
        self.patterns = [
            r"<script[^>]*>.*?</script>",
            r"<script[^>]*>",
            r"on\w+\s*=\s*['\"].*?['\"]",
            r"on\w+\s*=\s*[^'\"].*?[\s>]",
            r"javascript\s*:",
            r"<img[^>]*onerror[^>]*>",
            r"<iframe[^>]*src[^>]*>",
            r"<svg[^>]*onload[^>]*>",
            r"<body[^>]*onload[^>]*>",
            r"<input[^>]*onfocus[^>]*>",
            r"<marquee[^>]*onstart[^>]*>",
            r"(alert|confirm|prompt)\s*\(",
            r"eval\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
            r"innerHTML",
            r"&#x[0-9a-f]+;",
            r"&#[0-9]+;",
        ]
        
        self.entity_patterns = [
            r"&lt;script&gt;",
            r"&\#x[0-9a-f]+;",
            r"&\#[0-9]+;"
        ]
        
        self.model_loaded = True
    
    def detect(self, input_text):
        if not input_text:
            return {"is_xss": False, "confidence": 0.0, "type": None}
        
        matched_patterns = []
        for pattern in self.patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                matched_patterns.append(pattern)
        
        entity_matches = []
        for pattern in self.entity_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                entity_matches.append(pattern)
                
        is_xss = len(matched_patterns) > 0 or len(entity_matches) > 0
        
        confidence = min((len(matched_patterns) * 0.2) + (len(entity_matches) * 0.1), 0.99) if is_xss else 0.0
        
        if not is_xss and ("<" in input_text or ">" in input_text):
            confidence = random.uniform(0.2, 0.4)
            is_xss = confidence > 0.3
        
        xss_type = None
        if is_xss:
            from xss.xss_attack import classify_xss_type
            xss_type = classify_xss_type(input_text)
            
            if xss_type and xss_type != "Unknown/Other":
                confidence = min(confidence + 0.3, 0.99)
        
        return {
            "is_xss": is_xss,
            "confidence": confidence,
            "type": xss_type,
            "matched_patterns": matched_patterns if is_xss else []
        }

_detector = None

def get_xss_detector():
    global _detector
    if _detector is None:
        _detector = XSSDetector()
    return _detector

def detect_xss(input_text):
    detector = get_xss_detector()
    return detector.detect(input_text)