import re
import random

class SQLInjectionDetector:
    def __init__(self):
        self.patterns = [
            r"union\s+select",
            r"union\s+all\s+select",
            r"\s+or\s+[\d\w]+\s*=\s*[\d\w]+",
            r"\s+or\s+['\"]\w+['\"][\s\w]*=[\s\w]*['\"]\w+['\"]",
            r"waitfor\s+delay",
            r"sleep\s*\(",
            r"pg_sleep",
            r"benchmark\s*\(",
            r"convert\s*\(",
            r"--\s+",
            r"#\s*$",
            r";\s*drop\s+table",
            r";\s*delete\s+from",
            r";\s*truncate\s+table",
            r"exec\s+",
            r"execute\s+",
            r"xp_cmdshell",
            r"information_schema",
            r"schema_name",
            r"table_name",
            r"column_name",
            r"sqlite_master"
        ]
        
        self.model_loaded = True
    
    def detect(self, query):
        if not query:
            return {"is_injection": False, "confidence": 0.0, "type": None}
        
        normalized_query = query.lower()
        
        matched_patterns = []
        for pattern in self.patterns:
            if re.search(pattern, normalized_query):
                matched_patterns.append(pattern)
        
        is_injection = len(matched_patterns) > 0
        
        confidence = min(len(matched_patterns) * 0.2, 0.99) if matched_patterns else 0.0
        
        if not is_injection and "'" in query:
            confidence = random.uniform(0.3, 0.5)
            is_injection = confidence > 0.4
        
        injection_type = None
        if is_injection:
            from sql_inject.sql_attack import classify_injection_type
            injection_type = classify_injection_type(query)
            
            if injection_type and injection_type != "Unknown/Other":
                confidence = min(confidence + 0.3, 0.99)
        
        return {
            "is_injection": is_injection,
            "confidence": confidence,
            "type": injection_type,
            "matched_patterns": matched_patterns if is_injection else []
        }

_detector = None

def get_sql_detector():
    global _detector
    if _detector is None:
        _detector = SQLInjectionDetector()
    return _detector

def detect_injection(query):
    detector = get_sql_detector()
    return detector.detect(query)
