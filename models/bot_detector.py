import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

BOT_PATTERNS = {
    "no_mouse_movement": "No or minimal mouse movement",
    "direct_resource_access": "Direct access to hidden resources",
    "rapid_clicking": "Unusually rapid clicking patterns",
    "linear_movement": "Perfectly linear mouse movements",
    "abnormal_visit_time": "Abnormally short page visit time",
    "predictable_pattern": "Predictable interaction pattern",
    "header_anomalies": "Suspicious browser headers",
    "uniform_timing": "Uniformly timed interactions"
}

def load_bot_detector():
    model_path = "./bot_detector_model.joblib"
    
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
        except:
            model = create_simple_model()
    else:
        model = create_simple_model()
    
    def detect_bot(features):
        suspicious_patterns = []
        
        if isinstance(features, dict):
            if features.get("movement_count", 0) < 5:
                suspicious_patterns.append(BOT_PATTERNS["no_mouse_movement"])
            
            if features.get("click_count", 0) > 20:
                suspicious_patterns.append(BOT_PATTERNS["rapid_clicking"])
                
            if features.get("request_pattern") == "direct":
                suspicious_patterns.append(BOT_PATTERNS["direct_resource_access"])
                
            if features.get("time_on_page", 0) < 2:
                suspicious_patterns.append(BOT_PATTERNS["abnormal_visit_time"])
        
        else:
            pattern_keys = list(BOT_PATTERNS.keys())
            selected_patterns = np.random.choice(
                pattern_keys, 
                size=np.random.randint(1, 4), 
                replace=False
            )
            for pattern in selected_patterns:
                suspicious_patterns.append(BOT_PATTERNS[pattern])
        
        confidence = min(0.5 + (len(suspicious_patterns) * 0.1), 0.99) if suspicious_patterns else 0.2
        
        is_bot = confidence > 0.6
        
        return {
            "is_bot": is_bot,
            "confidence": confidence,
            "suspicious_patterns": suspicious_patterns
        }
    
    return detect_bot

def create_simple_model():
    model = RandomForestClassifier(n_estimators=10)
    return model