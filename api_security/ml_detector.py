import numpy as np
import pandas as pd
import os
import pickle
import json
import time
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer

class APIThreatDetector:
    def __init__(self, model_path="models/api_security"):
        self.model_path = model_path
        self.anomaly_model = None
        self.classification_model = None
        self.vectorizer = None
        self.scaler = None
        self._load_or_create_models()
        self.request_history = []
        self.max_history_size = 1000
        
        self.suspicious_patterns = [
            r"../../",              # Path traversal
            r"SELECT.*FROM",        # SQL injection
            r"<script>",            # XSS
            r"function\(\)",        # JS injection
            r"UNION SELECT",        # SQL injection
            r"exec\(",              # Command injection
            r"passw(or)?d",         # Password hunting
            r"admin",               # Admin access hunting
            r"token",               # Token hunting
            r"key",                 # API key hunting
            r"curl",                # Direct tool signature
            r"wget",                # Direct tool signature
            r"ObjectId",            # NoSQL injection
            r"eval\(",              # Code execution
            r";.*;",                # Command chaining
        ]
        
    def _load_or_create_models(self):
        os.makedirs(self.model_path, exist_ok=True)
        
        anomaly_path = os.path.join(self.model_path, "anomaly_model.pkl")
        if os.path.exists(anomaly_path):
            try:
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_model = pickle.load(f)
            except Exception:
                self.anomaly_model = IsolationForest(n_estimators=100, contamination=0.05)
        else:
            self.anomaly_model = IsolationForest(n_estimators=100, contamination=0.05)
        
        classification_path = os.path.join(self.model_path, "classification_model.pkl")
        if os.path.exists(classification_path):
            try:
                with open(classification_path, 'rb') as f:
                    self.classification_model = pickle.load(f)
            except Exception:
                self.classification_model = RandomForestClassifier(n_estimators=100)
        else:
            self.classification_model = RandomForestClassifier(n_estimators=100)
            
        vectorizer_path = os.path.join(self.model_path, "vectorizer.pkl")
        if os.path.exists(vectorizer_path):
            try:
                with open(vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
            except Exception:
                self.vectorizer = TfidfVectorizer(max_features=100)
        else:
            self.vectorizer = TfidfVectorizer(max_features=100)
            
        scaler_path = os.path.join(self.model_path, "scaler.pkl")
        if os.path.exists(scaler_path):
            try:
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            except Exception:
                self.scaler = StandardScaler()
        else:
            self.scaler = StandardScaler()
    
    def save_models(self):
        os.makedirs(self.model_path, exist_ok=True)
        
        with open(os.path.join(self.model_path, "anomaly_model.pkl"), 'wb') as f:
            pickle.dump(self.anomaly_model, f)
        
        with open(os.path.join(self.model_path, "classification_model.pkl"), 'wb') as f:
            pickle.dump(self.classification_model, f)
            
        with open(os.path.join(self.model_path, "vectorizer.pkl"), 'wb') as f:
            pickle.dump(self.vectorizer, f)
            
        with open(os.path.join(self.model_path, "scaler.pkl"), 'wb') as f:
            pickle.dump(self.scaler, f)
    
    def _extract_features(self, request_data):
        features = {
            "param_count": len(request_data.get("params", {})),
            "header_count": len(request_data.get("headers", {})),
            "endpoint_length": len(request_data.get("endpoint", "")),
            "has_auth": 1 if request_data.get("api_key") else 0,
            "query_length": len(json.dumps(request_data.get("params", {}))),
            "body_length": len(request_data.get("body", "")),
            "is_json": 1 if request_data.get("content_type", "").find("json") >= 0 else 0,
        }
        
        current_time = time.time()
        time_features = {
            "hour_of_day": datetime.fromtimestamp(current_time).hour,
            "day_of_week": datetime.fromtimestamp(current_time).weekday(),
        }
        
        features.update(time_features)
        
        ip = request_data.get("client_ip", "unknown")
        ip_history = [r for r in self.request_history if r.get("client_ip") == ip]
        
        if ip_history:
            features["requests_per_min"] = len(ip_history) / max(1, (current_time - ip_history[0].get("timestamp", 0)) / 60)
            features["unique_endpoints"] = len(set(r.get("endpoint", "") for r in ip_history))
            features["error_rate"] = sum(1 for r in ip_history if r.get("status_code", 200) >= 400) / len(ip_history)
        else:
            features["requests_per_min"] = 0
            features["unique_endpoints"] = 0
            features["error_rate"] = 0
            
        return features
    
    def _extract_text_features(self, request_data):
        texts = []
        
        texts.append(request_data.get("endpoint", ""))
        
        for key, value in request_data.get("params", {}).items():
            texts.append(f"{key}={value}")
            
        for header, value in request_data.get("headers", {}).items():
            if header.lower() in ["user-agent", "referer", "content-type"]:
                texts.append(f"{header}:{value}")
                
        body = request_data.get("body", "")
        if isinstance(body, str):
            texts.append(body)
            
        return " ".join(texts)
    
    def analyze_request(self, request_data):
        request_data["timestamp"] = time.time()
        
        self.request_history.append(request_data.copy())
        
        if len(self.request_history) > self.max_history_size:
            self.request_history = self.request_history[-self.max_history_size:]
            
        features = self._extract_features(request_data)
        text_features = self._extract_text_features(request_data)
        
        feature_names = sorted(features.keys())
        feature_array = np.array([features[name] for name in feature_names]).reshape(1, -1)
        
        pattern_matches = []
        for pattern in self.suspicious_patterns:
            import re
            if re.search(pattern, text_features, re.IGNORECASE):
                pattern_matches.append(pattern)
                
        is_honeypot_target = False
        if "endpoint" in request_data:
            honeypot_endpoints = [
                "/api/internal/configs", 
                "/api/v1/admin", 
                "/api/system/debug", 
                "/api/private/keys"
            ]
            is_honeypot_target = any(he in request_data["endpoint"] for he in honeypot_endpoints)
            
        anomaly_score = 0
        is_anomaly = False
        
        try:
            if hasattr(self.anomaly_model, "fit_predict") and self.scaler is not None:
                if hasattr(self.scaler, "transform"):
                    scaled_features = self.scaler.transform(feature_array)
                else:
                    scaled_features = feature_array
                
                # -1 for anomalies, 1 for normal
                anomaly_result = self.anomaly_model.predict(scaled_features)
                is_anomaly = anomaly_result[0] == -1
                
                if hasattr(self.anomaly_model, "decision_function"):
                    anomaly_score = abs(self.anomaly_model.decision_function(scaled_features)[0])
                else:
                    anomaly_score = 0.5
        except Exception as e:
            is_anomaly = False
            anomaly_score = 0
            
        threat_type = "Unknown"
        threat_confidence = 0
        
        try:
            if hasattr(self.classification_model, "predict_proba") and self.classification_model.classes_ is not None:
                if hasattr(self.scaler, "transform"):
                    scaled_features = self.scaler.transform(feature_array) 
                else:
                    scaled_features = feature_array
                
                proba = self.classification_model.predict_proba(scaled_features)[0]
                
                max_class_idx = np.argmax(proba)
                threat_type = self.classification_model.classes_[max_class_idx]
                threat_confidence = proba[max_class_idx]
        except Exception as e:
            threat_type = "Unknown"
            threat_confidence = 0
            
        threat_indicators = [
            1.0 if pattern_matches else 0.0,  # Rule-based patterns
            anomaly_score,                     # Anomaly score 
            threat_confidence,                 # Classification confidence
            1.0 if is_honeypot_target else 0.0 # Honeypot targeting
        ]
        
        overall_threat_score = sum(threat_indicators) / len(threat_indicators)
        
        if is_honeypot_target:
            final_classification = "Honeypot Target"
        elif pattern_matches and anomaly_score > 0.6:
            final_classification = "Definite Attack"
        elif pattern_matches:
            final_classification = "Likely Attack"
        elif is_anomaly:
            final_classification = "Anomalous Behavior"
        elif overall_threat_score > 0.5:
            final_classification = "Suspicious"
        else:
            final_classification = "Legitimate"
            
            return {
            "is_threat": final_classification != "Legitimate",
            "classification": final_classification,
            "threat_score": overall_threat_score,
            "pattern_matches": pattern_matches,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "threat_type": threat_type,
            "threat_confidence": threat_confidence,
            "is_honeypot_target": is_honeypot_target,
            "features": features,
            "timestamp": request_data["timestamp"]
        }
    
    def train_models(self, labeled_data):
        if not labeled_data or len(labeled_data) < 10:
            return {"status": "error", "message": "Not enough data to train (minimum 10 samples)"}
            
        try:
            features_list = []
            texts_list = []
            labels = []
            
            for entry in labeled_data:
                features = self._extract_features(entry)
                feature_names = sorted(features.keys())
                feature_values = [features[name] for name in feature_names]
                features_list.append(feature_values)
                
                text = self._extract_text_features(entry)
                texts_list.append(text)
                
                labels.append(1 if entry.get("is_threat", False) else 0)
                
            X = np.array(features_list)
            y = np.array(labels)
            
            self.scaler = StandardScaler().fit(X)
            X_scaled = self.scaler.transform(X)
            
            legitimate_indices = np.where(y == 0)[0]
            if len(legitimate_indices) > 5:  # Need at least 5 legitimate requests
                legitimate_features = X_scaled[legitimate_indices]
                self.anomaly_model = IsolationForest(n_estimators=100, contamination=0.05)
                self.anomaly_model.fit(legitimate_features)
            
            if len(set(y)) > 1:
                self.classification_model = RandomForestClassifier(n_estimators=100)
                self.classification_model.fit(X_scaled, y)
            
            if len(texts_list) > 5:
                self.vectorizer = TfidfVectorizer(max_features=100)
                self.vectorizer.fit(texts_list)
            
            self.save_models()
            
            return {
                "status": "success", 
                "samples_trained": len(labeled_data),
                "features_used": len(feature_names)
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def cluster_attacks(self, request_data_list, min_samples=2, eps=0.5):
        if not request_data_list or len(request_data_list) < min_samples:
            return {"clusters": [], "num_clusters": 0}
            
        try:
            features_list = []
            
            for entry in request_data_list:
                features = self._extract_features(entry)
                feature_names = sorted(features.keys())
                feature_values = [features[name] for name in feature_names]
                features_list.append(feature_values)
                
            X = np.array(features_list)
            
            if hasattr(self.scaler, "transform"):
                X_scaled = self.scaler.transform(X)
            else:
                self.scaler = StandardScaler().fit(X)
                X_scaled = self.scaler.transform(X)
                
            clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(X_scaled)
            
            labels = clustering.labels_
            
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            
            clusters = []
            
            for i in range(n_clusters):
                cluster_indices = np.where(labels == i)[0]
                cluster_requests = [request_data_list[idx] for idx in cluster_indices]
                
                clusters.append({
                    "cluster_id": i,
                    "size": len(cluster_indices),
                    "requests": cluster_requests
                })
                
            return {
                "clusters": clusters,
                "num_clusters": n_clusters,
                "noise_points": np.sum(labels == -1),
                "total_requests": len(request_data_list)
            }
            
        except Exception as e:
            return {"clusters": [], "num_clusters": 0, "error": str(e)}

def get_api_threat_detector():
    detector = APIThreatDetector()
    return detector 