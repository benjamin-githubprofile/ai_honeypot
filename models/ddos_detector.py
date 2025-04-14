import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime
import time
from typing import Dict, List, Tuple, Optional
import threading
import warnings
import sklearn.exceptions
from sklearn.utils.validation import check_is_fitted

warnings.filterwarnings("ignore", category=UserWarning)

class DDoSDetector:
    def __init__(self, model_dir: str = "models/trained"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.anomaly_model_path = os.path.join(model_dir, "ddos_anomaly_model.joblib")
        self.classifier_model_path = os.path.join(model_dir, "ddos_classifier_model.joblib")
        self._load_or_create_models()
        self.recent_anomalies = []
        self.max_recent_anomalies = 1000
        self.lock = threading.Lock()
        
    def _load_or_create_models(self):
        if os.path.exists(self.anomaly_model_path):
            try:
                self.anomaly_model = joblib.load(self.anomaly_model_path)
                print("Loaded anomaly detection model")
            except Exception as e:
                print(f"Error loading anomaly model: {e}")
                self.anomaly_model = self._create_anomaly_model()
                self._initialize_anomaly_model()  # Train with sample data
        else:
            self.anomaly_model = self._create_anomaly_model()
            self._initialize_anomaly_model()  # Train with sample data
        
        if os.path.exists(self.classifier_model_path):
            try:
                self.classifier_model = joblib.load(self.classifier_model_path)
                print("Loaded attack classifier model")
            except Exception as e:
                print(f"Error loading classifier model: {e}")
                self.classifier_model = self._create_classifier_model()
        else:
            self.classifier_model = self._create_classifier_model()
    
    def _create_anomaly_model(self):
        """Create a new anomaly detection model."""
        model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Assuming ~10% of traffic might be anomalous
            random_state=42,
            n_jobs=-1  # Use all available processors
        )
        return model
    
    def _create_classifier_model(self):
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        return model
    
    def _extract_features(self, request_data: Dict) -> np.ndarray:
        features = []
        
        req_freq = request_data.get("request_frequency", 0)
        features.append(req_freq)
        
        conn_time = request_data.get("connection_time", 1)
        features.append(conn_time)
        
        completed = 1 if request_data.get("completed", True) else 0
        features.append(completed)
        
        header_count = len(request_data.get("headers", {}))
        features.append(header_count)
        
        ua = request_data.get("headers", {}).get("User-Agent", "")
        suspicious_ua = 1 if any(kw in ua.lower() for kw in ["bot", "curl", "python", "go-http"]) else 0
        features.append(suspicious_ua)
        
        req_size = request_data.get("request_size", 0)
        features.append(req_size)
        
        time_since_last = request_data.get("time_since_last_request", 100)
        features.append(time_since_last)
        
        return np.array(features).reshape(1, -1)
    
    def detect_anomaly(self, request_data: Dict) -> Dict:
        with self.lock:
            features = self._extract_features(request_data)
            
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            try:
                check_is_fitted(self.anomaly_model)
                model_fitted = True
            except sklearn.exceptions.NotFittedError:
                model_fitted = False
                print("Model not fitted, initializing now...")
                self._initialize_anomaly_model()
            
            try:
                if model_fitted:
                    anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
                    is_anomaly = self.anomaly_model.predict(features_scaled)[0] == -1

                    anomaly_probability = 1.0 - (max(0, anomaly_score + 0.5) / 2)
                else:
                    req_freq = request_data.get("request_frequency", 0)
                    header_count = len(request_data.get("headers", {}))
                    
                    is_anomaly = req_freq > 10 or (req_freq > 5 and header_count < 3)
                    anomaly_probability = min(0.5 + (req_freq / 20), 0.9) if is_anomaly else 0.1
                    anomaly_score = -0.5 if is_anomaly else 0.5
            except Exception as e:
                print(f"Error in anomaly detection: {e}")
                req_freq = request_data.get("request_frequency", 0)
                header_count = len(request_data.get("headers", {}))
                
                is_anomaly = req_freq > 10 or (req_freq > 5 and header_count < 3)
                anomaly_probability = min(0.5 + (req_freq / 20), 0.9) if is_anomaly else 0.1
                anomaly_score = -0.5 if is_anomaly else 0.5
            
            if len(self.recent_anomalies) >= self.max_recent_anomalies:
                self.recent_anomalies.pop(0)
            
            timestamp = time.time()
            self.recent_anomalies.append({
                "timestamp": timestamp,
                "ip": request_data.get("ip", "unknown"),
                "is_anomaly": is_anomaly,
                "score": anomaly_score,
                "probability": anomaly_probability,
                "features": features.tolist()[0]
            })
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score,
                "anomaly_probability": anomaly_probability,
                "timestamp": timestamp
            }
    
    def classify_attack_type(self, request_data: Dict) -> Dict:
        features = self._extract_features(request_data)
        
        if request_data.get("request_frequency", 0) > 10:
            attack_type = "HTTP_FLOOD"
            confidence = min(0.5 + (request_data.get("request_frequency", 0) / 100), 0.95)
        elif request_data.get("connection_time", 0) > 10 and not request_data.get("completed", True):
            attack_type = "SLOW_LORIS"
            confidence = min(0.5 + (request_data.get("connection_time", 0) / 60), 0.95)
        elif not request_data.get("completed", True) and request_data.get("connection_time", 0) < 2:
            attack_type = "TCP_SYN_FLOOD"
            confidence = 0.8
        elif request_data.get("connection_time", 0) < 0.5:
            attack_type = "UDP_FLOOD"
            confidence = 0.7
        else:
            attack_type = "UNKNOWN"
            confidence = 0.5
        
        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "timestamp": time.time()
        }
    
    def identify_attack_clusters(self, recent_requests: List[Dict], eps: float = 0.5, min_samples: int = 5) -> Dict:
        if len(recent_requests) < min_samples:
            return {"clusters": [], "num_clusters": 0}
        
        features_list = []
        for req in recent_requests:
            if "features" in req:
                features_list.append(req["features"])
            else:
                features = self._extract_features(req)
                features_list.append(features[0])
        
        features_array = np.array(features_list)
        
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_array)
        
        clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(features_scaled)
        
        labels = clustering.labels_
        
        unique_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        
        clusters = {}
        for i, label in enumerate(labels):
            if label == -1:
                continue
                
            if label not in clusters:
                clusters[label] = []
            
            clusters[label].append({
                "ip": recent_requests[i].get("ip", "unknown"),
                "timestamp": recent_requests[i].get("timestamp", 0),
                "features": recent_requests[i].get("features", [])
            })
        
        clusters_list = [{"cluster_id": k, "requests": v} for k, v in clusters.items()]
        
        return {
            "clusters": clusters_list,
            "num_clusters": unique_clusters,
            "total_requests": len(recent_requests),
            "noise_points": list(labels).count(-1)
        }
    
    def train_models(self, training_data: List[Dict]) -> Dict:
        if not training_data:
            return {"status": "error", "message": "No training data provided"}
        
        with self.lock:
            features_list = []
            anomaly_labels = []
            attack_type_labels = []
            
            for entry in training_data:
                features = self._extract_features(entry)
                features_list.append(features[0])
                
                anomaly_labels.append(1 if not entry.get("is_anomaly", False) else -1)
                
                attack_type_labels.append(entry.get("attack_type", "UNKNOWN"))
            
            features_array = np.array(features_list)
            
            self.anomaly_model = self._create_anomaly_model()
            self.anomaly_model.fit(features_array)
            
            if len(set(attack_type_labels)) > 1:
                self.classifier_model = self._create_classifier_model()
                self.classifier_model.fit(features_array, attack_type_labels)
            
            joblib.dump(self.anomaly_model, self.anomaly_model_path)
            joblib.dump(self.classifier_model, self.classifier_model_path)
            
            return {
                "status": "success",
                "message": "Models trained successfully",
                "anomaly_model": str(self.anomaly_model),
                "classifier_model": str(self.classifier_model),
                "samples_trained": len(features_list)
            }
    
    def get_attack_trends(self, hours: int = 24) -> Dict:
        with self.lock:
            if not self.recent_anomalies:
                return {"status": "error", "message": "No data available for trend analysis"}
            
            cutoff_time = time.time() - (hours * 3600)
            recent_data = [entry for entry in self.recent_anomalies if entry["timestamp"] >= cutoff_time]
            
            if not recent_data:
                return {"status": "error", "message": f"No data available in the last {hours} hours"}
            
            hourly_counts = {}
            for entry in recent_data:
                hour = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:00")
                if hour not in hourly_counts:
                    hourly_counts[hour] = {"total": 0, "anomalies": 0}
                
                hourly_counts[hour]["total"] += 1
                if entry["is_anomaly"]:
                    hourly_counts[hour]["anomalies"] += 1
            
            hourly_rates = []
            for hour, counts in hourly_counts.items():
                hourly_rates.append({
                    "hour": hour,
                    "total_requests": counts["total"],
                    "anomalies": counts["anomalies"],
                    "anomaly_rate": counts["anomalies"] / counts["total"] if counts["total"] > 0 else 0
                })
            
            hourly_rates.sort(key=lambda x: x["hour"])
            
            total_requests = sum(counts["total"] for counts in hourly_counts.values())
            total_anomalies = sum(counts["anomalies"] for counts in hourly_counts.values())
            
            return {
                "status": "success",
                "total_requests": total_requests,
                "total_anomalies": total_anomalies,
                "anomaly_rate": total_anomalies / total_requests if total_requests > 0 else 0,
                "hourly_breakdown": hourly_rates,
                "hours_analyzed": hours
            }

    def _initialize_anomaly_model(self):
        print("Training anomaly model with sample data...")
        try:
            sample_data = np.array([
                [1, 1.0, 1, 10, 0, 1000, 10],
                [2, 0.8, 1, 8, 0, 800, 5],
                [0.5, 1.2, 1, 12, 0, 1200, 20],
                [1.5, 0.9, 1, 9, 0, 900, 8],
                [0.8, 1.1, 1, 11, 0, 1100, 15],
                [15, 0.1, 0, 3, 1, 200, 0.1],
                [20, 0.2, 0, 2, 1, 100, 0.2],
                [18, 0.15, 0, 1, 1, 150, 0.1],
                [25, 0.3, 0, 2, 1, 120, 0.3]
            ])
            
            self.anomaly_model.fit(sample_data)
            
            test_prediction = self.anomaly_model.predict(sample_data[0:1])
            print(f"Model test prediction successful: {test_prediction}")
            
            joblib.dump(self.anomaly_model, self.anomaly_model_path)
            print("Saved initialized anomaly model")
            
        except Exception as e:
            print(f"Error initializing anomaly model: {e}")
            print("Using simplified fallback model...")
            self.anomaly_model = IsolationForest(
                n_estimators=10,
                max_samples=10,
                contamination=0.1,
                random_state=42
            )
            self.anomaly_model.fit(sample_data)

_detector_instance = None

def get_detector():
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = DDoSDetector()
    return _detector_instance