import os
import json
import pandas as pd
import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

class CredentialStorage:
    def __init__(self, base_dir="credential_data"):
        """Initialize the credential storage system with a base directory."""
        self.base_dir = base_dir
        
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
            os.makedirs(os.path.join(base_dir, "raw_attempts"))
            os.makedirs(os.path.join(base_dir, "processed_data"))
            os.makedirs(os.path.join(base_dir, "models"))
        
        counts_file = os.path.join(base_dir, "counts.json")
        if not os.path.exists(counts_file):
            with open(counts_file, "w") as f:
                json.dump({"total_attempts": 0}, f)
        
        self.model_path = os.path.join(base_dir, "models", "credential_model.joblib")
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            
        self.feature_names = [
            "username_length", 
            "password_length", 
            "username_has_number", 
            "common_username",
            "password_complexity",
            "username_password_match"
        ]
    
    def store_attempt(self, username, password, analysis):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{timestamp}.json"
        
        data = {
            "timestamp": str(datetime.datetime.now()),
            "username": username,
            "password_hash": hash(password),
            "password_length": len(password),
            "analysis": analysis
        }
        
        filepath = os.path.join(self.base_dir, "raw_attempts", filename)
        with open(filepath, "w") as f:
            json.dump(data, f)
        
        counts_file = os.path.join(self.base_dir, "counts.json")
        with open(counts_file, "r") as f:
            counts = json.load(f)
        counts["total_attempts"] += 1
        with open(counts_file, "w") as f:
            json.dump(counts, f)
        
        features = self._extract_features(username, password, analysis)
        self._prepare_for_model_update(features, analysis)
        
        return filepath
    
    def _extract_features(self, username, password, analysis):
        features = {
            "username_length": len(username),
            "password_length": len(password),
            "username_has_number": any(char.isdigit() for char in username),
            "common_username": 1 if username.lower() in ["admin", "root", "user", "test", "guest"] else 0,
            "password_complexity": sum([
                any(char.isupper() for char in password),
                any(char.isdigit() for char in password),
                any(not char.isalnum() for char in password)
            ]),
            "username_password_match": 1 if username.lower() in password.lower() or password.lower() in username.lower() else 0,
            "risk_score": analysis["risk_score"]
        }
        return features
    
    def _prepare_for_model_update(self, features, analysis):
        processed_file = os.path.join(self.base_dir, "processed_data", "training_data.csv")
        
        row = {name: features[name] for name in self.feature_names}
        row["risk_score"] = features["risk_score"]
        row["is_attack"] = 1 if features["risk_score"] > 0.5 else 0
        
        if os.path.exists(processed_file):
            df = pd.read_csv(processed_file)
            df.loc[len(df)] = row
            df.to_csv(processed_file, index=False)
        else:
            df = pd.DataFrame([row])
            df.to_csv(processed_file, index=False)
    
    def update_model(self):
        processed_file = os.path.join(self.base_dir, "processed_data", "training_data.csv")
        
        if not os.path.exists(processed_file):
            return False, "No training data available yet"
        
        df = pd.read_csv(processed_file)
        if len(df) < 10:
            return False, f"Not enough data ({len(df)} samples, need at least 10)"
        
        X = df[self.feature_names]
        y = df["is_attack"]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        predictions = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        
        joblib.dump(self.model, self.model_path)
        
        return True, f"Model updated with {len(df)} samples. Accuracy: {accuracy:.2f}"
    
    def predict_risk(self, username, password):
        if not hasattr(self, 'model') or self.model is None:
            return None, "No trained model available"
        
        features = {
            "username_length": len(username),
            "password_length": len(password),
            "username_has_number": any(char.isdigit() for char in username),
            "common_username": 1 if username.lower() in ["admin", "root", "user", "test", "guest"] else 0,
            "password_complexity": sum([
                any(char.isupper() for char in password),
                any(char.isdigit() for char in password),
                any(not char.isalnum() for char in password)
            ]),
            "username_password_match": 1 if username.lower() in password.lower() or password.lower() in username.lower() else 0
        }
        
        X = np.array([[features[name] for name in self.feature_names]])
        
        prediction = self.model.predict_proba(X)
        risk_score = prediction[0][1]
        
        return risk_score, "ML model prediction"
    
    def get_statistics(self):
        stats = {
            "total_attempts": 0,
            "unique_usernames": set(),
            "high_risk_attempts": 0,
            "most_common_usernames": [],
            "latest_update": "Never"
        }
        
        counts_file = os.path.join(self.base_dir, "counts.json")
        with open(counts_file, "r") as f:
            counts = json.load(f)
        stats["total_attempts"] = counts["total_attempts"]
        
        raw_attempts_dir = os.path.join(self.base_dir, "raw_attempts")
        usernames = {}
        
        if os.path.exists(raw_attempts_dir):
            for filename in os.listdir(raw_attempts_dir):
                if filename.endswith(".json"):
                    filepath = os.path.join(raw_attempts_dir, filename)
                    with open(filepath, "r") as f:
                        attempt = json.load(f)
                    
                    username = attempt["username"]
                    stats["unique_usernames"].add(username)
                    
                    if username in usernames:
                        usernames[username] += 1
                    else:
                        usernames[username] = 1
                    
                    if attempt["analysis"]["risk_score"] > 0.5:
                        stats["high_risk_attempts"] += 1
        
        stats["most_common_usernames"] = sorted(
            usernames.items(), key=lambda x: x[1], reverse=True
        )[:5]
        
        stats["unique_usernames"] = len(stats["unique_usernames"])
        
        if os.path.exists(self.model_path):
            mod_time = os.path.getmtime(self.model_path)
            stats["latest_update"] = datetime.datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M:%S")
        
        return stats