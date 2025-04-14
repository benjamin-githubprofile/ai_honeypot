import time
import jwt
import re
import uuid
import logging
import json
from functools import wraps
import streamlit as st
from datetime import datetime, timedelta

class APIRateLimiter:
    def __init__(self, limit=100, window=3600):
        self.limit = limit  # Number of requests allowed
        self.window = window  # Time window in seconds
        self.clients = {}  # Store client request history: {ip: [(timestamp, endpoint), ...]}
        
    def is_rate_limited(self, client_ip, endpoint):
        current_time = time.time()
        
        if client_ip not in self.clients:
            self.clients[client_ip] = []
        
        self.clients[client_ip] = [
            req for req in self.clients[client_ip] 
            if current_time - req[0] <= self.window
        ]
        
        self.clients[client_ip].append((current_time, endpoint))
        
        return len(self.clients[client_ip]) > self.limit
    
    def get_remaining_requests(self, client_ip):
        """Get remaining requests for a client"""
        if client_ip not in self.clients:
            return self.limit
        
        current_time = time.time()
        self.clients[client_ip] = [
            req for req in self.clients[client_ip] 
            if current_time - req[0] <= self.window
        ]
        
        return max(0, self.limit - len(self.clients[client_ip]))

class APIKeyManager:
    def __init__(self, key_file_path="config/api_keys.json"):
        self.key_file_path = key_file_path
        self.keys = self._load_keys()
        
    def _load_keys(self):
        try:
            with open(self.key_file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            default_keys = {
                "keys": {},
                "revoked_keys": []
            }
            import os
            os.makedirs(os.path.dirname(self.key_file_path), exist_ok=True)
            with open(self.key_file_path, 'w') as f:
                json.dump(default_keys, f, indent=4)
            return default_keys
    
    def verify_key(self, api_key):
        if api_key in self.keys.get("revoked_keys", []):
            return False, "API key has been revoked"
        
        if api_key not in self.keys.get("keys", {}):
            return False, "Invalid API key"
        
        key_data = self.keys["keys"][api_key]
        
        if "expires" in key_data and datetime.fromisoformat(key_data["expires"]) < datetime.now():
            return False, "API key has expired"
            
        return True, key_data
    
    def generate_key(self, owner, permissions=None, expires_days=None):
        api_key = f"hpot_{uuid.uuid4().hex}"
        
        key_data = {
            "owner": owner,
            "created": datetime.now().isoformat(),
            "permissions": permissions or ["read"],
        }
        
        if expires_days:
            expiry_date = datetime.now() + timedelta(days=expires_days)
            key_data["expires"] = expiry_date.isoformat()
        
        self.keys["keys"][api_key] = key_data
        self._save_keys()
        
        return api_key
    
    def revoke_key(self, api_key):
        if api_key in self.keys["keys"]:
            del self.keys["keys"][api_key]
            self.keys["revoked_keys"].append(api_key)
            self._save_keys()
            return True
        return False
    
    def _save_keys(self):
        with open(self.key_file_path, 'w') as f:
            json.dump(self.keys, f, indent=4)

class JWTManager:
    def __init__(self, secret_key=None, algorithm="HS256"):
        self.secret_key = secret_key or str(uuid.uuid4())
        self.algorithm = algorithm
        
    def generate_token(self, user_id, expiry_minutes=30, additional_claims=None):
        payload = {
            "sub": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=expiry_minutes)
        }
        
        if additional_claims:
            payload.update(additional_claims)
            
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "Token has expired"
        except jwt.InvalidTokenError:
            return False, "Invalid token"

class APIVersionManager:
    def __init__(self, current_version="v1", deprecated_versions=None, sunset_versions=None):
        self.current_version = current_version
        self.deprecated_versions = deprecated_versions or []
        self.sunset_versions = sunset_versions or []
        
    def check_version(self, version):
        if version == self.current_version:
            return True, "Current version"
        
        if version in self.deprecated_versions:
            return True, "Deprecated version - will be removed in future"
        
        if version in self.sunset_versions:
            return False, "Version no longer supported"
            
        return False, "Unknown version"

class APIFuzzingDetector:
    def __init__(self, valid_endpoints=None, log_file="logs/api_fuzzing.log"):
        self.valid_endpoints = valid_endpoints or []
        self.log_file = log_file
        self.suspicious_patterns = [
            r"[;'\"\(\)%<>]",  # Common injection characters
            r"\/\.\.\/",       # Path traversal attempts
            r"exec\s*\(",      # Command execution attempts
            r"\s(OR|AND)\s+\d+=\d+", # SQL injection patterns
            r"<script>"        # XSS attempts
        ]
        self.setup_logger()
        
    def setup_logger(self):
        import os
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        self.logger = logging.getLogger("api_fuzzing_detector")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def is_fuzzing_attempt(self, endpoint, params, headers, client_ip):
        endpoint_valid = any(
            re.match(valid_pattern, endpoint) 
            for valid_pattern in self.valid_endpoints
        ) if self.valid_endpoints else True
        
        has_suspicious_pattern = any(
            re.search(pattern, endpoint) or 
            any(re.search(pattern, str(value)) for value in params.values())
            for pattern in self.suspicious_patterns
        )
        
        if not endpoint_valid or has_suspicious_pattern:
            self.logger.warning(
                f"Potential API fuzzing detected: IP={client_ip}, Endpoint={endpoint}, "
                f"Valid={endpoint_valid}, Suspicious={has_suspicious_pattern}"
            )
            return True
            
        return False

class APISecurityManager:
    def __init__(self):
        self.rate_limiter = APIRateLimiter(limit=100, window=3600)
        self.key_manager = APIKeyManager()
        self.jwt_manager = JWTManager()
        self.version_manager = APIVersionManager()
        
        self.fuzzing_detector = APIFuzzingDetector(
            valid_endpoints=[
                r"^/api/v1/sentiment$",
                r"^/api/v1/users/\d+$",
            ]
        )
    
    def log_request(self, endpoint, client_ip, api_key, status_code, response_time):
        with open("logs/api_requests.log", "a") as f:
            timestamp = datetime.now().isoformat()
            f.write(f"{timestamp}|{client_ip}|{endpoint}|{api_key}|{status_code}|{response_time}ms\n")
