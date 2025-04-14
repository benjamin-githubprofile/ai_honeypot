import time
import json
from functools import wraps
from datetime import datetime
import streamlit as st
from .api_security import APISecurityManager
from .honeypot import get_api_honeypot
from .ml_detector import get_api_threat_detector

security_manager = APISecurityManager()
honeypot = get_api_honeypot()
threat_detector = get_api_threat_detector()

def api_middleware(endpoint):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            client_ip = kwargs.get("client_ip", "127.0.0.1")
            api_key = kwargs.get("api_key", "")
            method = kwargs.get("method", "GET")
            headers = kwargs.get("headers", {})
            params = kwargs.get("params", {})
            body = kwargs.get("body", "")
            
            for key in ["client_ip", "api_key", "method", "headers", "params", "body"]:
                if key in kwargs:
                    kwargs.pop(key, None)
            
            is_honeypot, honeypot_config = honeypot.is_honeypot_endpoint(endpoint, method)
            if is_honeypot:
                honeypot.log_interaction(endpoint, method, client_ip, headers, body, params)
                response, _, tracking_id = honeypot.get_response(endpoint, method)
                
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 403, response_time)
                
                return {
                    "status": "error",
                    "code": 403,
                    "message": response.get("error", "Access denied"),
                    "tracking_id": tracking_id,
                    "data": None
                }
            
            request_data = {
                "endpoint": endpoint,
                "client_ip": client_ip,
                "api_key": api_key,
                "method": method,
                "headers": headers,
                "params": params,
                "body": body,
                "content_type": headers.get("Content-Type", "")
            }
            
            threat_analysis = threat_detector.analyze_request(request_data)
            
            if threat_analysis["is_threat"]:
                security_manager.log_request(endpoint, client_ip, api_key, 403, 0, threat=threat_analysis)
                
                return {
                    "status": "error",
                    "code": 403,
                    "message": f"Request blocked: {threat_analysis['classification']}",
                    "tracking_id": str(time.time()),
                    "data": None
                }
            
            if security_manager.rate_limiter.is_rate_limited(client_ip, endpoint):
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 429, response_time)
                return {
                    "status": "error",
                    "code": 429,
                    "message": "Rate limit exceeded",
                    "data": None
                }
            
            valid_key, key_data = security_manager.key_manager.verify_key(api_key)
            if not valid_key:
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 401, response_time)
                return {
                    "status": "error",
                    "code": 401,
                    "message": key_data,
                    "data": None
                }
            
            api_version = kwargs.get("api_version", security_manager.version_manager.current_version)
            valid_version, version_message = security_manager.version_manager.check_version(api_version)
            
            if not valid_version:
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 410, response_time)
                return {
                    "status": "error",
                    "code": 410,
                    "message": version_message,
                    "data": None
                }
            
            if security_manager.fuzzing_detector.is_fuzzing_attempt(endpoint, kwargs, {}, client_ip):
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 400, response_time)
                return {
                    "status": "error",
                    "code": 400,
                    "message": "Suspicious request detected",
                    "data": None
                }
            
            try:
                result = func(*args, **kwargs)
                status_code = 200
                
                response = {
                    "status": "success",
                    "code": status_code,
                    "message": "OK",
                    "data": result
                }
                
                if valid_version and version_message != "Current version":
                    response["warning"] = version_message
                    
            except Exception as e:
                status_code = 500
                response = {
                    "status": "error",
                    "code": status_code,
                    "message": str(e),
                    "data": None
                }
            
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            security_manager.log_request(endpoint, client_ip, api_key, status_code, response_time)
            
            request_data["status_code"] = status_code
            request_data["response_time"] = response_time
            request_data["is_threat"] = False
            
            return response
            
        return wrapper
    return decorator

@api_middleware("/api/v1/sentiment")
def analyze_sentiment(text, **kwargs):
    from models.text_classifier import load_classifier
    classifier = load_classifier()
    result = classifier(text)
    return result

@api_middleware("/api/v1/users")
def get_users(**kwargs):
    users = [
        {"id": 1, "name": "Alice", "role": "Admin"},
        {"id": 2, "name": "Bob", "role": "User"},
        {"id": 3, "name": "Charlie", "role": "User"}
    ]
    return users

@api_middleware("/api/v1/stats")
def get_stats(**kwargs):
    stats = {
        "users": 1250,
        "requests_today": 5432,
        "uptime": "3d 12h 45m",
        "cpu_usage": "32%",
        "memory_usage": "45%"
    }
    return stats

def get_api_threat_stats():
    return {
        "total_threats_detected": len([r for r in threat_detector.request_history if r.get("is_threat", False)]),
        "honeypot_interactions": honeypot.get_honeypot_stats()["total_interactions"],
        "blocked_ips": len(set([r["client_ip"] for r in threat_detector.request_history if r.get("is_threat", False)])),
        "common_threat_types": {
            "Honeypot Target": 23,
            "SQL Injection": 15,
            "Anomalous Behavior": 12,
            "Fuzzing": 8,
            "Rate Limiting": 42
        },
        "threat_timeline": [
            {"date": "2023-07-01", "count": 12},
            {"date": "2023-07-02", "count": 8},
            {"date": "2023-07-03", "count": 15},
            {"date": "2023-07-04", "count": 10},
            {"date": "2023-07-05", "count": 5}
        ]
    }

def train_threat_models():
    training_data = threat_detector.request_history
    if not training_data:
        return {"status": "error", "message": "No training data available yet"}
    
    result = threat_detector.train_models(training_data)
    return result

def get_recent_threats(limit=10):
    threats = [r for r in threat_detector.request_history if r.get("is_threat", False)]
    threats.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return threats[:limit]
