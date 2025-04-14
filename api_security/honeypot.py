import json
import time
import re
import os
import uuid
from datetime import datetime

class APIHoneypot:
    def __init__(self, log_file="logs/api_honeypot.log"):
        self.log_file = log_file
        self.decoy_endpoints = {
            "/api/v1/admin/login": {
                "type": "admin",
                "severity": "critical",
                "response": {"error": "Unauthorized access attempt logged"},
                "methods": ["POST", "GET"]
            },
            "/api/v1/admin/users": {
                "type": "admin",
                "severity": "critical",
                "response": {"error": "Insufficient permissions"},
                "methods": ["GET", "POST", "PUT", "DELETE"]
            },
            "/api/internal/configs": {
                "type": "internal",
                "severity": "high",
                "response": {"error": "Access denied to internal API"},
                "methods": ["GET", "POST"]
            },
            "/api/internal/keys": {
                "type": "internal",
                "severity": "critical",
                "response": {"error": "Security exception: access attempt logged"},
                "methods": ["GET"]
            },
            "/api/debug/logs": {
                "type": "debug",
                "severity": "medium",
                "response": {"error": "Debug mode not enabled in production"},
                "methods": ["GET"]
            },
            "/api/system/debug": {
                "type": "debug",
                "severity": "high",
                "response": {"error": "System debug interface disabled"},
                "methods": ["GET", "POST"]
            },
            "/api/v1/users/all": {
                "type": "data_access",
                "severity": "high",
                "response": {"error": "Rate limit exceeded"},
                "methods": ["GET"]
            },
            "/api/v1/export/database": {
                "type": "data_access",
                "severity": "critical",
                "response": {"error": "Operation not permitted"},
                "methods": ["GET", "POST"]
            },
            "/api/v1/graphql": {
                "type": "vulnerability",
                "severity": "medium",
                "response": {"error": "GraphQL endpoint not available"},
                "methods": ["POST", "GET"]
            },
            "/api/private/keys": {
                "type": "vulnerability",
                "severity": "critical",
                "response": {"error": "Endpoint does not exist"},
                "methods": ["GET"]
            }
        }
        
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    def is_honeypot_endpoint(self, endpoint, method="GET"):
        """Check if an endpoint is a honeypot endpoint"""
        if endpoint in self.decoy_endpoints:
            if method in self.decoy_endpoints[endpoint]["methods"]:
                return True, self.decoy_endpoints[endpoint]
        
        for decoy in self.decoy_endpoints:
            if decoy.endswith("s") and endpoint.startswith(decoy + "/"):
                if method in self.decoy_endpoints[decoy]["methods"]:
                    return True, self.decoy_endpoints[decoy]
        
        return False, None

    def get_response(self, endpoint, method="GET"):
        is_honeypot, config = self.is_honeypot_endpoint(endpoint, method)
        
        if is_honeypot:
            tracking_id = str(uuid.uuid4())[:8]
            
            response = config["response"].copy()
            response["tracking_id"] = tracking_id
            
            time.sleep(0.5)
            
            return response, config["severity"], tracking_id
        
        return None, None, None

    def log_interaction(self, endpoint, method, client_ip, headers=None, body=None, params=None):
        is_honeypot, config = self.is_honeypot_endpoint(endpoint, method)
        
        if not is_honeypot:
            return False
            
        _, severity, tracking_id = self.get_response(endpoint, method)
        
        safe_headers = {}
        if headers:
            for key, value in headers.items():
                if key.lower() in ["authorization", "cookie", "api-key"]:
                    safe_headers[key] = "[REDACTED]"
                else:
                    safe_headers[key] = value
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "method": method,
            "client_ip": client_ip,
            "headers": safe_headers,
            "params": params,
            "body_sample": str(body)[:100] if body else None,
            "severity": severity,
            "type": config["type"],
            "tracking_id": tracking_id
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
        return True
    
    def get_dummy_data(self, endpoint_type):
        if endpoint_type == "admin":
            return {
                "users": [
                    {"id": 1, "username": "admin", "role": "admin", "email": "admin@example.com"},
                    {"id": 2, "username": "manager", "role": "manager", "email": "manager@example.com"},
                    {"id": 3, "username": "user1", "role": "user", "email": "user1@example.com"}
                ]
            }
        elif endpoint_type == "internal":
            return {
                "config": {
                    "debug": False,
                    "environment": "production",
                    "api_rate_limit": 100,
                    "maintenance_mode": False,
                    "api_keys": [
                        {"key": "k_1234567890abcdef", "owner": "system", "permissions": "full"},
                        {"key": "k_abcdef1234567890", "owner": "readonly", "permissions": "read"}
                    ]
                }
            }
        elif endpoint_type == "data_access":
            return {
                "limit": 50,
                "offset": 0,
                "total": 1250,
                "data": [
                    {"id": 1, "name": "Sample User 1", "email": "user1@example.com"},
                    {"id": 2, "name": "Sample User 2", "email": "user2@example.com"},
                    {"id": 3, "name": "Sample User 3", "email": "user3@example.com"}
                ]
            }
        else:
            return {"status": "error", "message": "Access denied"}
    
    def get_honeypot_logs(self, limit=100, severity=None, type=None):
        logs = []
        
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        
                        if severity and log_entry.get("severity") != severity:
                            continue
                            
                        if type and log_entry.get("type") != type:
                            continue
                            
                        logs.append(log_entry)
                        
                        if len(logs) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
            
        return logs
    
    def get_honeypot_stats(self):
        logs = self.get_honeypot_logs(limit=1000)
        
        if not logs:
            return {
                "total_interactions": 0,
                "unique_ips": 0,
                "severity_counts": {},
                "type_counts": {},
                "recent_interactions": []
            }
            
        unique_ips = set(log.get("client_ip") for log in logs)
        
        severity_counts = {}
        for log in logs:
            severity = log.get("severity")
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
        type_counts = {}
        for log in logs:
            log_type = log.get("type")
            if log_type:
                type_counts[log_type] = type_counts.get(log_type, 0) + 1
                
        logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        recent = logs[:10]
        
        return {
            "total_interactions": len(logs),
            "unique_ips": len(unique_ips),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "recent_interactions": recent
        }
        
def get_api_honeypot():
    """Get or create an API honeypot instance"""
    honeypot = APIHoneypot()
    return honeypot 