import streamlit as st
from functools import wraps
import time
from api_security.api_security import APISecurityManager

security_manager = APISecurityManager()

def secure_endpoint(required_permissions=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            endpoint = st.experimental_get_query_params().get("endpoint", [""])[0]
            client_ip = st.experimental_get_query_params().get("client_ip", ["127.0.0.1"])[0]
            api_key = st.experimental_get_query_params().get("api_key", [""])[0]
            
            if security_manager.rate_limiter.is_rate_limited(client_ip, endpoint):
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 429, response_time)
                return {"error": "Rate limit exceeded", "status": 429}
            
            valid_key, key_data = security_manager.key_manager.verify_key(api_key)
            if not valid_key:
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 401, response_time)
                return {"error": key_data, "status": 401}
            
            if required_permissions and not any(perm in key_data.get("permissions", []) for perm in required_permissions):
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 403, response_time)
                return {"error": "Insufficient permissions", "status": 403}
            
            params = st.experimental_get_query_params()
            headers = {}
            
            if security_manager.fuzzing_detector.is_fuzzing_attempt(endpoint, params, headers, client_ip):
                end_time = time.time()
                response_time = int((end_time - start_time) * 1000)
                security_manager.log_request(endpoint, client_ip, api_key, 400, response_time)
                return {"error": "Suspicious request detected", "status": 400}
            
            result = func(*args, **kwargs)
            
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
            security_manager.log_request(endpoint, client_ip, api_key, 200, response_time)
            
            return result
        return wrapper
    return decorator
