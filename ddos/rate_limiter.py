import time
from datetime import datetime
from typing import Dict, List, Tuple, Set
from collections import deque, defaultdict
import threading

class RateLimiter:
    def __init__(self, window_size: int = 60, threshold: int = 30):
        self.window_size = window_size
        self.threshold = threshold
        self.requests = defaultdict(lambda: deque())
        self.blocked_ips = {}  # IP -> (timestamp_blocked, duration)
        self.lock = threading.Lock()  # Thread safety
        self.suspicious_threshold = int(threshold * 0.7)  # 70% of threshold
        self.warning_threshold = int(threshold * 0.5)  # 50% of threshold
        self.suspicion_levels = defaultdict(int)
        self.max_suspicion_level = 5
    
    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            if ip in self.blocked_ips:
                blocked_time, duration = self.blocked_ips[ip]
                current_time = time.time()
                
                if current_time - blocked_time >= duration:
                    del self.blocked_ips[ip]
                    return False
                return True
            return False
    
    def check_rate(self, ip: str) -> Tuple[bool, int, float]:
        if self.is_blocked(ip):
            return False, 0, 1.0
        
        with self.lock:
            current_time = time.time()
            window_start = current_time - self.window_size
            
            while self.requests[ip] and self.requests[ip][0] < window_start:
                self.requests[ip].popleft()
            
            current_count = len(self.requests[ip])
            
            threshold_percentage = current_count / self.threshold
            
            if current_count >= self.threshold:
                self.suspicion_levels[ip] = min(self.max_suspicion_level, self.suspicion_levels[ip] + 2)
            elif current_count >= self.suspicious_threshold:
                self.suspicion_levels[ip] = min(self.max_suspicion_level, self.suspicion_levels[ip] + 1)
            elif current_count <= self.warning_threshold:
                self.suspicion_levels[ip] = max(0, self.suspicion_levels[ip] - 1)
            
            self.requests[ip].append(current_time)
            
            allowed = current_count < self.threshold
            
            return allowed, current_count, threshold_percentage
    
    def record_request(self, ip: str) -> Tuple[bool, Dict]:
        allowed, count, threshold_pct = self.check_rate(ip)
        
        status = {
            "ip": ip,
            "request_count": count,
            "threshold": self.threshold,
            "window_size": self.window_size,
            "threshold_percentage": threshold_pct,
            "suspicion_level": self.suspicion_levels[ip],
            "allowed": allowed,
            "timestamp": datetime.now().isoformat()
        }
        
        return allowed, status
    
    def block_ip(self, ip: str, duration: int = 300) -> None:
        with self.lock:
            self.blocked_ips[ip] = (time.time(), duration)
            self.requests[ip] = deque()
    
    def get_suspicious_ips(self, min_suspicion_level: int = 3) -> List[Dict]:
        suspicious = []
        with self.lock:
            for ip, level in self.suspicion_levels.items():
                if level >= min_suspicion_level:
                    suspicious.append({
                        "ip": ip,
                        "suspicion_level": level,
                        "request_count": len(self.requests[ip]),
                        "is_blocked": ip in self.blocked_ips
                    })
        
        return sorted(suspicious, key=lambda x: x["suspicion_level"], reverse=True)
    
    def check_for_distributed_attack(self, time_window: int = 300) -> Dict:
        current_time = time.time()
        window_start = current_time - time_window
        
        with self.lock:
            active_ips = 0
            high_rate_ips = 0
            total_requests = 0
            
            for ip, requests in self.requests.items():
                recent_requests = [r for r in requests if r >= window_start]
                if recent_requests:
                    active_ips += 1
                    total_requests += len(recent_requests)
                    if len(recent_requests) >= self.suspicious_threshold:
                        high_rate_ips += 1
            
            is_distributed = active_ips > 10 and high_rate_ips > 5
            confidence = min(0.1 * high_rate_ips + 0.02 * active_ips, 0.95)
            
            return {
                "is_distributed_attack": is_distributed,
                "confidence": confidence,
                "active_ips": active_ips,
                "high_rate_ips": high_rate_ips,
                "total_requests": total_requests,
                "window_size": time_window,
                "timestamp": datetime.now().isoformat()
            }