from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json

ATTACK_TYPES = {
    "HTTP_FLOOD": "HTTP Flood Attack",
    "SLOW_LORIS": "Slow Loris Attack", 
    "TCP_SYN_FLOOD": "TCP SYN Flood Attack",
    "UDP_FLOOD": "UDP Flood Attack",
    "DNS_AMPLIFICATION": "DNS Amplification Attack",
    "UNKNOWN": "Unknown Attack Pattern"
}

@dataclass
class AttackSignature:
    pattern_name: str
    pattern_type: str
    confidence: float
    indicators: Dict[str, float]
    
    def to_dict(self) -> Dict:
        return {
            "pattern_name": self.pattern_name,
            "pattern_type": self.pattern_type,
            "confidence": self.confidence,
            "indicators": self.indicators
        }

def analyze_request_pattern(request_data: Dict) -> AttackSignature:
    scores = {
        "HTTP_FLOOD": 0.0,
        "SLOW_LORIS": 0.0,
        "TCP_SYN_FLOOD": 0.0,
        "UDP_FLOOD": 0.0,
        "DNS_AMPLIFICATION": 0.0
    }
    
    indicators = {}
    
    if "request_frequency" in request_data:
        req_freq = request_data["request_frequency"]
        if req_freq > 30:
            scores["HTTP_FLOOD"] += 0.5
            indicators["high_request_frequency"] = req_freq
    
    if "connection_time" in request_data and "completed" in request_data:
        conn_time = request_data["connection_time"]
        completed = request_data["completed"]
        if conn_time > 30 and not completed:
            scores["SLOW_LORIS"] += 0.7
            indicators["long_connection_incomplete"] = conn_time
    
    if "headers" in request_data:
        headers = request_data["headers"]
        if len(headers) < 3:
            scores["HTTP_FLOOD"] += 0.3
            indicators["minimal_headers"] = len(headers)
        
        if "User-Agent" in headers:
            ua = headers["User-Agent"].lower()
            if "python" in ua or "go-http" in ua or "curl" in ua:
                scores["HTTP_FLOOD"] += 0.4
                indicators["suspicious_user_agent"] = headers["User-Agent"]
    
    attack_type = max(scores.items(), key=lambda x: x[1])
    
    if attack_type[1] < 0.4:
        pattern_type = "UNKNOWN"
        confidence = 0.2
    else:
        pattern_type = attack_type[0]
        confidence = attack_type[1]
    
    return AttackSignature(
        pattern_name=ATTACK_TYPES[pattern_type],
        pattern_type=pattern_type,
        confidence=confidence,
        indicators=indicators
    )

def simulate_ddos_attack(attack_type: str, intensity: int = 5) -> Dict:
    intensity = max(1, min(10, intensity))
    
    simulation = {
        "attack_type": attack_type,
        "intensity": intensity,
        "timestamp": datetime.now().isoformat(),
        "request_patterns": [],
        "characteristics": {}
    }
    
    if attack_type == "HTTP_FLOOD":
        req_per_second = 10 * intensity
        simulation["characteristics"] = {
            "requests_per_second": req_per_second,
            "distributed_sources": intensity > 5,
            "targets": ["login", "search", "api", "assets"],
            "description": "Rapid HTTP requests aimed at overwhelming server resources"
        }
        
    elif attack_type == "SLOW_LORIS":
        connections = 50 * intensity
        simulation["characteristics"] = {
            "concurrent_connections": connections,
            "connection_duration": 300,  # 5 minutes
            "partial_requests": True,
            "description": "Slow, incomplete HTTP requests that hold connections open"
        }
        
    elif attack_type == "TCP_SYN_FLOOD":
        packets_per_second = 20 * intensity
        simulation["characteristics"] = {
            "packets_per_second": packets_per_second,
            "syn_only": True,
            "spoofed_ip": True,
            "description": "TCP SYN packets without completing handshake"
        }
    
    else:
        simulation["characteristics"] = {
            "generic_load": 10 * intensity,
            "description": "Generic high-volume traffic to server resources"
        }
    
    return simulation

def detect_honeytoken_access(resource_path: str) -> bool:
    honeytokens = [
        "/api/internal/",
        "/admin/config/",
        "/system/credentials/",
        "/backup/",
        "/test/dev/",
        "/.well-known/security.txt"
    ]
    
    for token in honeytokens:
        if token in resource_path:
            return True
            
    return False