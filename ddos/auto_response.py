from typing import Dict, List, Tuple, Set, Optional
import time
from datetime import datetime
import threading
import json
import os
import random
from dataclasses import dataclass, field, asdict
import uuid

from models.ddos_detector import get_detector

@dataclass
class CaptchaChallenge:
    id: str
    ip: str
    timestamp: float
    expires_at: float
    solved: bool = False
    
    def is_valid(self) -> bool:
        return time.time() < self.expires_at and not self.solved

@dataclass
class ResponseAction:
    action_type: str
    ip: str
    timestamp: float
    duration: float
    reason: str
    severity: int
    details: Dict = field(default_factory=dict)
    
    def is_active(self) -> bool:
        return time.time() < (self.timestamp + self.duration)
    
    def to_dict(self) -> Dict:
        return asdict(self)

class AutomatedResponseSystem:
    def __init__(self, config_path: str = "config/auto_response_config.json"):
        self.config_path = config_path
        self.actions = []  # History of response actions taken
        self.captcha_challenges = {}  # Active CAPTCHA challenges by IP
        self.blocked_ips = set()  # Currently blocked IPs
        self.throttled_ips = {}  # Currently throttled IPs and their rates
        
        self.config = self._load_config()
        
        self.lock = threading.Lock()
        
        self.notification_history = {}
    
    def _load_config(self) -> Dict:
        default_config = {
            "throttling": {
                "enabled": True,
                "suspicion_thresholds": {
                    "1": {"rate": 0.9, "duration": 30},    # 90% of normal rate for 30s
                    "2": {"rate": 0.7, "duration": 60},    # 70% of normal rate for 60s
                    "3": {"rate": 0.5, "duration": 300},   # 50% of normal rate for 5min
                    "4": {"rate": 0.3, "duration": 600},   # 30% of normal rate for 10min
                    "5": {"rate": 0.1, "duration": 1800}   # 10% of normal rate for 30min
                }
            },
            "captcha": {
                "enabled": True,
                "suspicion_threshold": 3,  # Minimum suspicion level to trigger CAPTCHA
                "challenge_duration": 300,  # How long the challenge is valid for (5min)
                "cooldown": 1800  # Time before requiring another CAPTCHA (30min)
            },
            "blocking": {
                "enabled": True,
                "auto_block_threshold": 4,  # Suspicion level to auto-block
                "max_failed_captchas": 3,   # Failed CAPTCHAs before blocking
                "block_durations": {
                    "suspicion_4": 900,     # 15min for suspicion level 4
                    "suspicion_5": 3600,    # 1hr for suspicion level 5
                    "failed_captcha": 1800, # 30min for failing CAPTCHA
                    "repeat_offender": 86400 # 24hr for repeat offenders
                }
            }
        }
        
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    self._deep_update(default_config, loaded_config)
            else:
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, indent=2, fp=f)
        except Exception as e:
            print(f"Error loading configuration: {e}")
        
        return default_config
    
    def _deep_update(self, d: Dict, u: Dict) -> Dict:
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v
        return d
    
    def update_config(self, new_config: Dict) -> Dict:
        with self.lock:
            self._deep_update(self.config, new_config)
            
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, indent=2, fp=f)
            except Exception as e:
                print(f"Error saving configuration: {e}")
            
            return self.config
    
    def process_request(self, request_data: Dict, suspicion_level: int) -> Dict:
        ip = request_data.get("ip", "unknown")
        
        with self.lock:
            if ip in self.blocked_ips:
                return {
                    "action": "block",
                    "allowed": False,
                    "reason": "IP is blocked",
                    "details": self._get_active_action(ip, "block")
                }
            
            if ip in self.captcha_challenges:
                challenge = self.captcha_challenges[ip]
                if challenge.is_valid() and not challenge.solved:
                    return {
                        "action": "captcha",
                        "allowed": False,
                        "challenge_id": challenge.id,
                        "reason": "CAPTCHA required",
                        "details": {"expires_at": challenge.expires_at}
                    }
            
            action = self._determine_action(ip, suspicion_level, request_data)
            
            if action["action"] != "allow":
                self._record_action(ip, action)
            
            return action
    
    def _determine_action(self, ip: str, suspicion_level: int, request_data: Dict) -> Dict:
        detector = get_detector()
        
        if (self.config["blocking"]["enabled"] and 
            suspicion_level >= self.config["blocking"]["auto_block_threshold"]):
            
            if suspicion_level >= 5:
                duration = self.config["blocking"]["block_durations"]["suspicion_5"]
            else:
                duration = self.config["blocking"]["block_durations"]["suspicion_4"]
            
            self._block_ip(ip, duration, f"High suspicion level ({suspicion_level})", suspicion_level)
            
            return {
                "action": "block",
                "allowed": False,
                "duration": duration,
                "reason": f"Automatically blocked due to suspicion level {suspicion_level}"
            }
        
        if (self.config["captcha"]["enabled"] and 
            suspicion_level >= self.config["captcha"]["suspicion_threshold"]):
            
            cooldown = self.config["captcha"]["cooldown"]
            recent_captcha = any(
                a for a in self.actions 
                if a.ip == ip and a.action_type == "captcha" and 
                (time.time() - a.timestamp) < cooldown and a.details.get("solved", False)
            )
            
            if not recent_captcha:
                challenge = self._create_captcha_challenge(ip)
                
                return {
                    "action": "captcha",
                    "allowed": False,
                    "challenge_id": challenge.id,
                    "reason": f"CAPTCHA required due to suspicion level {suspicion_level}",
                    "details": {"expires_at": challenge.expires_at}
                }
        
        if self.config["throttling"]["enabled"] and suspicion_level > 0:
            throttle_level = str(suspicion_level)
            if throttle_level in self.config["throttling"]["suspicion_thresholds"]:
                throttle_config = self.config["throttling"]["suspicion_thresholds"][throttle_level]
                
                throttle_rate = throttle_config["rate"]
                duration = throttle_config["duration"]
                
                self._throttle_ip(ip, throttle_rate, duration, 
                                 f"Suspicion level {suspicion_level}", suspicion_level)
                
                return {
                    "action": "throttle",
                    "allowed": True,
                    "rate": throttle_rate,
                    "duration": duration,
                    "reason": f"Throttled due to suspicion level {suspicion_level}"
                }
        
        if suspicion_level >= 2:
            anomaly_result = detector.detect_anomaly(request_data)
            if anomaly_result["is_anomaly"]:
                self._record_action(ip, {
                    "action_type": "monitor",
                    "duration": 1800,
                    "reason": "ML-detected anomaly",
                    "severity": suspicion_level
                })
                
                return {
                    "action": "monitor",
                    "allowed": True,
                    "reason": "Request allowed but marked as suspicious by ML detection",
                    "details": {"anomaly_probability": anomaly_result["anomaly_probability"]}
                }
        
        return {
            "action": "allow",
            "allowed": True,
            "reason": "Below threshold for automated response"
        }
    
    def _get_active_action(self, ip: str, action_type: Optional[str] = None) -> Optional[Dict]:
        active_actions = [a.to_dict() for a in self.actions 
                         if a.ip == ip and a.is_active() and 
                         (action_type is None or a.action_type == action_type)]
        
        if active_actions:
            return max(active_actions, key=lambda a: a["timestamp"])
        return None
    
    def _record_action(self, ip: str, action: Dict) -> None:
        action_record = ResponseAction(
            action_type=action["action"],
            ip=ip,
            timestamp=time.time(),
            duration=action.get("duration", 300),
            reason=action.get("reason", "Unspecified"),
            severity=action.get("severity", 3),
            details=action.get("details", {})
        )
        
        self.actions.append(action_record)
        
        if len(self.actions) > 10000:
            current_time = time.time()
            self.actions = [a for a in self.actions if current_time < (a.timestamp + a.duration)]
    
    def _create_captcha_challenge(self, ip: str) -> CaptchaChallenge:
        """Create a new CAPTCHA challenge for an IP."""
        challenge_id = str(uuid.uuid4())
        duration = self.config["captcha"]["challenge_duration"]
        
        challenge = CaptchaChallenge(
            id=challenge_id,
            ip=ip,
            timestamp=time.time(),
            expires_at=time.time() + duration,
            solved=False
        )
        
        self.captcha_challenges[ip] = challenge
        
        self._record_action(ip, {
            "action": "captcha",
            "duration": duration,
            "reason": "CAPTCHA challenge issued",
            "severity": 3,
            "details": {"challenge_id": challenge_id}
        })
        
        return challenge
    
    def verify_captcha(self, ip: str, challenge_id: str, solution: str) -> Dict:
        with self.lock:
            if ip not in self.captcha_challenges:
                return {"success": False, "message": "No active CAPTCHA challenge found"}
            
            challenge = self.captcha_challenges[ip]
            
            if challenge.id != challenge_id:
                return {"success": False, "message": "Invalid challenge ID"}
            
            if not challenge.is_valid():
                del self.captcha_challenges[ip]
                return {"success": False, "message": "CAPTCHA challenge expired"}
            
            valid_solution = self._validate_captcha_solution(solution)
            
            if valid_solution:
                challenge.solved = True
                
                for action in self.actions:
                    if (action.ip == ip and action.action_type == "captcha" and 
                        action.details.get("challenge_id") == challenge_id):
                        action.details["solved"] = True
                        break
                
                return {"success": True, "message": "CAPTCHA solved successfully"}
            else:
                failed_attempts = sum(
                    1 for a in self.actions
                    if a.ip == ip and a.action_type == "captcha" and 
                    not a.details.get("solved", False) and
                    (time.time() - a.timestamp) < 3600
                )
                
                if failed_attempts >= self.config["blocking"]["max_failed_captchas"]:
                    duration = self.config["blocking"]["block_durations"]["failed_captcha"]
                    self._block_ip(ip, duration, "Multiple failed CAPTCHA attempts", 4)
                    
                    del self.captcha_challenges[ip]
                    
                    return {
                        "success": False,
                        "message": "Too many failed CAPTCHA attempts, IP blocked",
                        "blocked": True,
                        "duration": duration
                    }
                
                return {"success": False, "message": "Incorrect CAPTCHA solution"}
    
    def _validate_captcha_solution(self, solution: str) -> bool:
        return "human" in solution.lower()
    
    def _block_ip(self, ip: str, duration: int, reason: str, severity: int) -> None:
        self.blocked_ips.add(ip)
        
        unblock_time = time.time() + duration
        
        self._record_action(ip, {
            "action": "block",
            "duration": duration,
            "reason": reason,
            "severity": severity,
            "details": {"unblock_time": unblock_time}
        })

    def _throttle_ip(self, ip: str, rate: float, duration: int, reason: str, severity: int) -> None:
        self.throttled_ips[ip] = {
            "rate": rate,
            "until": time.time() + duration
        }
        
        self._record_action(ip, {
            "action": "throttle",
            "duration": duration,
            "reason": reason,
            "severity": severity,
            "details": {"rate": rate}
        })
    
    def get_response_status(self, ip: str) -> Dict:
        with self.lock:
            status = {"ip": ip}
            
            status["blocked"] = ip in self.blocked_ips
            
            if ip in self.throttled_ips:
                throttle_info = self.throttled_ips[ip]
                if time.time() < throttle_info["until"]:
                    status["throttled"] = True
                    status["throttle_rate"] = throttle_info["rate"]
                    status["throttle_expires"] = throttle_info["until"]
                else:
                    del self.throttled_ips[ip]
                    status["throttled"] = False
            else:
                status["throttled"] = False
            
            if ip in self.captcha_challenges:
                challenge = self.captcha_challenges[ip]
                if challenge.is_valid():
                    status["captcha_required"] = not challenge.solved
                    status["captcha_id"] = challenge.id if not challenge.solved else None
                    status["captcha_expires"] = challenge.expires_at
                else:
                    del self.captcha_challenges[ip]
                    status["captcha_required"] = False
            else:
                status["captcha_required"] = False
            
            current_time = time.time()
            recent_actions = [
                a.to_dict() for a in self.actions
                if a.ip == ip and (current_time - a.timestamp) < 86400
            ]
            
            status["recent_actions"] = sorted(
                recent_actions, 
                key=lambda a: a["timestamp"], 
                reverse=True
            )
            
            return status
    
    def cleanup_expired(self) -> None:
        with self.lock:
            current_time = time.time()
            
            active_blocks = [
                a for a in self.actions
                if a.action_type == "block" and a.is_active()
            ]
            
            self.blocked_ips = {a.ip for a in active_blocks}
            
            expired_throttles = [
                ip for ip, info in self.throttled_ips.items()
                if current_time >= info["until"]
            ]
            
            for ip in expired_throttles:
                del self.throttled_ips[ip]
            
            expired_challenges = [
                ip for ip, challenge in self.captcha_challenges.items()
                if not challenge.is_valid()
            ]
            
            for ip in expired_challenges:
                del self.captcha_challenges[ip]
    
    def get_config(self) -> Dict:
        """Get the current configuration."""
        return self.config

_response_system_instance = None

def get_response_system():
    """Get the singleton AutomatedResponseSystem instance."""
    global _response_system_instance
    if _response_system_instance is None:
        _response_system_instance = AutomatedResponseSystem()
    return _response_system_instance

class NotificationChannel:
    def send_alert(self, message: str, level: str, details: Dict) -> bool:
        """Send an alert through this channel."""
        raise NotImplementedError("Subclasses must implement send_alert")


class EmailNotifier(NotificationChannel):
    def __init__(self, config: Dict):
        self.config = config
        self.recipients = config.get("recipients", [])
        self.from_email = config.get("from_email", "ddos-alerts@example.com")
        self.smtp_server = config.get("smtp_server", "localhost")
        self.smtp_port = config.get("smtp_port", 25)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.use_tls = config.get("use_tls", False)
    
    def send_alert(self, message: str, level: str, details: Dict) -> bool:
        if not self.recipients:
            return False
            
        try:
            print(f"[EMAIL ALERT - {level}] To: {', '.join(self.recipients)}")
            print(f"Subject: DDoS Alert: {level} - {message}")
            print(f"Body: {message}\n\nDetails: {json.dumps(details, indent=2)}")
            return True
        except Exception as e:
            print(f"Error sending email alert: {e}")
            return False


class SMSNotifier(NotificationChannel):
    def __init__(self, config: Dict):
        self.config = config
        self.phone_numbers = config.get("phone_numbers", [])
        self.service = config.get("service", "twilio")
        self.account_sid = config.get("account_sid", "")
        self.auth_token = config.get("auth_token", "")
        self.from_number = config.get("from_number", "")
    
    def send_alert(self, message: str, level: str, details: Dict) -> bool:
        if not self.phone_numbers:
            return False
            
        try:
            print(f"[SMS ALERT - {level}] To: {', '.join(self.phone_numbers)}")
            print(f"Message: DDoS {level} Alert: {message}")
            return True
        except Exception as e:
            print(f"Error sending SMS alert: {e}")
            return False


class WebhookNotifier(NotificationChannel):
    def __init__(self, config: Dict):
        self.config = config
        self.endpoints = config.get("endpoints", [])
        self.headers = config.get("headers", {})
        self.include_details = config.get("include_details", True)
    
    def send_alert(self, message: str, level: str, details: Dict) -> bool:
        if not self.endpoints:
            return False
            
        try:
            payload = {
                "alert_level": level,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
            
            if self.include_details:
                payload["details"] = details
                
            print(f"[WEBHOOK ALERT - {level}] To: {', '.join(self.endpoints)}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
            return True
        except Exception as e:
            print(f"Error sending webhook alert: {e}")
            return False


class SlackDiscordNotifier(NotificationChannel):
    """Slack/Discord notification channel."""
    def __init__(self, config: Dict):
        self.config = config
        self.service = config.get("service", "slack")
        self.webhook_url = config.get("webhook_url", "")
        self.channel = config.get("channel", "#security-alerts")
        self.username = config.get("username", "DDoS Defense Bot")
        self.icon = config.get("icon", ":shield:")
        self.include_details = config.get("include_details", True)
    
    def send_alert(self, message: str, level: str, details: Dict) -> bool:
        if not self.webhook_url:
            return False
            
        try:
            color_map = {
                "info": "#36a64f", 
                "warning": "#f2c744", 
                "critical": "#d00000" 
            }
            color = color_map.get(level.lower(), "#888888")
            
            if self.service == "slack":
                payload = {
                    "channel": self.channel,
                    "username": self.username,
                    "icon_emoji": self.icon,
                    "attachments": [
                        {
                            "color": color,
                            "title": f"DDoS Alert: {level}",
                            "text": message,
                            "fields": []
                        }
                    ]
                }
                
                if self.include_details and details:
                    for key, value in details.items():
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        payload["attachments"][0]["fields"].append({
                            "title": key,
                            "value": str(value),
                            "short": len(str(value)) < 30
                        })
            else:
                payload = {
                    "username": self.username,
                    "embeds": [
                        {
                            "title": f"DDoS Alert: {level}",
                            "description": message,
                            "color": int(color.replace("#", ""), 16),
                            "fields": []
                        }
                    ]
                }
                
                if self.include_details and details:
                    for key, value in details.items():
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        payload["embeds"][0]["fields"].append({
                            "name": key,
                            "value": str(value),
                            "inline": len(str(value)) < 30
                        })
            
            service_name = "Slack" if self.service == "slack" else "Discord"
            print(f"[{service_name} ALERT - {level}] To: {self.channel}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
            return True
        except Exception as e:
            print(f"Error sending {self.service} alert: {e}")
            return False


class NotificationSystem:
    def __init__(self, config_path: str = "config/notification_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.channels = self._setup_channels()
        self.recent_alerts = {}
        self.lock = threading.Lock()
    
    def _load_config(self) -> Dict:
        default_config = {
            "thresholds": {
                "info": 1,     
                "warning": 3,  
                "critical": 4 
            },
            "cooldown_periods": {
                "info": 3600,    
                "warning": 1800,  
                "critical": 300   
            },
            "channels": {
                "email": {
                    "enabled": False,
                    "recipients": [],
                    "from_email": "ddos-alerts@example.com",
                    "smtp_server": "localhost",
                    "smtp_port": 25,
                    "use_tls": False
                },
                "sms": {
                    "enabled": False,
                    "phone_numbers": [],
                    "service": "twilio"
                },
                "webhook": {
                    "enabled": True,
                    "endpoints": ["https://example.com/security-webhook"],
                    "include_details": True
                },
                "slack": {
                    "enabled": True,
                    "service": "slack",
                    "webhook_url": "https://hooks.slack.com/services/your/webhook/url",
                    "channel": "#security-alerts",
                    "username": "DDoS Defense Bot",
                    "icon": ":shield:",
                    "include_details": True
                },
                "discord": {
                    "enabled": False,
                    "service": "discord",
                    "webhook_url": "",
                    "username": "DDoS Defense Bot",
                    "include_details": True
                }
            },
            "alert_types": {
                "new_attack": {
                    "enabled": True,
                    "min_level": "warning"
                },
                "blocked_ip": {
                    "enabled": True,
                    "min_level": "info"
                },
                "distributed_attack": {
                    "enabled": True,
                    "min_level": "critical"
                },
                "honeypot_triggered": {
                    "enabled": True,
                    "min_level": "warning"
                },
                "rate_limit_exceeded": {
                    "enabled": True,
                    "min_level": "info" 
                }
            }
        }
        
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    self._deep_update(default_config, loaded_config)
            else:
                # Save default config
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, indent=2, fp=f)
        except Exception as e:
            print(f"Error loading notification configuration: {e}")
        
        return default_config
    
    def _deep_update(self, d: Dict, u: Dict) -> Dict:
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v
        return d
    
    def _setup_channels(self) -> Dict[str, NotificationChannel]:
        channels = {}
        
        if self.config["channels"]["email"]["enabled"]:
            channels["email"] = EmailNotifier(self.config["channels"]["email"])
        
        if self.config["channels"]["sms"]["enabled"]:
            channels["sms"] = SMSNotifier(self.config["channels"]["sms"])
        
        if self.config["channels"]["webhook"]["enabled"]:
            channels["webhook"] = WebhookNotifier(self.config["channels"]["webhook"])
        
        if self.config["channels"]["slack"]["enabled"]:
            channels["slack"] = SlackDiscordNotifier(self.config["channels"]["slack"])
        
        if self.config["channels"]["discord"]["enabled"]:
            channels["discord"] = SlackDiscordNotifier(self.config["channels"]["discord"])
        
        return channels
    
    def update_config(self, new_config: Dict) -> Dict:
        with self.lock:
            self._deep_update(self.config, new_config)
            
            self.channels = self._setup_channels()
            
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, indent=2, fp=f)
            except Exception as e:
                print(f"Error saving notification configuration: {e}")
            
            return self.config
    
    def send_alert(self, alert_type: str, message: str, severity: int, details: Dict) -> bool:
        with self.lock:
            if alert_type not in self.config["alert_types"] or not self.config["alert_types"][alert_type]["enabled"]:
                return False
            
            level = "info"
            if severity >= self.config["thresholds"]["critical"]:
                level = "critical"
            elif severity >= self.config["thresholds"]["warning"]:
                level = "warning"
            
            min_level = self.config["alert_types"][alert_type]["min_level"]
            if (min_level == "critical" and level != "critical") or \
               (min_level == "warning" and level == "info"):
                return False
            
            alert_key = f"{alert_type}:{details.get('ip', 'global')}"
            now = time.time()
            
            if alert_key in self.recent_alerts:
                cooldown = self.config["cooldown_periods"][level]
                last_alert_time = self.recent_alerts[alert_key]
                
                if now - last_alert_time < cooldown:
                    return False
            
            self.recent_alerts[alert_key] = now
            
            sent = False
            for channel_name, channel in self.channels.items():
                try:
                    success = channel.send_alert(message, level, details)
                    sent = sent or success
                except Exception as e:
                    print(f"Error sending alert through {channel_name}: {e}")
            
            return sent
    
    def get_config(self) -> Dict:
        """Get the current configuration."""
        return self.config

_notification_system_instance = None

def get_notification_system():
    global _notification_system_instance
    if _notification_system_instance is None:
        _notification_system_instance = NotificationSystem()
    return _notification_system_instance

def process_ddos_request(request_data: Dict, suspicion_level: int) -> Dict:
    response_system = get_response_system()
    notification_system = get_notification_system()
    
    response = response_system.process_request(request_data, suspicion_level)
    
    detector = get_detector()
    anomaly_result = detector.detect_anomaly(request_data)
    
    if anomaly_result["is_anomaly"] and suspicion_level < 3:
        ml_suspicion = int(min(5, 3 + (anomaly_result["anomaly_probability"] * 2)))
        
        if ml_suspicion > suspicion_level:
            notification_system.send_alert(
                "ml_detected_anomaly",
                f"ML model detected anomaly from IP {request_data.get('ip', 'unknown')}",
                ml_suspicion,
                {
                    "ip": request_data.get("ip", "unknown"),
                    "anomaly_probability": anomaly_result["anomaly_probability"],
                    "original_suspicion": suspicion_level,
                    "ml_suspicion": ml_suspicion,
                    "request_data": request_data
                }
            )
            
            suspicion_level = ml_suspicion
    
    if response["action"] == "block":
        notification_system.send_alert(
            "blocked_ip",
            f"IP {request_data.get('ip', 'unknown')} has been blocked",
            suspicion_level,
            {
                "ip": request_data.get("ip", "unknown"),
                "action": response,
                "request_data": request_data
            }
        )
    elif response["action"] == "captcha":
        notification_system.send_alert(
            "rate_limit_exceeded",
            f"CAPTCHA challenge issued to IP {request_data.get('ip', 'unknown')}",
            suspicion_level,
            {
                "ip": request_data.get("ip", "unknown"),
                "action": response,
                "request_data": request_data
            }
        )
    elif suspicion_level >= 3:
        notification_system.send_alert(
            "new_attack",
            f"Suspicious activity detected from IP {request_data.get('ip', 'unknown')}",
            suspicion_level,
            {
                "ip": request_data.get("ip", "unknown"),
                "suspicion_level": suspicion_level,
                "action": response,
                "request_data": request_data
            }
        )
    
    return response

def check_for_distributed_attack():
    response_system = get_response_system()
    notification_system = get_notification_system()
    detector = get_detector()
    
    recent_requests = []
    for action in response_system.actions:
        if action.action_type != "allow" and time.time() - action.timestamp < 3600:
            recent_requests.append({
                "ip": action.ip,
                "timestamp": action.timestamp,
                "severity": action.severity
            })
    
    if len(recent_requests) < 5:
        return
    
    clustering_result = detector.identify_attack_clusters(recent_requests)
    
    if clustering_result["num_clusters"] > 0:
        severity = 3
        largest_cluster_size = max([len(c["requests"]) for c in clustering_result["clusters"]], default=0)
        
        if largest_cluster_size > 20:
            severity = 5
        elif largest_cluster_size > 10:
            severity = 4
        
        notification_system.send_alert(
            "distributed_attack",
            f"Potential distributed attack detected: {clustering_result['num_clusters']} clusters found",
            severity,
            {
                "clustering_result": clustering_result,
                "largest_cluster_size": largest_cluster_size,
                "total_requests": clustering_result["total_requests"]
            }
        )

def cleanup_and_maintain():
    response_system = get_response_system()
    response_system.cleanup_expired()

def start_scheduled_tasks():
    import threading
    
    def run_periodic_tasks():
        while True:
            try:
                cleanup_and_maintain()
                check_for_distributed_attack()
                time.sleep(60)
            except Exception as e:
                print(f"Error in periodic tasks: {e}")
                time.sleep(30)
    
    task_thread = threading.Thread(target=run_periodic_tasks, daemon=True)
    task_thread.start()