import random
import json
import os
import time
from datetime import datetime
import uuid
import ipaddress
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple

from phishing.email_simulation import get_email_templates, generate_custom_phishing_email
from phishing.detector import detect_phishing
from phishing.utils import extract_urls_from_email, get_email_risk_score
from phishing.logger import log_phishing_attempt

class AIHoneypot:
    def __init__(self, data_path="honeypot_data"):
        self.data_path = data_path
        self.interactions = []
        self.attackers = defaultdict(list)
        self.honeypot_emails = []
        self.company_profiles = self._load_company_profiles()
        self.ml_model_ready = False
        self._setup_storage()
        
    def _setup_storage(self):
        """Set up the necessary directories for data storage"""
        # Create the main data directory first
        if not os.path.exists(self.data_path):
            os.makedirs(self.data_path)
        
        # Then create subdirectories
        for subdir in ["interactions", "attackers", "models", "training_data"]:
            path = os.path.join(self.data_path, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def _load_company_profiles(self) -> List[Dict]:
        """Load or create fake company profiles for the honeypot"""
        # Ensure the data path exists first
        if not os.path.exists(self.data_path):
            os.makedirs(self.data_path)
        
        profiles_path = os.path.join(self.data_path, "company_profiles.json")
        
        if os.path.exists(profiles_path):
            try:
                with open(profiles_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Create default company profiles
        profiles = [
            {
                "name": "TechCore Innovations",
                "domain": "techcoreinnovations.com",
                "industry": "Technology",
                "employees": [
                    {"name": "Alex Johnson", "title": "CEO", "email": "alex.johnson@techcoreinnovations.com"},
                    {"name": "Sarah Chen", "title": "CTO", "email": "sarah.chen@techcoreinnovations.com"},
                    {"name": "David Miller", "title": "CFO", "email": "david.miller@techcoreinnovations.com"},
                    {"name": "Emma Williams", "title": "HR Director", "email": "emma.williams@techcoreinnovations.com"}
                ]
            },
            {
                "name": "Global Finance Partners",
                "domain": "globalfinancepartners.com",
                "industry": "Finance",
                "employees": [
                    {"name": "Michael Roberts", "title": "President", "email": "m.roberts@globalfinancepartners.com"},
                    {"name": "Jessica Lee", "title": "VP Finance", "email": "j.lee@globalfinancepartners.com"},
                    {"name": "Robert Taylor", "title": "Investment Director", "email": "r.taylor@globalfinancepartners.com"},
                    {"name": "Sophia Garcia", "title": "Senior Analyst", "email": "s.garcia@globalfinancepartners.com"}
                ]
            },
            {
                "name": "HealthPlus Medical",
                "domain": "healthplusmedical.com",
                "industry": "Healthcare",
                "employees": [
                    {"name": "Dr. James Wilson", "title": "Medical Director", "email": "jwilson@healthplusmedical.com"},
                    {"name": "Emily Brown", "title": "Head of Operations", "email": "ebrown@healthplusmedical.com"},
                    {"name": "Daniel Kim", "title": "IT Administrator", "email": "dkim@healthplusmedical.com"},
                    {"name": "Lisa Martinez", "title": "Patient Coordinator", "email": "lmartinez@healthplusmedical.com"}
                ]
            }
        ]
        
        # Save the profiles
        try:
            with open(profiles_path, 'w') as f:
                json.dump(profiles, f, indent=2)
        except Exception as e:
            print(f"Error saving company profiles: {e}")
            
        return profiles
    
    def generate_honeypot_emails(self, count=5):
        honeypot_emails = []
        
        for _ in range(count):
            company = random.choice(self.company_profiles)
            sender = random.choice(company["employees"])
            recipients = [emp for emp in company["employees"] if emp != sender]
            recipient = random.choice(recipients)
            
            email_scenarios = [
                {
                    "template": "Bank Security Alert",
                    "variables": {
                        "bank_domain": f"secure.{company['domain']}",
                        "bank_name": f"{company['name']} Financial",
                        "verification_link": f"https://banking.{company['domain']}/verify?session={uuid.uuid4()}"
                    }
                },
                {
                    "template": "Package Delivery Notification",
                    "variables": {
                        "delivery_company": f"{company['name']} Shipping",
                        "tracking_number": f"TRK{random.randint(10000, 99999)}",
                        "issue_reason": "address verification required",
                        "verification_link": f"https://delivery.{company['domain']}/track?id={uuid.uuid4()}",
                        "delivery_date": (datetime.now().strftime("%Y-%m-%d")),
                        "partial_address": "123 Main St..."
                    }
                },
                {
                    "template": "Social Media Alert",
                    "variables": {
                        "social_platform": f"{company['name']} Connect",
                        "device_type": random.choice(["Windows PC", "Mac", "iPhone", "Android"]),
                        "login_location": random.choice(["San Francisco, CA", "New York, NY", "London, UK", "Tokyo, Japan"]),
                        "login_time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "verification_link": f"https://connect.{company['domain']}/security?token={uuid.uuid4()}"
                    }
                }
            ]
            
            scenario = random.choice(email_scenarios)
            email_content = generate_custom_phishing_email(scenario["template"], scenario["variables"])
            
            if email_content:
                honeypot_email = {
                    "from": sender["email"],
                    "to": recipient["email"],
                    "subject": email_content["subject"],
                    "body": email_content["body"],
                    "company": company["name"],
                    "trap_id": str(uuid.uuid4()),
                    "created_at": datetime.now().isoformat(),
                    "scenario_type": scenario["template"],
                    "scenario_data": scenario["variables"]
                }
                
                honeypot_emails.append(honeypot_email)
                
        self.honeypot_emails.extend(honeypot_emails)
        self._save_honeypot_emails()
        
        return honeypot_emails
    
    def _save_honeypot_emails(self):
        """Save the current honeypot emails to disk"""
        try:
            emails_path = os.path.join(self.data_path, "honeypot_emails.json")
            with open(emails_path, 'w') as f:
                json.dump(self.honeypot_emails, f, indent=2)
        except Exception as e:
            print(f"Error saving honeypot emails: {e}")
    
    def record_interaction(self, trap_id, ip_address, interaction_type, interaction_data=None):
        """Record an interaction with a honeypot email"""
        if not interaction_data:
            interaction_data = {}
            
        interaction = {
            "trap_id": trap_id,
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "type": interaction_type,
            "data": interaction_data
        }
        
        self.interactions.append(interaction)
        self.attackers[ip_address].append(interaction)
        
        # Save the interaction
        try:
            # Ensure the interactions directory exists
            interactions_dir = os.path.join(self.data_path, "interactions")
            if not os.path.exists(interactions_dir):
                os.makedirs(interactions_dir)
            
            interaction_path = os.path.join(interactions_dir, f"{trap_id}_{int(time.time())}.json")
            with open(interaction_path, 'w') as f:
                json.dump(interaction, f, indent=2)
        except Exception as e:
            print(f"Error saving interaction: {e}")
        
        return interaction
    
    def analyze_attacker(self, ip_address):
        if ip_address not in self.attackers:
            return {"ip": ip_address, "threat_level": "unknown", "interactions": 0}
            
        interactions = self.attackers[ip_address]
        
        interaction_types = Counter([i["type"] for i in interactions])
        
        threat_level = "low"
        if len(interactions) > 5:
            threat_level = "medium"
        if len(interactions) > 10 or "credential_submission" in interaction_types:
            threat_level = "high"
        if len(interactions) > 20 or interaction_types.get("malware_download", 0) > 0:
            threat_level = "critical"
            
        patterns = []
        if interaction_types.get("link_click", 0) > 3:
            patterns.append("multiple_link_clicks")
        if interaction_types.get("credential_submission", 0) > 0:
            patterns.append("credential_harvesting")
        if interaction_types.get("file_download", 0) > 0:
            patterns.append("file_exfiltration")
            
        return {
            "ip": ip_address,
            "threat_level": threat_level,
            "interactions": len(interactions),
            "interaction_types": dict(interaction_types),
            "patterns": patterns,
            "first_seen": interactions[0]["timestamp"],
            "last_seen": interactions[-1]["timestamp"]
        }
    
    def get_attacker_profiles(self):
        return [self.analyze_attacker(ip) for ip in self.attackers.keys()]
    
    def simulate_attacker_behavior(self, scenario_count=3, interaction_count=10):
        if len(self.honeypot_emails) < scenario_count:
            self.generate_honeypot_emails(scenario_count)
            
        if not self.honeypot_emails:
            return []
            
        simulated_interactions = []
        
        attacker_ips = [
            str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
            for _ in range(min(scenario_count, len(self.honeypot_emails)))
        ]
        
        for i, ip in enumerate(attacker_ips):
            if i >= len(self.honeypot_emails):
                break
                
            honeypot_email = self.honeypot_emails[i]
            trap_id = honeypot_email["trap_id"]
            
            attacker_type = random.choice(["curious", "credential_harvester", "data_thief"])
            
            for _ in range(random.randint(1, interaction_count)):
                if attacker_type == "curious":
                    interaction_type = random.choice(["email_view", "link_click"])
                elif attacker_type == "credential_harvester":
                    interaction_type = random.choice(["email_view", "link_click", "credential_submission"])
                else:
                    interaction_type = random.choice(["email_view", "link_click", "file_download", "malware_download"])
                
                interaction_data = {
                    "user_agent": random.choice([
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
                    ]),
                    "referrer": random.choice([
                        "https://mail.google.com/",
                        "https://outlook.office.com/",
                        "https://mail.yahoo.com/",
                        ""
                    ])
                }
                
                if interaction_type == "credential_submission":
                    interaction_data["credential_type"] = random.choice(["login", "banking", "personal"])
                
                interaction = self.record_interaction(trap_id, ip, interaction_type, interaction_data)
                simulated_interactions.append(interaction)
                
                time.sleep(0.1)
        
        return simulated_interactions
    
    def train_ai_model(self):
        if not self.interactions:
            return {"status": "error", "message": "No interaction data available for training"}
            
        training_data = []
        
        for ip, ip_interactions in self.attackers.items():
            interaction_count = len(ip_interactions)
            interaction_types = Counter([i["type"] for i in ip_interactions])
            unique_traps = len(set([i["trap_id"] for i in ip_interactions]))
            
            threat_level = 0  # low
            if interaction_count > 5:
                threat_level = 1  # medium
            if interaction_count > 10 or interaction_types.get("credential_submission", 0) > 0:
                threat_level = 2  # high
            if interaction_count > 20 or interaction_types.get("malware_download", 0) > 0:
                threat_level = 3  # critical
                
            data_point = {
                "ip": ip,
                "interaction_count": interaction_count,
                "unique_traps": unique_traps,
                "link_clicks": interaction_types.get("link_click", 0),
                "email_views": interaction_types.get("email_view", 0),
                "credential_submissions": interaction_types.get("credential_submission", 0),
                "file_downloads": interaction_types.get("file_download", 0),
                "malware_downloads": interaction_types.get("malware_download", 0),
                "threat_level": threat_level
            }
            
            training_data.append(data_point)
            
        training_data_path = os.path.join(self.data_path, "training_data", f"training_data_{int(time.time())}.json")
        with open(training_data_path, 'w') as f:
            json.dump(training_data, f, indent=2)
            
        self.ml_model_ready = True
        
        return {
            "status": "success", 
            "message": f"Training data saved with {len(training_data)} examples",
            "data_points": len(training_data)
        }
    
    def predict_threat(self, ip_address=None, interaction_data=None):
        if not self.ml_model_ready:
            return {"status": "error", "message": "AI model has not been trained yet"}
            
        if ip_address and ip_address in self.attackers:
            return self.analyze_attacker(ip_address)
            
        if not interaction_data:
            return {"status": "error", "message": "No data provided for prediction"}
            
        threat_level = "low"
        threat_score = 0.1
        
        interaction_type = interaction_data.get("type", "")
        
        if interaction_type == "credential_submission":
            threat_level = "high"
            threat_score = 0.8
        elif interaction_type == "file_download":
            threat_level = "medium"
            threat_score = 0.6
        elif interaction_type == "malware_download":
            threat_level = "critical"
            threat_score = 0.95
        elif interaction_type == "link_click":
            threat_level = "low"
            threat_score = 0.3
            
        return {
            "status": "success",
            "threat_level": threat_level,
            "threat_score": threat_score,
            "confidence": 0.7,
            "ip": interaction_data.get("ip_address", "unknown")
        }
    
    def analyze_honeypot_effectiveness(self):
        if not self.honeypot_emails:
            return {"status": "error", "message": "No honeypot emails have been generated"}
            
        if not self.interactions:
            return {"status": "warning", "message": "No interactions have been recorded yet"}
            
        total_traps = len(self.honeypot_emails)
        traps_with_interactions = len(set([i["trap_id"] for i in self.interactions]))
        total_interactions = len(self.interactions)
        unique_attackers = len(self.attackers)
        
        interaction_types = Counter([i["type"] for i in self.interactions])
        
        effectiveness_score = (traps_with_interactions / total_traps) * 0.5
        if total_interactions > 0:
            effectiveness_score += min(total_interactions / (total_traps * 3), 0.5)
            
        trap_types = defaultdict(int)
        trap_interactions = defaultdict(int)
        
        for email in self.honeypot_emails:
            trap_types[email["scenario_type"]] += 1
            
        for interaction in self.interactions:
            trap_id = interaction["trap_id"]
            for email in self.honeypot_emails:
                if email["trap_id"] == trap_id:
                    trap_interactions[email["scenario_type"]] += 1
                    break
        
        trap_effectiveness = {}
        for trap_type, count in trap_types.items():
            interactions = trap_interactions.get(trap_type, 0)
            effectiveness = interactions / count if count > 0 else 0
            trap_effectiveness[trap_type] = {
                "count": count,
                "interactions": interactions,
                "effectiveness": effectiveness
            }
            
        return {
            "status": "success",
            "total_traps": total_traps,
            "traps_with_interactions": traps_with_interactions,
            "total_interactions": total_interactions,
            "unique_attackers": unique_attackers,
            "interaction_types": dict(interaction_types),
            "effectiveness_score": effectiveness_score,
            "trap_effectiveness": trap_effectiveness
        }

_honeypot = None

def get_ai_honeypot():
    global _honeypot
    if _honeypot is None:
        _honeypot = AIHoneypot()
    return _honeypot

def generate_honeypot_scenarios(count=5):
    honeypot = get_ai_honeypot()
    return honeypot.generate_honeypot_emails(count)

def record_honeypot_interaction(trap_id, ip_address, interaction_type, interaction_data=None):
    honeypot = get_ai_honeypot()
    return honeypot.record_interaction(trap_id, ip_address, interaction_type, interaction_data)

def simulate_attacker_interactions(scenario_count=3, interaction_count=10):
    honeypot = get_ai_honeypot()
    return honeypot.simulate_attacker_behavior(scenario_count, interaction_count)

def train_honeypot_ai():
    honeypot = get_ai_honeypot()
    return honeypot.train_ai_model()

def analyze_honeypot_data():
    honeypot = get_ai_honeypot()
    return honeypot.analyze_honeypot_effectiveness()