import datetime
import os
import json

def log_phishing_attempt(email_data, detection_result, ip="127.0.0.1"):
    
    if not os.path.exists("logs"):
        os.makedirs("logs")
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = [
        f"Time: {timestamp}",
        f"IP: {ip}",
        f"From: {email_data.get('from', 'Unknown')}",
        f"Subject: {email_data.get('subject', 'Unknown')}",
        f"Is Phishing: {detection_result['is_phishing']}",
        f"Confidence: {detection_result['confidence']:.2f}",
    ]
    
    if detection_result['is_phishing']:
        log_entry.append(f"Phishing Type: {detection_result.get('type', 'Unknown')}")
        
        if 'indicators' in detection_result:
            indicators = [f"{ind['type']} ({ind['severity']})" for ind in detection_result['indicators']]
            log_entry.append(f"Indicators: {', '.join(indicators)}")
    
    log_entry = "\n".join(log_entry)
    
    with open("phishing_log.txt", "a") as f:
        f.write(log_entry)
        f.write("\n--------------------------------------\n")
    
    return log_entry

def get_phishing_logs(days=30, limit=1000):
    
    try:
        with open("phishing_log.txt", "r") as f:
            log_content = f.read()
    except FileNotFoundError:
        return []
    
    log_entries = log_content.split("--------------------------------------\n")
    
    parsed_logs = []
    current_time = datetime.datetime.now()
    cutoff_time = current_time - datetime.timedelta(days=days)
    
    for entry in log_entries:
        if not entry.strip():
            continue
        
        log_dict = {}
        for line in entry.strip().split("\n"):
            if line.startswith("Time: "):
                time_str = line.replace("Time: ", "")
                log_dict["timestamp"] = time_str
                try:
                    log_time = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    if log_time < cutoff_time:
                        break
                except ValueError:
                    pass
            elif line.startswith("IP: "):
                log_dict["ip"] = line.replace("IP: ", "")
            elif line.startswith("From: "):
                log_dict["from"] = line.replace("From: ", "")
            elif line.startswith("Subject: "):
                log_dict["subject"] = line.replace("Subject: ", "")
            elif line.startswith("Is Phishing: "):
                log_dict["is_phishing"] = line.replace("Is Phishing: ", "") == "True"
            elif line.startswith("Confidence: "):
                try:
                    log_dict["confidence"] = float(line.replace("Confidence: ", ""))
                except ValueError:
                    log_dict["confidence"] = 0.0
            elif line.startswith("Phishing Type: "):
                log_dict["phishing_type"] = line.replace("Phishing Type: ", "")
            elif line.startswith("Indicators: "):
                log_dict["indicators"] = line.replace("Indicators: ", "").split(", ")
        
        if "timestamp" in log_dict:
            parsed_logs.append(log_dict)
        
        if len(parsed_logs) >= limit:
            break
    
    return parsed_logs
