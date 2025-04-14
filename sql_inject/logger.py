import datetime
import os

def log_sql_injection(query, detection_result, ip="127.0.0.1"):
    if not os.path.exists("logs"):
        os.makedirs("logs")
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = [
        f"Time: {timestamp}",
        f"IP: {ip}",
        f"Query: {query}",
        f"Is Injection: {detection_result['is_injection']}",
        f"Injection Type: {detection_result['type'] if detection_result['type'] else 'None'}",
        f"Confidence: {detection_result['confidence']}"
    ]
    
    if detection_result['is_injection'] and 'matched_patterns' in detection_result:
        log_entry.append(f"Matched Patterns: {', '.join(detection_result['matched_patterns'])}")
    
    log_entry = "\n".join(log_entry)
    
    with open("sql_injection_log.txt", "a") as f:
        f.write(log_entry)
        f.write("\n--------------------------------------\n")
    
    return log_entry

def get_injection_logs(days=30, limit=1000):
    try:
        with open("sql_injection_log.txt", "r") as f:
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
            elif line.startswith("Query: "):
                log_dict["query"] = line.replace("Query: ", "")
            elif line.startswith("Is Injection: "):
                log_dict["is_injection"] = line.replace("Is Injection: ", "") == "True"
            elif line.startswith("Injection Type: "):
                log_dict["injection_type"] = line.replace("Injection Type: ", "")
            elif line.startswith("Confidence: "):
                try:
                    log_dict["confidence"] = float(line.replace("Confidence: ", ""))
                except ValueError:
                    log_dict["confidence"] = 0.0
            elif line.startswith("Matched Patterns: "):
                log_dict["patterns"] = line.replace("Matched Patterns: ", "").split(", ")
        
        if "timestamp" in log_dict:
            parsed_logs.append(log_dict)
        
        if len(parsed_logs) >= limit:
            break
    
    return parsed_logs
