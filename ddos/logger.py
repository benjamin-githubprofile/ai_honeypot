import json
import datetime
from typing import Dict, List, Optional
from pathlib import Path

def log_ddos_attack(
    ip: str, 
    request_data: Dict, 
    attack_signature: Dict, 
    geo_data: Optional[Dict] = None
) -> None:
    log_dir = Path("ddos_logs")
    log_dir.mkdir(exist_ok=True)
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    log_file = log_dir / f"ddos_log_{today}.jsonl"
    
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": ip,
        "request_data": request_data,
        "attack_signature": attack_signature
    }
    
    if geo_data:
        log_entry["geo_data"] = geo_data
    
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    summary_log = log_dir / "ddos_summary.jsonl"
    summary_entry = {
        "timestamp": log_entry["timestamp"],
        "ip": ip,
        "attack_type": attack_signature.get("pattern_type", "UNKNOWN"),
        "confidence": attack_signature.get("confidence", 0),
        "country": geo_data.get("country", "Unknown") if geo_data else "Unknown"
    }
    
    with open(summary_log, "a") as f:
        f.write(json.dumps(summary_entry) + "\n")

def get_attack_logs(days: int = 7, limit: int = 100) -> List[Dict]:
    log_dir = Path("ddos_logs")
    if not log_dir.exists():
        return []
    
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days)
    
    log_files = []
    for day_offset in range(days):
        date = end_date - datetime.timedelta(days=day_offset)
        date_str = date.strftime("%Y-%m-%d")
        log_file = log_dir / f"ddos_log_{date_str}.jsonl"
        if log_file.exists():
            log_files.append(log_file)
    
    logs = []
    for log_file in log_files:
        with open(log_file, "r") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except json.JSONDecodeError:
                    continue
    
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return logs[:limit]