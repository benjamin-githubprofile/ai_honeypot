import datetime

def log_scraping_attempt(target, detection_result):
    log_entry = (
        f"Time: {datetime.datetime.now()}\n"
        f"Target: {target}\n"
        f"Is Bot: {detection_result['is_bot']}\n"
        f"Confidence: {detection_result['confidence']}\n"
        f"Patterns: {', '.join(detection_result['suspicious_patterns'])}\n"
        "--------------------------------------\n"
    )
    with open("scraping_log.txt", "a") as f:
        f.write(log_entry)