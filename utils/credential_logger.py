import datetime

def log_credential_attack(username, password, ip_address, user_agent, analysis):
    masked_password = "*" * len(password)
    
    log_entry = (
        f"Time: {datetime.datetime.now()}\n"
        f"IP Address: {ip_address}\n"
        f"User Agent: {user_agent}\n"
        f"Username: {username}\n"
        f"Password: {masked_password}\n"
        f"Risk Score: {analysis['risk_score']}\n"
        f"Attack Type: {analysis['attack_type']}\n"
        f"Common Pattern: {analysis['common_pattern']}\n"
        f"Password Strength: {analysis['password_strength']}\n"
        "--------------------------------------\n"
    )
    with open("credential_honeypot_log.txt", "a") as f:
        f.write(log_entry)