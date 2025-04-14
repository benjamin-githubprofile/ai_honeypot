import re
import random
import json
from datetime import datetime, timedelta

def get_dummy_database_schema():
    return {
        "users": {
            "description": "User account information",
            "columns": {
                "id": {"type": "INTEGER", "primary_key": True, "description": "Unique user ID"},
                "username": {"type": "VARCHAR(50)", "description": "User's login name"},
                "password": {"type": "VARCHAR(100)", "description": "Hashed password"},
                "email": {"type": "VARCHAR(100)", "description": "User's email address"},
                "created_at": {"type": "TIMESTAMP", "description": "Account creation time"},
                "is_admin": {"type": "BOOLEAN", "description": "Administrator flag"}
            },
            "sample_data": [
                {"id": 1, "username": "admin", "email": "admin@example.com", "created_at": "2023-01-01", "is_admin": True},
                {"id": 2, "username": "johndoe", "email": "john@example.com", "created_at": "2023-01-15", "is_admin": False},
                {"id": 3, "username": "janedoe", "email": "jane@example.com", "created_at": "2023-02-20", "is_admin": False}
            ]
        },
        "products": {
            "description": "Product catalog information",
            "columns": {
                "id": {"type": "INTEGER", "primary_key": True, "description": "Unique product ID"},
                "name": {"type": "VARCHAR(100)", "description": "Product name"},
                "description": {"type": "TEXT", "description": "Product description"},
                "price": {"type": "DECIMAL(10,2)", "description": "Product price"},
                "category_id": {"type": "INTEGER", "description": "Foreign key to categories table"},
                "stock": {"type": "INTEGER", "description": "Available stock quantity"}
            },
            "sample_data": [
                {"id": 1, "name": "Laptop", "price": 999.99, "category_id": 1, "stock": 50},
                {"id": 2, "name": "Smartphone", "price": 499.99, "category_id": 1, "stock": 100},
                {"id": 3, "name": "Headphones", "price": 99.99, "category_id": 2, "stock": 200}
            ]
        },
        "orders": {
            "description": "Customer order information",
            "columns": {
                "id": {"type": "INTEGER", "primary_key": True, "description": "Unique order ID"},
                "user_id": {"type": "INTEGER", "description": "Foreign key to users table"},
                "total_amount": {"type": "DECIMAL(10,2)", "description": "Total order amount"},
                "order_date": {"type": "TIMESTAMP", "description": "Date and time of order"},
                "status": {"type": "VARCHAR(20)", "description": "Order status (pending, shipped, etc.)"}
            },
            "sample_data": [
                {"id": 1, "user_id": 2, "total_amount": 1099.98, "order_date": "2023-03-10", "status": "completed"},
                {"id": 2, "user_id": 3, "total_amount": 499.99, "order_date": "2023-03-15", "status": "shipped"},
                {"id": 3, "user_id": 2, "total_amount": 99.99, "order_date": "2023-03-20", "status": "pending"}
            ]
        }
    }

def execute_query(query, prevent_damage=True):
    from sql_inject.detector import detect_injection
    
    detection_result = detect_injection(query)
    query_lower = query.lower().strip()
    
    schema = get_dummy_database_schema()
    
    if query_lower.startswith("select"):
        table_match = re.search(r"from\s+([a-zA-Z0-9_]+)", query_lower)
        if not table_match:
            return []
        
        table_name = table_match.group(1)
        if table_name not in schema:
            return f"Table '{table_name}' not found"
        
        result = schema[table_name].get("sample_data", []).copy()
        
        where_match = re.search(r"where\s+(.*?)(?:$|order\s+by|group\s+by|limit)", query_lower)
        if where_match:
            where_clause = where_match.group(1).strip()
            
            if "1=1" in where_clause or "'1'='1'" in where_clause:
                return result
            
            id_match = re.search(r"id\s*=\s*(\d+)", where_clause)
            if id_match and result:
                id_val = int(id_match.group(1))
                result = [r for r in result if r.get("id") == id_val]
        
        if "union" in query_lower and "select" in query_lower[query_lower.index("union"):]:
            if detection_result["is_injection"]:
                result.extend([
                    {"username": "admin", "password": "hashed_super_secret_pwd"},
                    {"username": "system", "password": "hashed_system_pwd"},
                    {"username": "apiuser", "password": "hashed_api_key"}
                ])
        
        return result
    
    elif query_lower.startswith("insert"):
        table_match = re.search(r"insert\s+into\s+([a-zA-Z0-9_]+)", query_lower)
        if not table_match:
            return "Invalid INSERT query"
        
        table_name = table_match.group(1)
        if table_name not in schema:
            return f"Table '{table_name}' not found"
        
        return f"INSERT successful: 1 row added to {table_name}"
    
    elif query_lower.startswith("update"):
        table_match = re.search(r"update\s+([a-zA-Z0-9_]+)", query_lower)
        if not table_match:
            return "Invalid UPDATE query"
        
        table_name = table_match.group(1)
        if table_name not in schema:
            return f"Table '{table_name}' not found"
        
        if "where" not in query_lower:
            return "UPDATE successful: All rows updated in table (WARNING: No WHERE clause)"
        else:
            return f"UPDATE successful: Rows updated in {table_name}"
    
    elif query_lower.startswith("delete"):
        table_match = re.search(r"delete\s+from\s+([a-zA-Z0-9_]+)", query_lower)
        if not table_match:
            return "Invalid DELETE query"
        
        table_name = table_match.group(1)
        if table_name not in schema:
            return f"Table '{table_name}' not found"
        
        if "where" not in query_lower:
            return "DELETE successful: All rows deleted from table (WARNING: No WHERE clause)"
        else:
            return f"DELETE successful: Rows deleted from {table_name}"
    
    elif "drop table" in query_lower:
        table_match = re.search(r"drop\s+table\s+([a-zA-Z0-9_]+)", query_lower)
        if table_match:
            table_name = table_match.group(1)
            return f"⚠️ Attempted to DROP TABLE {table_name} - This action would permanently delete the table"
    
    elif any(keyword in query_lower for keyword in ["truncate", "alter", "drop database"]):
        return "⚠️ Potentially destructive operation detected - Not executed in simulation mode"
    
    return "Query executed successfully"

def analyze_query_risk(query):
    risks = []
    query_lower = query.lower()
    
    if (query_lower.startswith("update") or query_lower.startswith("delete")) and "where" not in query_lower:
        risks.append({
            "level": "high",
            "type": "missing_where",
            "description": "Missing WHERE clause could affect all rows in the table"
        })
    
    if "select" in query_lower and "*" in query_lower:
        risks.append({
            "level": "medium", 
            "type": "select_all",
            "description": "Selecting all columns may expose sensitive data"
        })
    
    if "password" in query_lower or "passwords" in query_lower:
        risks.append({
            "level": "high",
            "type": "password_exposure",
            "description": "Query directly accesses password fields"
        })
    
    if "[user_input]" in query_lower:
        risks.append({
            "level": "high",
            "type": "unsanitized_input",
            "description": "Query appears to use unsanitized user input"
        })
    
    risk_level = "low"
    if any(risk["level"] == "high" for risk in risks):
        risk_level = "high"
    elif any(risk["level"] == "medium" for risk in risks):
        risk_level = "medium"
    
    return {
        "overall_risk": risk_level,
        "risks": risks
    }
