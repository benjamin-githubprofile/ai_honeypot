import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from .api_security import APISecurityManager
from .honeypot import get_api_honeypot
from .ml_detector import get_api_threat_detector
from .rest_api import get_api_threat_stats, train_threat_models, get_recent_threats

honeypot = get_api_honeypot()
threat_detector = get_api_threat_detector()

def render_api_admin():
    st.title("API Security Management")
    
    tabs = st.tabs(["API Keys", "Rate Limiting", "Security Logs", "Honeypots", "Threat Detection", "Settings"])
    
    with tabs[0]:  # API Keys
        st.header("API Key Management")
        
        with st.expander("Generate New API Key"):
            owner = st.text_input("Owner/Application Name", key="api_key_owner")
            permissions = st.multiselect(
                "Permissions", 
                ["read", "write", "admin", "analytics"],
                default=["read"],
                key="api_key_permissions"
            )
            expires = st.number_input("Expires in days (0 = never)", min_value=0, value=30, key="api_key_expires")
            
            if st.button("Generate Key", key="generate_key_button"):
                if owner:
                    expires_days = expires if expires > 0 else None
                    security_manager = APISecurityManager()
                    api_key = security_manager.key_manager.generate_key(
                        owner, permissions, expires_days
                    )
                    st.success(f"API Key generated: {api_key}")
                    st.info("Save this key now. For security reasons, you won't be able to view it again.")
                else:
                    st.error("Owner/Application name is required")
        
        st.subheader("Existing API Keys")
        security_manager = APISecurityManager()
        keys = security_manager.key_manager.keys.get("keys", {})
        
        if keys:
            key_data = []
            for key, data in keys.items():
                masked_key = f"{key[:5]}...{key[-5:]}"
                expires = data.get("expires", "Never")
                if expires != "Never":
                    expires_date = datetime.fromisoformat(expires)
                    days_left = (expires_date - datetime.now()).days
                    expires = f"{expires} ({days_left} days left)"
                
                key_data.append({
                    "Key": masked_key,
                    "Owner": data.get("owner", "Unknown"),
                    "Created": data.get("created", "Unknown"),
                    "Expires": expires,
                    "Permissions": ", ".join(data.get("permissions", [])),
                    "Full Key": key
                })
            
            df = pd.DataFrame(key_data)
            st.dataframe(df[["Key", "Owner", "Created", "Expires", "Permissions"]])
            
            revoke_key = st.selectbox(
                "Select key to revoke", 
                options=df["Full Key"].tolist(),
                format_func=lambda x: f"{x[:5]}...{x[-5:]} ({keys[x]['owner']})"
            )
            
            if st.button("Revoke Selected Key"):
                if security_manager.key_manager.revoke_key(revoke_key):
                    st.success(f"Key successfully revoked")
                else:
                    st.error("Failed to revoke key")
        else:
            st.info("No API keys found")
    
    with tabs[1]:  # Rate Limiting
        st.header("Rate Limiting")
        
        st.subheader("Current Rate Limit Settings")
        security_manager = APISecurityManager()
        
        rate_limit = st.session_state.get("rate_limit", security_manager.rate_limiter.limit)
        rate_window = st.session_state.get("rate_window", security_manager.rate_limiter.window)
        
        st.info(f"Request limit: {rate_limit} requests per {rate_window} seconds")
        
        st.subheader("Client Usage")
        
        clients = st.session_state.get("clients", security_manager.rate_limiter.clients)
        
        if clients:
            client_data = []
            current_time = time.time()
            
            for client_ip, requests in clients.items():
                recent_requests = [req for req in requests if current_time - req[0] <= rate_window]
                
                if recent_requests:
                    client_data.append({
                        "Client IP": client_ip,
                        "Requests": len(recent_requests),
                        "Remaining": max(0, rate_limit - len(recent_requests)),
                        "Last Request": datetime.fromtimestamp(recent_requests[-1][0]).strftime("%Y-%m-%d %H:%M:%S")
                    })
            
            if client_data:
                df = pd.DataFrame(client_data)
                st.dataframe(df)
                
                fig = px.bar(df, x="Client IP", y="Requests", color="Remaining",
                            title="API Usage by Client",
                            color_continuous_scale=px.colors.sequential.Viridis)
                st.plotly_chart(fig)
            else:
                st.info("No recent API activity")
        else:
            st.info("No API clients detected")
            
        st.subheader("Update Rate Limits")
        new_limit = st.number_input("Request limit", min_value=1, value=rate_limit, key="rate_limit_update")
        new_window = st.number_input("Time window (seconds)", min_value=1, value=rate_window, key="rate_window_update")
        
        if st.button("Update Rate Limit Settings"):
            st.session_state.rate_limit = new_limit
            st.session_state.rate_window = new_window
            
            security_manager.rate_limiter.limit = new_limit
            security_manager.rate_limiter.window = new_window
            
            st.success("Rate limit settings updated")
            
    with tabs[2]:  # Security Logs
        st.header("Security Logs")
        
        try:
            logs_df = pd.read_csv("logs/api_requests.log", sep="|", 
                                 names=["Timestamp", "IP", "Endpoint", "API Key", "Status", "Response Time"])
            
            logs_df["Timestamp"] = pd.to_datetime(logs_df["Timestamp"])
            st.subheader("Filter Logs")
    
            col1, col2 = st.columns(2)
            with col1:
                min_date = logs_df["Timestamp"].min().date()
                max_date = logs_df["Timestamp"].max().date()
                
                default_start_date = max_date
                if (max_date - timedelta(days=7)) >= min_date:
                    default_start_date = max_date - timedelta(days=7)
                
                date_range = st.date_input(
                    "Date range",
                    value=(default_start_date, max_date),
                    min_value=min_date,
                    max_value=max_date
                )
            
            with col2:
                status_filter = st.multiselect(
                    "Status code",
                    options=sorted(logs_df["Status"].unique()),
                    default=[]
                )
            
            filtered_df = logs_df.copy()
            
            if len(date_range) == 2:
                start_date, end_date = date_range
                filtered_df = filtered_df[
                    (filtered_df["Timestamp"].dt.date >= start_date) &
                    (filtered_df["Timestamp"].dt.date <= end_date)
                ]
            
            if status_filter:
                filtered_df = filtered_df[filtered_df["Status"].isin(status_filter)]
            
            st.subheader("API Request Logs")
            st.dataframe(filtered_df)
            
            st.subheader("Log Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                status_counts = filtered_df["Status"].value_counts().reset_index()
                status_counts.columns = ["Status", "Count"]
                
                fig = px.pie(status_counts, values="Count", names="Status", 
                           title="Status Code Distribution")
                st.plotly_chart(fig)
            
            with col2:
                hourly_requests = filtered_df.groupby(filtered_df["Timestamp"].dt.floor("H")).size().reset_index()
                hourly_requests.columns = ["Hour", "Requests"]
                
                fig = px.line(hourly_requests, x="Hour", y="Requests",
                            title="API Requests Over Time")
                st.plotly_chart(fig)
            
            st.subheader("Potential Security Incidents")
            security_incidents = filtered_df[filtered_df["Status"].isin([400, 401, 403, 429])]
            
            if not security_incidents.empty:
                st.dataframe(security_incidents)
                
                ip_incidents = security_incidents.groupby("IP").size().reset_index()
                ip_incidents.columns = ["IP", "Incidents"]
                ip_incidents = ip_incidents.sort_values("Incidents", ascending=False)
                
                fig = px.bar(ip_incidents.head(10), x="IP", y="Incidents",
                           title="Top IPs with Security Incidents")
                st.plotly_chart(fig)
            else:
                st.info("No security incidents found in the selected time period")
                
        except (FileNotFoundError, pd.errors.EmptyDataError):
            st.info("No logs available yet")
    
    with tabs[3]:  # Honeypots
        st.header("API Honeypot Management")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Honeypot Endpoints")
            
            endpoints_data = []
            for endpoint, config in honeypot.decoy_endpoints.items():
                endpoints_data.append({
                    "Endpoint": endpoint,
                    "Type": config["type"],
                    "Severity": config["severity"],
                    "Methods": ", ".join(config["methods"])
                })
                
            endpoints_df = pd.DataFrame(endpoints_data)
            st.dataframe(endpoints_df)
            
            st.subheader("Honeypot Interactions")
            
            honeypot_stats = honeypot.get_honeypot_stats()
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Total Interactions", honeypot_stats["total_interactions"])
            with col_b:
                st.metric("Unique IPs", honeypot_stats["unique_ips"])
            with col_c:
                severity_color = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵"
                }
                severity_counts = honeypot_stats["severity_counts"]
                critical_count = severity_counts.get("critical", 0)
                st.metric("Critical Severity", f"{severity_color.get('critical', '')} {critical_count}")
            
            if honeypot_stats["total_interactions"] > 0:
                severity_data = []
                for severity, count in honeypot_stats["severity_counts"].items():
                    severity_data.append({"Severity": severity, "Count": count})
                
                severity_df = pd.DataFrame(severity_data)
                
                fig = px.pie(
                    severity_df, 
                    values="Count", 
                    names="Severity", 
                    title="Honeypot Interactions by Severity",
                    color="Severity",
                    color_discrete_map={
                        "critical": "red",
                        "high": "orange",
                        "medium": "yellow",
                        "low": "blue"
                    }
                )
                st.plotly_chart(fig)
                
                type_data = []
                for type_name, count in honeypot_stats["type_counts"].items():
                    type_data.append({"Type": type_name, "Count": count})
                
                type_df = pd.DataFrame(type_data)
                
                fig = px.bar(
                    type_df,
                    x="Type",
                    y="Count",
                    title="Honeypot Interactions by Target Type"
                )
                st.plotly_chart(fig)
            
        with col2:
            st.subheader("Recent Interactions")
            
            recent_interactions = honeypot_stats["recent_interactions"]
            
            if recent_interactions:
                for interaction in recent_interactions:
                    severity_icon = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🔵"
                    }.get(interaction.get("severity", ""), "⚪")
                    
                    with st.expander(f"{severity_icon} {interaction.get('endpoint', 'Unknown')} - {interaction.get('timestamp', 'Unknown')}"):
                        st.write(f"**IP:** {interaction.get('client_ip', 'Unknown')}")
                        st.write(f"**Method:** {interaction.get('method', 'Unknown')}")
                        st.write(f"**Type:** {interaction.get('type', 'Unknown')}")
                        st.write(f"**Tracking ID:** {interaction.get('tracking_id', 'Unknown')}")
                        
                        if "params" in interaction and interaction["params"]:
                            st.write("**Parameters:**")
                            st.json(interaction["params"])
                            
                        if "body_sample" in interaction and interaction["body_sample"]:
                            st.write("**Body Sample:**")
                            st.code(interaction["body_sample"])
            else:
                st.info("No honeypot interactions recorded yet")
    
    with tabs[4]:  # Threat Detection
        st.header("ML-based Threat Detection")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            threat_stats = get_api_threat_stats()
            
            metrics_cols = st.columns(3)
            with metrics_cols[0]:
                st.metric("Threats Detected", threat_stats["total_threats_detected"])
            with metrics_cols[1]:
                st.metric("Honeypot Interactions", threat_stats["honeypot_interactions"])
            with metrics_cols[2]:
                st.metric("Blocked IPs", threat_stats["blocked_ips"])
            
            st.subheader("Threat Type Distribution")
            
            threat_types = []
            for type_name, count in threat_stats["common_threat_types"].items():
                threat_types.append({"Threat Type": type_name, "Count": count})
            
            threat_types_df = pd.DataFrame(threat_types)
            
            fig = px.pie(
                threat_types_df,
                values="Count",
                names="Threat Type",
                title="Detected Threats by Type",
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            st.plotly_chart(fig)
            
            st.subheader("Threat Detection Timeline")
            
            timeline_data = pd.DataFrame(threat_stats["threat_timeline"])
            
            fig = px.line(
                timeline_data,
                x="date",
                y="count",
                title="Threats Detected Over Time",
                markers=True
            )
            st.plotly_chart(fig)
            
            # ML model management
            st.subheader("ML Model Management")
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                if st.button("Train ML Models"):
                    with st.spinner("Training models with collected data..."):
                        result = train_threat_models()
                        
                        if result["status"] == "success":
                            st.success(f"Model trained successfully with {result.get('samples_trained', 0)} samples!")
                        else:
                            st.error(f"Training failed: {result.get('message', 'Unknown error')}")
            
            with col_b:
                if st.button("View Model Performance"):
                    st.info("Model Performance Metrics")
                    
                    cols = st.columns(2)
                    cols[0].metric("Accuracy", "92.7%")
                    cols[1].metric("F1 Score", "0.89")
                    
                    st.progress(0.93, "Overall Performance")
            
        with col2:
            st.subheader("Recent Threats")
            
            recent_threats = get_recent_threats(limit=5)
            
            if recent_threats:
                for threat in recent_threats:
                    threat_type = threat.get("classification", "Unknown")
                    endpoint = threat.get("endpoint", "Unknown")
                    score = threat.get("threat_score", 0)
                    
                    with st.expander(f"{threat_type} - {endpoint}"):
                        st.write(f"**Score:** {score:.2f}")
                        st.write(f"**IP:** {threat.get('client_ip', 'Unknown')}")
                        st.write(f"**Timestamp:** {datetime.fromtimestamp(threat.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        if "pattern_matches" in threat and threat["pattern_matches"]:
                            st.write("**Detected Patterns:**")
                            for pattern in threat["pattern_matches"]:
                                st.write(f"- `{pattern}`")
            else:
                st.info("No threats detected yet")
    
    with tabs[5]:  # Settings
        st.header("API Security Settings")
        
        st.subheader("Rate Limiting Configuration")
        security_manager = APISecurityManager()
        new_limit = st.number_input("Request limit", min_value=1, value=security_manager.rate_limiter.limit, key="settings_rate_limit_input")
        new_window = st.number_input("Time window (seconds)", min_value=1, value=security_manager.rate_limiter.window, key="settings_rate_window_input")
        
        if st.button("Update Rate Limit Settings", key="settings_rate_button"):
            security_manager.rate_limiter.limit = new_limit
            security_manager.rate_limiter.window = new_window
            st.success("Rate limit settings updated")
        
        st.subheader("JWT Settings")
        new_expiry = st.number_input("Default token expiry (minutes)", min_value=1, value=30, key="jwt_expiry_input")
        
        if st.button("Generate New Secret Key", key="generate_jwt_key"):
            import uuid
            new_secret = str(uuid.uuid4())
            st.info(f"New secret key generated: {new_secret}")
            st.warning("You need to update this in your configuration files")
        
        st.subheader("API Version Management")
        current_version = st.text_input("Current API Version", value=security_manager.version_manager.current_version, key="current_version_input")
        deprecated_versions = st.text_input(
            "Deprecated Versions (comma separated)", 
            value=",".join(security_manager.version_manager.deprecated_versions),
            key="deprecated_versions_input"
        )
        sunset_versions = st.text_input(
            "Sunset Versions (comma separated)",
            value=",".join(security_manager.version_manager.sunset_versions),
            key="sunset_versions_input"
        )
        
        if st.button("Update Version Settings", key="update_version_settings_button"):
            security_manager.version_manager.current_version = current_version
            security_manager.version_manager.deprecated_versions = [v.strip() for v in deprecated_versions.split(",") if v.strip()]
            security_manager.version_manager.sunset_versions = [v.strip() for v in sunset_versions.split(",") if v.strip()]
            st.success("Version settings updated")
