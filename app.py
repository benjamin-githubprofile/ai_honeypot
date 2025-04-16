import streamlit as st
print("🔥 app.py is running")
st.write("👋 Hello from AI Honeypot!")
from models.text_classifier import load_classifier
from text_attack.text_attack import generate_adversarial
from models.style_transfer import load_style_transfer_model, apply_style_transfer
from utils.logger import log_attack
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit.components.v1 as components
from datetime import datetime, timedelta
import json
from streamlit.errors import StreamlitAPIException
import plotly.utils as pu
import random
import time
import uuid
from web_scraping.honeypots import get_dummy_financial_data, get_dummy_customer_data, get_dummy_api_keys
from web_scraping.logger import log_scraping_attempt
from web_scraping.utils import evaluate_scraper_effectiveness, display_attack_results
from phishing.email_simulation import get_sample_emails, get_email_templates
from phishing.detector import detect_phishing, get_phishing_detector
from phishing.logger import log_phishing_attempt
from phishing.url_analyzer import analyze_url
from phishing.utils import render_email, extract_urls_from_email

from ddos import (
    RateLimiter, 
    IPGeolocation, 
    analyze_request_pattern, 
    simulate_ddos_attack, 
    log_ddos_attack, 
    get_attack_logs
)
from models.ddos_detector import get_detector
from sql_inject.sql_attack import simulate_sql_injection
from sql_inject.detector import detect_injection, get_sql_detector
from sql_inject.logger import log_sql_injection
from sql_inject.utils import get_dummy_database_schema, execute_query
from xss.xss_attack import simulate_xss_attack, get_common_xss_patterns
from xss.detector import detect_xss, get_xss_detector
from xss.logger import log_xss_attempt
from xss.utils import render_web_context, simulate_web_impact, sanitize_html
from api_security.admin_dashboard import render_api_admin
from phishing.ai_honeypot import (
    get_ai_honeypot, generate_honeypot_scenarios, record_honeypot_interaction,
    simulate_attacker_interactions, train_honeypot_ai, analyze_honeypot_data
)

def plotly_chart_with_clicks(fig, use_container_width=True):
    div_id = f"plotly-chart-{id(fig)}"
    
    config = {"displayModeBar": True, "responsive": True}
    
    figure_json = pu.PlotlyJSONEncoder().encode(fig.to_dict())
    
    fig_html = f"""
    <div id="{div_id}" class="plotly-chart-container"></div>
    <script>
        var figure = {figure_json};
        var config = {json.dumps(config)};
        
        // Create the chart
        Plotly.newPlot("{div_id}", figure.data, figure.layout, config);
        
        // Add click event listener
        document.getElementById("{div_id}").on("plotly_click", function(data) {{
            // Send the clicked data to Streamlit
            var clicked_data = JSON.stringify(data);
            window.parent.postMessage({{
                type: "streamlit:setComponentValue",
                value: clicked_data
            }}, "*");
        }});
    </script>
    """
    
    try:
        clicked_data = components.html(
            fig_html,
            height=500,
            width=None if use_container_width else 700
        )
        
        if clicked_data:
            return json.loads(clicked_data)
        return None
    except (StreamlitAPIException, TypeError):
        st.plotly_chart(fig, use_container_width=use_container_width)
        return None

classifier = load_classifier()

style_model, style_tokenizer = load_style_transfer_model()

def format_prediction(prediction):
    if prediction:
        pred = prediction[0]
        label = pred["label"]
        score = pred["score"]
        formatted_score = f"{score:.3f}"
        if label.upper() == "POSITIVE":
            return f"<strong style='color: green; font-size:18px;'>Positive: {formatted_score}</strong>"
        elif label.upper() == "NEGATIVE":
            return f"<strong style='color: red; font-size:18px;'>Negative: {formatted_score}</strong>"
        else:
            return f"<span style='font-size:18px;'>{label}: {formatted_score}</span>"
    else:
        return "No prediction available"

attack_tab, credential_tab, scraping_tab, ddos_tab, sql_tab, xss_tab, phishing_tab, api_tab, analysis_tab = st.tabs(
    ["Text Attack", "Credential Stuffing", "Web Scraping", "DDoS Attack", "SQL Injection", "XSS Attack", "Phishing Attack", "API Security", "Analysis"]
)

with attack_tab:
    st.title("Attack Simulation")
    st.write("Enter text and simulate an adversarial attack on the decoy text classifier.")
    
    input_text = st.text_area("Input Text:")
    
    attack_option = st.selectbox("Choose Attack Type", ["TextFooler", "DeepWordBug", "Negative Model"])
    
    if st.button("Simulate Attack"):
        if input_text:
            if attack_option == "Negative Model" or attack_option == "StyleTransfer(Self-Trained Model(100% Negative))":
                adversarial_text = apply_style_transfer(input_text, model=style_model, tokenizer=style_tokenizer)
            else:
                adversarial_text = generate_adversarial(input_text, attack_type=attack_option)
            
            st.subheader("Results")
            st.write("**Original Text:**", input_text)
            st.write("**Adversarial Text:**", adversarial_text)
            
            original_prediction = classifier(input_text)
            adversarial_prediction = classifier(adversarial_text)
            
            original_pred_formatted = format_prediction(original_prediction)
            adversarial_pred_formatted = format_prediction(adversarial_prediction)
            
            st.write("**Original Prediction:**")
            st.markdown(original_pred_formatted, unsafe_allow_html=True)
            st.write("**Adversarial Prediction:**")
            st.markdown(adversarial_pred_formatted, unsafe_allow_html=True)
            
            log_attack(input_text, adversarial_text, original_prediction, adversarial_prediction)
        else:
            st.error("Please enter some text before simulating an attack.")

with credential_tab:
    st.title("Credential Stuffing Honeypot")
    st.write("This simulates a login form that tracks attempted credential stuffing attacks.")
    
    if "credential_analysis" not in st.session_state:
        st.session_state.credential_analysis = None
    
    with st.form("login_form"):
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")
        
        ip_address = st.session_state.get("ip_address", "127.0.0.1")
        user_agent = st.session_state.get("user_agent", "Unknown")
        
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if username and password:
                from text_attack.credential_attack import analyze_login_attempt
                from utils.credential_logger import log_credential_attack
                
                analysis = analyze_login_attempt(username, password)
                
                st.session_state.credential_analysis = analysis
                
                log_credential_attack(username, password, ip_address, user_agent, analysis)
                
                st.error("Invalid username or password.")
            else:
                st.warning("Please enter both username and password.")
    
    if st.checkbox("Show Analysis (Admin Only)", value=False):
        if st.session_state.credential_analysis:
            st.json(st.session_state.credential_analysis)
        else:
            st.info("No analysis available. Submit a login attempt first.")

    st.write("---")
    st.subheader("Machine Learning Model")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Update ML Model"):
            from text_attack.credential_attack import update_credential_model
            success, message = update_credential_model()
            if success:
                st.success(message)
            else:
                st.warning(message)
    
    with col2:
        if st.button("Show Statistics"):
            from text_attack.credential_attack import get_credential_statistics
            stats = get_credential_statistics()
            st.write("### Credential Attack Statistics")
            st.metric("Total Attempts", stats["total_attempts"])
            st.metric("Unique Usernames", stats["unique_usernames"])
            st.metric("High Risk Attempts", stats["high_risk_attempts"])
            st.write("**Most Common Usernames:**")
            for username, count in stats["most_common_usernames"]:
                st.write(f"- {username}: {count} attempts")
            st.write(f"**Last Model Update:** {stats['latest_update']}")

with scraping_tab:
    st.title("Web Scraping Honeypot")
    st.write("This page simulates a data-rich environment to detect and analyze web scraping attempts.")
    
    st.subheader("Company Directory")
    
    st.write("To help us improve your experience, we collect some anonymous interaction data.")
    
    if "showing_financial_data" not in st.session_state:
        st.session_state.showing_financial_data = False
    if "showing_customer_data" not in st.session_state:
        st.session_state.showing_customer_data = False
    if "showing_api_keys" not in st.session_state:
        st.session_state.showing_api_keys = False
    if "financial_month" not in st.session_state:
        st.session_state.financial_month = None
    if "scrape_success" not in st.session_state:
        st.session_state.scrape_success = False
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("View Financial Data"):
            st.session_state.scrape_success = False
            
            st.session_state.showing_financial_data = True
            st.session_state.showing_customer_data = False
            st.session_state.showing_api_keys = False
            
            from models.bot_detector import load_bot_detector
            bot_detector = load_bot_detector()
            
            log_scraping_attempt("financial_data", bot_detector(st.session_state))
            
    with col2:
        if st.button("Download Customer List"):
            st.session_state.scrape_success = False
            
            st.session_state.showing_financial_data = False
            st.session_state.showing_customer_data = True
            st.session_state.showing_api_keys = False
            
            from models.bot_detector import load_bot_detector
            bot_detector = load_bot_detector()
            
            log_scraping_attempt("customer_list", bot_detector(st.session_state))
            
    with col3:
        if st.button("Access API Keys"):
            st.session_state.scrape_success = False
            
            st.session_state.showing_financial_data = False
            st.session_state.showing_customer_data = False
            st.session_state.showing_api_keys = True
            
            from models.bot_detector import load_bot_detector
            bot_detector = load_bot_detector()
            
            log_scraping_attempt("api_keys", bot_detector(st.session_state))
    
    if st.session_state.showing_financial_data:
        if not st.session_state.scrape_success:
            st.subheader("Company Financial Data")
            
            month = st.selectbox("Select Month", ["January", "February"])
            st.session_state.financial_month = month
            
            st.write(f"### {month} 2023 Financial Report")
            financial_data = get_dummy_financial_data()[month]
            
            df = pd.DataFrame(financial_data)
            st.dataframe(df, use_container_width=True)
            
            fig = px.bar(
                df, 
                x="Date", 
                y=["Revenue", "Expenses", "Profit"],
                title=f"{month} 2023 Financial Performance",
                barmode="group"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.subheader("Scraped Financial Data")
            st.success("🤖 Successfully scraped financial data!")
            
            month = st.session_state.financial_month or "January"
            financial_data = get_dummy_financial_data()[month]
            
            st.code(json.dumps(financial_data, indent=2), language="json")
    
    elif st.session_state.showing_customer_data:
        if not st.session_state.scrape_success:
            st.subheader("Customer List")
            
            customer_data = get_dummy_customer_data()
            
            df = pd.DataFrame(customer_data)
            st.dataframe(df, use_container_width=True)
            
            fig = px.pie(
                df,
                values=[int(val.replace("$", "").replace(",", "")) for val in df["Value"]],
                names="Name",
                title="Customer Value Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.subheader("Scraped Customer Data")
            st.success("🤖 Successfully scraped customer data!")
            
            customer_data = get_dummy_customer_data()
            
            st.code(json.dumps(customer_data, indent=2), language="json")
    
    elif st.session_state.showing_api_keys:
        if not st.session_state.scrape_success:
            st.subheader("API Keys")
            
            api_data = get_dummy_api_keys()
            
            df = pd.DataFrame(api_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.subheader("Scraped API Keys")
            st.success("🤖 Successfully scraped API keys!")
            
            api_data = get_dummy_api_keys()
            
            st.code(json.dumps(api_data, indent=2), language="json")
    
    st.markdown("---")
    
    st.subheader("AI Bot Detection")

    if "show_custom_form" not in st.session_state:
        st.session_state.show_custom_form = False

    if "custom_attack_result" not in st.session_state:
        st.session_state.custom_attack_result = None

    if st.button("Custom Attack Configuration", use_container_width=True):
        st.session_state.show_custom_form = True

    if st.session_state.show_custom_form:
        st.subheader("Configure Custom Bot Attack")
        
        with st.form("custom_attack_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("### HTTP Headers Configuration")
                
                user_agent_option = st.selectbox(
                    "User-Agent",
                    [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Chrome/91.0.4472.124)",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
                        "Python-requests/2.26.0",
                        "Googlebot/2.1 (+http://www.google.com/bot.html)",
                        "Custom/Minimal-Agent"
                    ]
                )
                
                accept_header = st.selectbox(
                    "Accept Header",
                    ["*/*", "text/html", "application/json", "text/html,application/json,image/*", "None"]
                )
                
                referrer = st.selectbox(
                    "Referrer",
                    ["https://www.google.com", "https://www.bing.com", "Direct (No Referrer)", "Internal Page"]
                )
                
                target_resource = st.selectbox(
                    "Target Resource to Scrape",
                    ["Financial Data", "Customer List", "API Keys"]
                )
            
            with col2:
                st.write("### Behavior Configuration")
                
                mouse_movement = st.radio(
                    "Mouse Movement Pattern",
                    ["None", "Minimal (1-5 movements)", "Linear/Predictable", "Natural Human"]
                )
                
                interaction_speed = st.slider(
                    "Interaction Speed (clicks per second)",
                    min_value=0.1, max_value=20.0, value=5.0, step=0.1
                )
                
                page_time = st.slider(
                    "Time on Page (seconds)",
                    min_value=0.1, max_value=300.0, value=5.0, step=0.1
                )
                
                access_pattern = st.radio(
                    "Resource Access Pattern",
                    ["Direct Resource Access", "Normal Navigation", "Random Navigation"]
                )
            
            submitted = st.form_submit_button("Test Attack", use_container_width=True)
            
            if submitted:
                from models.bot_detector import load_bot_detector
                bot_detector = load_bot_detector()
                
                features = {
                    "movement_count": {
                        "None": 0,
                        "Minimal (1-5 movements)": random.randint(1, 5),
                        "Linear/Predictable": random.randint(20, 30),
                        "Natural Human": random.randint(50, 200)
                    }[mouse_movement],
                    
                    "click_count": int(interaction_speed * page_time),
                    
                    "time_on_page": page_time,
                    
                    "request_pattern": {
                        "Direct Resource Access": "direct", 
                        "Normal Navigation": "normal",
                        "Random Navigation": "random"
                    }[access_pattern],
                    
                    "headers": {
                        "user-agent": user_agent_option,
                        "accept": None if accept_header == "None" else accept_header,
                        "referer": None if referrer == "Direct (No Referrer)" else referrer
                    }
                }
                
                if "Python" in user_agent_option or "bot" in user_agent_option.lower() or "Custom" in user_agent_option:
                    features["suspicious_user_agent"] = True
                
                if accept_header == "None" or accept_header == "*/*":
                    features["suspicious_accept"] = True
                
                if referrer == "Direct (No Referrer)":
                    features["no_referrer"] = True
                
                is_effective_scraper = evaluate_scraper_effectiveness(features)
                
                result = bot_detector(features)
                
                target_map = {
                    "Financial Data": "financial_data",
                    "Customer List": "customer_list",
                    "API Keys": "api_keys"
                }
                
                target = target_map[target_resource]
                
                st.session_state.custom_attack_result = {
                    "result": result,
                    "features": features,
                    "target": target,
                    "is_effective_scraper": is_effective_scraper
                }
                
                st.session_state.scrape_success = (not result["is_bot"]) or (is_effective_scraper and result["confidence"] < 0.6)
                
                st.session_state.showing_financial_data = (target == "financial_data")
                st.session_state.showing_customer_data = (target == "customer_list")
                st.session_state.showing_api_keys = (target == "api_keys")
                
                if target == "financial_data":
                    st.session_state.financial_month = "January"  # Default
                
                log_scraping_attempt(f"custom_attack_{target}", result)
        
        if st.session_state.custom_attack_result:
            display_attack_results(st.session_state.custom_attack_result, st)

            st.markdown("---")
            
            if st.session_state.scrape_success:
                target = st.session_state.custom_attack_result["target"]
                
                if target == "financial_data":
                    st.subheader("Scraped Financial Data")
                    st.success("🤖 Successfully scraped financial data!")
                    month = st.session_state.financial_month or "January"
                    financial_data = get_dummy_financial_data()[month]
                    st.code(json.dumps(financial_data, indent=2), language="json")
                    
                elif target == "customer_list":
                    st.subheader("Scraped Customer Data")
                    st.success("🤖 Successfully scraped customer data!")
                    customer_data = get_dummy_customer_data()
                    st.code(json.dumps(customer_data, indent=2), language="json")
                    
                elif target == "api_keys":
                    st.subheader("Scraped API Keys")
                    st.success("🤖 Successfully scraped API keys!")
                    api_data = get_dummy_api_keys()
                    st.code(json.dumps(api_data, indent=2), language="json")
                    
            else:
                st.error("🚫 ACCESS BLOCKED! Your scraping attempt was detected.")
                st.warning("Try adjusting your configuration to appear more human-like.")
                
                st.info("""
                **Tips to avoid detection:**
                1. Use a legitimate browser user agent
                2. Include proper Accept and Referrer headers
                3. Add reasonable mouse movements
                4. Use normal navigation patterns instead of direct access
                5. Increase page view time to appear more human-like
                """)

with ddos_tab:
    st.title("DDoS Attack Simulation")
    st.write("This tab simulates and detects Distributed Denial of Service (DDoS) attacks.")
    
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter(window_size=60, threshold=30)
    
    if "ip_geolocation" not in st.session_state:
        st.session_state.ip_geolocation = IPGeolocation()
    
    detector = get_detector()
    
    ddos_sim_tab, ml_insights_tab, config_tab = st.tabs(["Simulation", "ML Insights", "Configuration"])
    
    with ddos_sim_tab:
        st.subheader("Attack Simulation")
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        with st.form("ddos_simulation_form"):
            attack_type = st.selectbox(
                "Attack Type",
                options=["HTTP_FLOOD", "SLOW_LORIS", "TCP_SYN_FLOOD", "UDP_FLOOD"]
            )
            
            intensity = st.slider(
                "Attack Intensity",
                min_value=1,
                max_value=10,
                value=5,
                help="Higher intensity means more aggressive attack patterns"
            )
            
            num_sources = st.slider(
                "Number of Source IPs",
                min_value=1,
                max_value=100,
                value=10,
                help="Number of different IP addresses to simulate in the attack"
            )
            
            target = st.selectbox(
                "Target Resource",
                options=[
                    "Main Page", 
                    "API Endpoint", 
                    "Login Page", 
                    "Search Function",
                    "/api/internal/config", # Honeytoken
                    "/admin/settings" # Honeytoken
                ]
            )
            
            simulate_button = st.form_submit_button("Simulate Attack")
        
        if simulate_button:
            st.session_state.attack_results = []
            st.session_state.attack_timestamp = datetime.now().isoformat()
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            ips = [f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(num_sources)]
            
            requests_per_ip = intensity * 5
            
            blocked_ips = set()
            
            total_requests = num_sources * requests_per_ip
            request_count = 0
            
            geo_locations = [
                {"country": "United States", "country_code": "US", "city": "New York", "latitude": 40.7128, "longitude": -74.0060},
                {"country": "United States", "country_code": "US", "city": "San Francisco", "latitude": 37.7749, "longitude": -122.4194},
                {"country": "United States", "country_code": "US", "city": "Chicago", "latitude": 41.8781, "longitude": -87.6298},
                {"country": "China", "country_code": "CN", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074},
                {"country": "China", "country_code": "CN", "city": "Shanghai", "latitude": 31.2304, "longitude": 121.4737},
                {"country": "Russia", "country_code": "RU", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173},
                {"country": "Russia", "country_code": "RU", "city": "Saint Petersburg", "latitude": 59.9343, "longitude": 30.3351},
                {"country": "Germany", "country_code": "DE", "city": "Berlin", "latitude": 52.5200, "longitude": 13.4050},
                {"country": "Germany", "country_code": "DE", "city": "Munich", "latitude": 48.1351, "longitude": 11.5820},
                {"country": "Brazil", "country_code": "BR", "city": "São Paulo", "latitude": -23.5505, "longitude": -46.6333},
                {"country": "Brazil", "country_code": "BR", "city": "Rio de Janeiro", "latitude": -22.9068, "longitude": -43.1729},
                {"country": "India", "country_code": "IN", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777},
                {"country": "India", "country_code": "IN", "city": "New Delhi", "latitude": 28.6139, "longitude": 77.2090},
                {"country": "United Kingdom", "country_code": "GB", "city": "London", "latitude": 51.5074, "longitude": -0.1278},
                {"country": "Australia", "country_code": "AU", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093},
                {"country": "Japan", "country_code": "JP", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
                {"country": "Canada", "country_code": "CA", "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832},
                {"country": "France", "country_code": "FR", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522},
                {"country": "South Korea", "country_code": "KR", "city": "Seoul", "latitude": 37.5665, "longitude": 126.9780},
                {"country": "Italy", "country_code": "IT", "city": "Rome", "latitude": 41.9028, "longitude": 12.4964}
            ]
            
            for i, ip in enumerate(ips):
                progress = i / len(ips)
                progress_bar.progress(progress)
                status_text.text(f"Simulating attack from IP {ip}... ({i+1}/{len(ips)})")
                
                # Get base attack simulation
                attack_sim = simulate_ddos_attack(attack_type, intensity)
                request_frequency = attack_sim["characteristics"].get("requests_per_second", 10)
                
                for req in range(requests_per_ip):
                    request_count += 1
                    progress = request_count / total_requests
                    progress_bar.progress(progress)
                    
                    request_data = {
                        "ip": ip,
                        "target": target,
                        "request_frequency": request_frequency,
                        "connection_time": 30 if attack_type == "SLOW_LORIS" else 1,
                        "completed": attack_type != "SLOW_LORIS",
                        "headers": {
                            "User-Agent": "Mozilla/5.0" if random.random() > 0.3 else "Python-requests/2.25.1",
                            "Accept": "*/*",
                            "Connection": "keep-alive" if attack_type == "SLOW_LORIS" else "close"
                        }
                    }
                    
                    is_honeytoken = "/api/internal" in target or "/admin/" in target
                    
                    attack_signature = analyze_request_pattern(request_data)
                    
                    allowed, status = st.session_state.rate_limiter.record_request(ip)
                    
                    # Keep track if this IP gets blocked
                    if not allowed:
                        blocked_ips.add(ip)
                    
                    if req == 0:
                        geo_data = random.choice(geo_locations).copy()
                        geo_data["ip"] = ip
                        geo_data["is_private"] = True  # Since we're using private IPs for simulation
                        
                        st.session_state.attack_results.append({
                            "ip": ip,
                            "attack_type": attack_type,
                            "target": target,
                            "allowed": allowed,
                            "blocked": not allowed or ip in blocked_ips,
                            "suspicion_level": status["suspicion_level"],
                            "request_count": status["request_count"],
                            "threshold_percentage": status["threshold_percentage"],
                            "attack_confidence": attack_signature.confidence,
                            "timestamp": time.time(),
                            "geo_data": geo_data,
                            "is_honeytoken": is_honeytoken,
                            "total_requests": requests_per_ip
                        })
                    
                    time.sleep(0.01)
            
            for i, result in enumerate(st.session_state.attack_results):
                if result["ip"] in blocked_ips:
                    st.session_state.attack_results[i]["blocked"] = True
            
            progress_bar.empty()
            status_text.empty()
            
            # Show success message with blocking stats
            blocked_count = len(blocked_ips)
            blocking_rate = (blocked_count / len(ips)) * 100
            st.success(f"Successfully simulated {attack_type} attack with {num_sources} sources! {blocked_count} IPs were blocked ({blocking_rate:.1f}%).")
    
            # Add ML model analysis of the simulation
            st.markdown("---")
            st.subheader("Machine Learning Analysis")
            
            with st.spinner("Analyzing attack patterns with ML..."):
                suspicious_ips = [r["ip"] for r in st.session_state.attack_results if r["suspicion_level"] >= 2]
                
                if suspicious_ips:
                    st.write(f"ML model analyzed {len(suspicious_ips)} suspicious IPs")
                    
                    clustering_result = detector.identify_attack_clusters(
                        [r for r in st.session_state.attack_results if r["suspicion_level"] >= 2]
                    )
                    
                    if clustering_result["num_clusters"] > 0:
                        st.warning(f"**Potential Coordinated Attack Detected**: {clustering_result['num_clusters']} distinct attack patterns identified")
                        
                        cluster_data = []
                        for cluster in clustering_result["clusters"]:
                            for req in cluster["requests"]:
                                for result in st.session_state.attack_results:
                                    if result["ip"] == req["ip"]:
                                        cluster_data.append({
                                            "ip": req["ip"],
                                            "cluster": f"Cluster {cluster['cluster_id']}",
                                            "lat": result["geo_data"]["latitude"],
                                            "lon": result["geo_data"]["longitude"],
                                            "country": result["geo_data"]["country"]
                                        })
                    
                        if cluster_data:
                            cluster_df = pd.DataFrame(cluster_data)
                            
                            fig = px.scatter_geo(
                                cluster_df,
                                lat="lat",
                                lon="lon",
                                color="cluster",
                                hover_name="ip",
                                hover_data=["country"],
                                title="Attack Clusters by Geographic Location",
                                projection="natural earth"
                            )
                            
                            for cluster_name in cluster_df["cluster"].unique():
                                cluster_points = cluster_df[cluster_df["cluster"] == cluster_name]
                                
                                if len(cluster_points) >= 2:
                                    centroid_lat = cluster_points["lat"].mean()
                                    centroid_lon = cluster_points["lon"].mean()
                                    
                                    for _, point in cluster_points.iterrows():
                                        fig.add_trace(go.Scattergeo(
                                            lat=[point["lat"], centroid_lat],
                                            lon=[point["lon"], centroid_lon],
                                            mode="lines",
                                            line=dict(width=0.5, color="rgba(0, 0, 0, 0.3)"),
                                            showlegend=False
                                        ))
                            
                            st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.success("No coordinated attack patterns detected in this simulation")

    with ml_insights_tab:
        st.subheader("Machine Learning Insights")
        st.write("View ML-based analysis of DDoS patterns and anomaly detection")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("### Anomaly Detection")
            
            if "attack_results" in st.session_state and st.session_state.attack_results:
                ml_results = []
                for result in st.session_state.attack_results:
                    request_data = {
                        "ip": result["ip"],
                        "request_frequency": result.get("request_count", 0),
                        "connection_time": 30 if result.get("attack_type") == "SLOW_LORIS" else 1,
                        "completed": result.get("attack_type") != "SLOW_LORIS",
                        "headers": {"User-Agent": "Test Agent"},
                        "time_since_last_request": 1.0
                    }
                    
                    anomaly_result = detector.detect_anomaly(request_data)
                    
                    classification = detector.classify_attack_type(request_data)
                    
                    ml_results.append({
                        "ip": result["ip"],
                        "is_anomaly": anomaly_result["is_anomaly"],
                        "anomaly_probability": anomaly_result["anomaly_probability"],
                        "attack_type": classification["attack_type"],
                        "attack_confidence": classification["confidence"]
                    })
                
                anomaly_count = sum(1 for r in ml_results if r["is_anomaly"])
                anomaly_percent = (anomaly_count / len(ml_results)) * 100 if ml_results else 0
                
                col_a, col_b = st.columns(2)
                with col_a:
                    st.metric("Anomalies Detected", f"{anomaly_count}/{len(ml_results)}")
                with col_b:
                    st.metric("Anomaly Rate", f"{anomaly_percent:.1f}%")
                
                st.write("#### Anomaly Probability Distribution")
                anomaly_df = pd.DataFrame([(r["ip"], r["anomaly_probability"]) for r in ml_results], 
                                         columns=["IP", "Anomaly Probability"])
                
                fig = px.histogram(
                    anomaly_df,
                    x="Anomaly Probability",
                    nbins=20,
                    title="Distribution of Anomaly Probabilities",
                    color_discrete_sequence=["#ff7f0e"]
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Run a DDoS simulation to see ML-based anomaly detection results")
        
        with col2:
            st.write("### Attack Classification")
            
            if "attack_results" in st.session_state and st.session_state.attack_results:
                attack_types = [r["attack_type"] for r in ml_results]
                attack_type_counts = pd.Series(attack_types).value_counts().reset_index()
                attack_type_counts.columns = ["Attack Type", "Count"]
                
                fig = px.pie(
                    attack_type_counts,
                    values="Count",
                    names="Attack Type",
                    title="Attack Type Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                st.plotly_chart(fig, use_container_width=True)
                
                confidence_df = pd.DataFrame([
                    (r["ip"], r["attack_type"], r["attack_confidence"]) 
                    for r in ml_results
                ], columns=["IP", "Attack Type", "Confidence"])
                
                fig = px.box(
                    confidence_df,
                    x="Attack Type",
                    y="Confidence",
                    title="Attack Detection Confidence by Type",
                    color="Attack Type"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Run a DDoS simulation to see attack classification results")
        
        st.write("### Attack Clustering Analysis")
        
        if "attack_results" in st.session_state and st.session_state.attack_results:
            cluster_data = []
            for i, result in enumerate(st.session_state.attack_results):
                if i < len(ml_results):
                    cluster_data.append({
                        "ip": result["ip"],
                        "timestamp": result["timestamp"],
                        "suspicion_level": result["suspicion_level"],
                        "features": [
                            result.get("request_count", 0),
                            30 if result.get("attack_type") == "SLOW_LORIS" else 1,
                            0 if result.get("attack_type") == "SLOW_LORIS" else 1,
                            1,
                            0,
                            0,
                            1.0
                        ]
                    })
            
            if len(cluster_data) >= 5:  # Need at least 5 data points for meaningful clustering
                clustering_result = detector.identify_attack_clusters(cluster_data)
                
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("Clusters Detected", clustering_result["num_clusters"])
                with col_b:
                    st.metric("Total Data Points", clustering_result["total_requests"])
                with col_c:
                    st.metric("Noise Points", clustering_result["noise_points"])
                
                if clustering_result["num_clusters"] > 0:
                    st.write("#### Detected Attack Clusters")
                    
                    cluster_sizes = []
                    cluster_ids = []
                    for cluster in clustering_result["clusters"]:
                        cluster_ids.append(f"Cluster {cluster['cluster_id']}")
                        cluster_sizes.append(len(cluster["requests"]))
                    
                    cluster_df = pd.DataFrame({
                        "Cluster": cluster_ids,
                        "Size": cluster_sizes
                    })
                    
                    fig = px.bar(
                        cluster_df,
                        x="Cluster",
                        y="Size",
                        title="Attack Cluster Sizes",
                        color="Size",
                        color_continuous_scale="Viridis"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    for i, cluster in enumerate(clustering_result["clusters"]):
                        with st.expander(f"Cluster {cluster['cluster_id']} - {len(cluster['requests'])} IPs"):
                            ips = [req["ip"] for req in cluster["requests"]]
                            st.write(f"IPs in this cluster: {', '.join(ips[:10])}" + 
                                    (f" and {len(ips)-10} more..." if len(ips) > 10 else ""))
                else:
                    st.info("No significant attack clusters detected in this simulation")
            else:
                st.info("Need at least 5 data points for clustering analysis. Run a larger simulation.")
            
            with st.expander("ML Model Training Controls", expanded=False):
                st.write("""
                ### Train the ML Model
                
                You can train the ML model with your own labeled data to improve detection accuracy.
                In a real-world scenario, you would use historical attack data with known labels.
                """)
                
                if st.button("Train Model with Current Simulation Data"):
                    if "attack_results" in st.session_state and st.session_state.attack_results:
                        training_data = []
                        for result in st.session_state.attack_results:
                            training_data.append({
                                "ip": result["ip"],
                                "request_frequency": result.get("request_count", 0),
                                "connection_time": 30 if result.get("attack_type") == "SLOW_LORIS" else 1,
                                "completed": result.get("attack_type") != "SLOW_LORIS",
                                "headers": {"User-Agent": "Test Agent"},
                                "is_anomaly": result.get("suspicion_level", 0) >= 3,  # Use suspicion level as a proxy
                                "attack_type": result.get("attack_type", "UNKNOWN")
                            })
                        
                        with st.spinner("Training ML model..."):
                            training_result = detector.train_models(training_data)
                        
                        if training_result["status"] == "success":
                            st.success(f"Model trained successfully with {training_result['samples_trained']} samples!")
                        else:
                            st.error(f"Training failed: {training_result['message']}")
                    else:
                        st.warning("No simulation data available for training. Run a simulation first.")

    with config_tab:
        st.subheader("DDoS Defense Configuration")
        
        rate_limit_config, auto_response_config, ml_config = st.tabs(
            ["Rate Limiting", "Automated Response", "ML Configuration"]
        )
        
        with rate_limit_config:
            st.write("### Rate Limiter Settings")

        with auto_response_config:
            st.write("### Automated Response System")
            
            from ddos.auto_response import get_response_system
            response_system = get_response_system()
            
            current_config = response_system.get_config()
            
            with st.form("auto_response_config_form"):
                st.write("#### Throttling Settings")
                throttling_enabled = st.checkbox("Enable Throttling", 
                                              value=current_config["throttling"]["enabled"])
                
                st.write("#### CAPTCHA Settings")
                captcha_enabled = st.checkbox("Enable CAPTCHA Challenges", 
                                           value=current_config["captcha"]["enabled"])
                captcha_threshold = st.slider("CAPTCHA Suspicion Threshold (1-5)", 
                                           min_value=1, max_value=5, 
                                           value=current_config["captcha"]["suspicion_threshold"])
                
                st.write("#### Blocking Settings")
                blocking_enabled = st.checkbox("Enable IP Blocking", 
                                            value=current_config["blocking"]["enabled"])
                block_threshold = st.slider("Auto-block Suspicion Threshold (1-5)", 
                                         min_value=1, max_value=5, 
                                         value=current_config["blocking"]["auto_block_threshold"])
                
                submit_button = st.form_submit_button("Update Configuration")
                
                if submit_button:
                    new_config = {
                        "throttling": {
                            "enabled": throttling_enabled
                        },
                        "captcha": {
                            "enabled": captcha_enabled,
                            "suspicion_threshold": captcha_threshold
                        },
                        "blocking": {
                            "enabled": blocking_enabled,
                            "auto_block_threshold": block_threshold
                        }
                    }
                    
                    updated_config = response_system.update_config(new_config)
                    st.success("Configuration updated successfully!")
        
        with ml_config:
            st.write("### Machine Learning Configuration")
            st.write("""
            Configure the behavior of the machine learning models used in DDoS detection.
            These settings affect how the system identifies anomalies and classifies attacks.
            """)
            
            with st.form("ml_config_form"):
                st.write("#### Anomaly Detection")
                anomaly_threshold = st.slider(
                    "Anomaly Threshold (lower = more sensitive)", 
                    min_value=0.1, max_value=0.9, value=0.5, step=0.05
                )
                
                st.write("#### Clustering")
                cluster_eps = st.slider(
                    "Cluster Distance Threshold (lower = tighter clusters)",
                    min_value=0.1, max_value=1.0, value=0.5, step=0.05
                )
                
                cluster_min_samples = st.slider(
                    "Minimum Samples per Cluster",
                    min_value=2, max_value=20, value=5
                )
                
                submit_ml_button = st.form_submit_button("Update ML Configuration")
                
                if submit_ml_button:
                    st.success("ML configuration updated successfully!")
                    st.info("Note: In a production environment, this would modify the behavior of the ML models.")

with sql_tab:
    st.title("SQL Injection Simulator")
    st.write("This tab simulates SQL injection attacks and demonstrates detection techniques.")
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.subheader("Database Schema")
        schema = get_dummy_database_schema()
        
        tables = list(schema.keys())
        selected_table = st.selectbox("Select Table", tables)
        
        if selected_table:
            st.write(f"**{selected_table} Table Schema:**")
            cols = schema[selected_table]["columns"]
            
            schema_df = pd.DataFrame({
                "Column": list(cols.keys()),
                "Type": [col["type"] for col in cols.values()],
                "Description": [col.get("description", "") for col in cols.values()]
            })
            st.dataframe(schema_df)
            
            st.write(f"**Sample {selected_table} Data:**")
            sample_data = schema[selected_table].get("sample_data", [])
            if sample_data:
                st.dataframe(pd.DataFrame(sample_data))
    
    with col2:
        st.subheader("Query Builder")
        st.write("Enter an SQL query to execute against the simulated database.")
        
        query_type = st.selectbox(
            "Query Type", 
            ["Custom Query", "SELECT", "INSERT", "UPDATE", "DELETE"]
        )
        
        if query_type == "SELECT":
            template = f"SELECT * FROM {selected_table} WHERE id = "
        elif query_type == "INSERT":
            cols = schema[selected_table]["columns"]
            col_names = list(cols.keys())
            template = f"INSERT INTO {selected_table} ({', '.join(col_names)}) VALUES ("
        elif query_type == "UPDATE":
            template = f"UPDATE {selected_table} SET column_name = 'new_value' WHERE id = "
        elif query_type == "DELETE":
            template = f"DELETE FROM {selected_table} WHERE id = "
        else:
            template = ""
        
        sql_query = st.text_area("SQL Query", value=template, height=100)
        
        if st.button("Execute Query"):
            if sql_query:
                detection_result = detect_injection(sql_query)
                
                try:
                    result = execute_query(sql_query)
                    
                    log_sql_injection(sql_query, detection_result)
                    
                    st.session_state.sql_result = {
                        "query": sql_query,
                        "detection": detection_result,
                        "result": result
                    }
                except Exception as e:
                    st.error(f"Error executing query: {str(e)}")
    
    if "sql_result" in st.session_state and st.session_state.sql_result:
        st.markdown("---")
        st.subheader("Query Results")
        
        result = st.session_state.sql_result
        
        if result["detection"]["is_injection"]:
            st.error(f"⚠️ SQL Injection Detected! Confidence: {result['detection']['confidence']:.2f}")
            st.warning(f"**Injection Type:** {result['detection']['type']}")
        else:
            st.success("✅ No SQL Injection Detected")
        
        st.write("**Result:**")
        if isinstance(result["result"], list):
            st.dataframe(pd.DataFrame(result["result"]))
        else:
            st.info(result["result"])
    
    with st.expander("SQL Injection Detection Model", expanded=False):
        st.write("""
        ### How the SQL Injection Detector Works
        
        The SQL injection detector uses a combination of techniques:
        
        1. **Pattern Matching**: Searching for known SQL injection patterns
        2. **Lexical Analysis**: Analyzing SQL query structure
        3. **Machine Learning**: Using NLP models to detect anomalous queries
        
        Try different variations of SQL injection to see how the detector responds!
        """)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Test Union-Based Injection"):
                union_query = f"SELECT * FROM {selected_table} UNION SELECT username, password FROM users"
                st.code(union_query)
                detection = detect_injection(union_query)
                st.write(f"**Detection Result:** {'⚠️ Injection Detected' if detection['is_injection'] else 'No Injection Detected'}")
        
        with col2:
            if st.button("Test Boolean-Based Injection"):
                boolean_query = f"SELECT * FROM {selected_table} WHERE id = 1 OR 1=1"
                st.code(boolean_query)
                detection = detect_injection(boolean_query)
                st.write(f"**Detection Result:** {'⚠️ Injection Detected' if detection['is_injection'] else 'No Injection Detected'}")
        
        with col3:
            if st.button("Test Time-Based Injection"):
                time_query = f"SELECT * FROM {selected_table} WHERE id = 1; WAITFOR DELAY '0:0:5'"
                st.code(time_query)
                detection = detect_injection(time_query)
                st.write(f"**Detection Result:** {'⚠️ Injection Detected' if detection['is_injection'] else 'No Injection Detected'}")

with xss_tab:
    st.title("XSS Attack Simulator")
    st.write("This tab simulates Cross-Site Scripting (XSS) attacks and demonstrates detection techniques.")
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.subheader("Web Context")
        contexts = list(render_web_context("comment_section", "").keys())
        if "error" in contexts:
            contexts = ["comment_section", "search_box", "profile_page", "url_parameters"]
            
        selected_context = st.selectbox(
            "Select Vulnerable Context", 
            ["comment_section", "search_box", "profile_page", "url_parameters"]
        )
        
        context_descriptions = {
            "comment_section": "A comment section on a blog or article where users can post comments.",
            "search_box": "A search results page that reflects the user's search query.",
            "profile_page": "A user profile page that displays user-provided information.",
            "url_parameters": "A page that uses URL parameters to customize content."
        }
        
        st.info(context_descriptions.get(selected_context, ""))
        
        st.subheader("Vulnerable Code Example")
        
        if selected_context == "comment_section":
            st.code("""
// Vulnerable code - directly inserting user input into HTML
let userComment = getUserInput();
commentSection.innerHTML = '<div class="comment">' + userComment + '</div>';

// Safe code - using proper sanitization
let userComment = getUserInput();
let sanitizedComment = sanitizeHTML(userComment);
commentSection.innerHTML = '<div class="comment">' + sanitizedComment + '</div>';
            """, language="javascript")
        elif selected_context == "search_box":
            st.code("""
// Vulnerable code - directly reflecting search query
let searchQuery = getUrlParameter('q');
resultHeader.innerHTML = 'Results for: ' + searchQuery;

// Safe code - using proper sanitization
let searchQuery = getUrlParameter('q');
let sanitizedQuery = sanitizeHTML(searchQuery);
resultHeader.innerHTML = 'Results for: ' + sanitizedQuery;
            """, language="javascript")
        elif selected_context == "profile_page":
            st.code("""
// Vulnerable code - directly inserting user profile data
let userName = userData.name;
let userBio = userData.bio;
profileDiv.innerHTML = '<h2>' + userName + '</h2><div>' + userBio + '</div>';

// Safe code - using proper sanitization
let userName = sanitizeHTML(userData.name);
let userBio = sanitizeHTML(userData.bio);
profileDiv.innerHTML = '<h2>' + userName + '</h2><div>' + userBio + '</div>';
            """, language="javascript")
        elif selected_context == "url_parameters":
            st.code("""
// Vulnerable code - directly reflecting URL parameters
let message = getUrlParameter('message');
document.getElementById('message').innerHTML = message;

// Safe code - using proper sanitization
let message = getUrlParameter('message');
let sanitizedMessage = sanitizeHTML(message);
document.getElementById('message').textContent = sanitizedMessage; // Using textContent is safer
            """, language="javascript")
    
    with col2:
        st.subheader("XSS Payload")
        st.write("Enter a potential XSS payload to test:")
        
        xss_examples = st.selectbox(
            "Preset XSS Examples", 
            ["Custom Input", "<script>alert('XSS')</script>", 
             "<img src='x' onerror='alert(\"XSS\")'>",
             "<svg onload='alert(\"XSS\")'>",
             "javascript:alert('XSS')"]
        )
        
        if xss_examples == "Custom Input":
            xss_payload = st.text_area("Enter XSS Payload:", "", height=100)
        else:
            xss_payload = xss_examples
            st.text_area("XSS Payload:", xss_payload, height=100)
        
        enable_sanitization = st.checkbox("Enable Sanitization", value=False)
        
        if st.button("Test XSS Payload"):
            if xss_payload:
                detection_result = detect_xss(xss_payload)
                
                render_result = render_web_context(
                    selected_context, 
                    xss_payload, 
                    sanitize=enable_sanitization
                )
                
                impact_result = simulate_web_impact(xss_payload, selected_context)
                
                log_xss_attempt(xss_payload, detection_result)
                
                st.session_state.xss_result = {
                    "detection": detection_result,
                    "render": render_result,
                    "impact": impact_result
                }
            else:
                st.warning("Please enter an XSS payload to test.")
    
    if "xss_result" in st.session_state and st.session_state.xss_result:
        st.markdown("---")
        st.subheader("XSS Test Results")
        
        result = st.session_state.xss_result
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**XSS Detection:**")
            if result["detection"]["is_xss"]:
                st.error(f"⚠️ XSS Detected! Confidence: {result['detection']['confidence']:.2f}")
                st.warning(f"**Type:** {result['detection']['type']}")
            else:
                st.success("✅ No XSS Detected")
            
            st.write("**Security Impact:**")
            impact = result["impact"]
            
            if impact["overall_severity"] == "critical":
                st.error(f"⚠️ Critical Security Risk!")
            elif impact["overall_severity"] == "high":
                st.error(f"⚠️ High Security Risk!")
            elif impact["overall_severity"] == "medium":
                st.warning(f"⚠️ Medium Security Risk!")
            else:
                st.info(f"ℹ️ Low Security Risk")
            
            for i, imp in enumerate(impact["impacts"]):
                severity_color = {
                    "critical": "🔴", 
                    "high": "🟠", 
                    "medium": "🟡", 
                    "low": "🔵"
                }.get(imp["severity"], "⚪")
                
                st.write(f"{severity_color} **{imp['type']}**: {imp['description']}")
        
        with col2:
            st.write("**Rendering Results:**")
            
            st.write("Without Sanitization:")
            unsafe_container = st.container()
            with unsafe_container:
                st.warning("⚠️ **Unsafe Output** (could execute if rendered in a browser)")
                st.code(result["render"]["unsafe_output"], language="html")
            
            st.write("With Sanitization:")
            safe_container = st.container()
            with safe_container:
                st.success("✅ **Safe Output** (properly sanitized)")
                st.code(result["render"]["safe_output"], language="html")
        
        st.markdown("---")
        st.subheader("Prevention Tips")
        
        if result["detection"]["is_xss"]:
            st.write("To prevent this type of XSS attack:")
            
            st.markdown("""
            1. **Always sanitize user input**: Use built-in functions or libraries to escape/encode HTML special characters
            2. **Implement Content Security Policy (CSP)**: Restrict which scripts can execute on your page
            3. **Use modern frameworks**: Many modern frameworks like React, Angular, or Vue automatically escape content
            """)
            
            if selected_context == "comment_section":
                st.markdown("""
                **For comment systems:**
                - Consider using Markdown instead of allowing HTML
                - Use a well-tested HTML sanitization library
                - Store sanitized content, not raw input
                """)
            elif selected_context == "search_box":
                st.markdown("""
                **For search results:**
                - Use textContent instead of innerHTML when reflecting search terms
                - Encode search terms when included in URLs
                - Validate and sanitize input server-side as well
                """)
            elif selected_context == "profile_page":
                st.markdown("""
                **For profile pages:**
                - Sanitize all user-provided data before storage
                - Consider allowing only a limited subset of formatting options
                - Apply additional validation for sensitive profile fields
                """)
            elif selected_context == "url_parameters":
                st.markdown("""
                **For URL parameters:**
                - Never trust data from URLs or query parameters
                - Always sanitize parameters before use
                - Use appropriate DOM APIs like textContent instead of innerHTML
                """)
        else:
            st.success("Your input doesn't appear to contain XSS. Always follow secure coding practices anyway!")
    
    with st.expander("Advanced XSS Testing", expanded=False):
        st.write("""
        ### Advanced XSS Testing
        
        Cross-Site Scripting comes in several forms:
        
        1. **Reflected XSS**: The malicious script is reflected off a web server, such as in search results or error messages
        2. **Stored XSS**: The malicious script is stored on the server (in a database, comment, etc.) and retrieved later
        3. **DOM-based XSS**: The vulnerability exists in client-side code rather than server-side code
        
        Try different techniques to understand how each works.
        """)
        
        st.subheader("DOM-based XSS Simulation")
        
        dom_payload = st.text_input("Enter DOM-XSS payload:", "")
        
        if st.button("Test DOM-XSS Payload"):
            if dom_payload:
                is_dom_xss = "document." in dom_payload or "window." in dom_payload or "location" in dom_payload
                
                st.code(f"""
// Vulnerable code:
const url = new URL(window.location.href);
const paramValue = url.searchParams.get('param');
document.getElementById('output').innerHTML = paramValue;  // Vulnerable to XSS!

// What happens with your input:
const paramValue = "{dom_payload}";
document.getElementById('output').innerHTML = paramValue;
                """, language="javascript")
                
                if is_dom_xss:
                    st.error("⚠️ Potential DOM-based XSS detected!")
                    st.warning("This input could manipulate the page's DOM if inserted into a vulnerable page.")
                else:
                    st.info("This input doesn't appear to target DOM manipulation specifically, but could still be dangerous in other contexts.")

with api_tab:
    st.title("API Security Analysis")
    st.write("Analyze API security issues and potential vulnerabilities.")
    
    render_api_admin()

with analysis_tab:
    st.title("Attack Analysis")
    st.write("Select the type of attack logs you want to analyze.")
    
    log_type = st.selectbox(
        "Select Analysis Type",
        ["Select an option...", "Text Attack Logs", "Credential Stuffing Logs", "Web Scraping Logs", 
         "DDoS Attack Logs", "SQL Injection Logs", "XSS Attack Logs", "Phishing Attack Logs"]
    )
    
    if log_type == "Text Attack Logs":
        st.subheader("Text Attack Analysis")
        st.write("Analyze logged adversarial text attack data captured by the honeypot.")
        
        try:
            with open("honeypot_log.txt", "r") as f:
                logs = f.read().split("--------------------------------------\n")
            
            data = []
            for entry in logs:
                if entry.strip():
                    lines = entry.splitlines()
                    entry_dict = {}
                    for line in lines:
                        if line.startswith("Time:"):
                            entry_dict["Time"] = line.replace("Time: ", "").strip()
                        elif line.startswith("Input Text:"):
                            entry_dict["Input"] = line.replace("Input Text: ", "").strip()
                        elif line.startswith("Adversarial Text:"):
                            entry_dict["Adversarial"] = line.replace("Adversarial Text: ", "").strip()
                        elif line.startswith("Original Prediction:"):
                            entry_dict["Original Prediction"] = line.replace("Original Prediction: ", "").strip()
                        elif line.startswith("Adversarial Prediction:"):
                            entry_dict["Adversarial Prediction"] = line.replace("Adversarial Prediction: ", "").strip()
                    data.append(entry_dict)
            
            if data:
                df = pd.DataFrame(data)
                st.write("### Logged Attack Data")
                st.dataframe(df)
                
                df["Time"] = pd.to_datetime(df["Time"], errors='coerce')
                
                st.write("### Attack Frequency Visualization")
                
                available_years = sorted(df["Time"].dt.year.unique().tolist())
                if not available_years:
                    available_years = [pd.Timestamp.now().year]
                selected_year = st.selectbox("Select Year", available_years, index=len(available_years)-1)  # Default to latest year
                
                year_df = df[df["Time"].dt.year == selected_year]
                
                interval_option = st.selectbox("Select Time Interval", ["1 Day", "7 Days", "30 Days"])
                
                if interval_option == "1 Day":
                    days = 1
                elif interval_option == "7 Days":
                    days = 7
                else:
                    days = 30
                    
                year_df["day"] = year_df["Time"].dt.strftime("%Y-%m-%d")
                daily_counts = year_df.groupby("day").size().reset_index(name="Attack Count")
                
                if not daily_counts.empty:
                    fig = px.bar(
                        daily_counts,
                        x="day",
                        y="Attack Count",
                        color="Attack Count",
                        color_continuous_scale=px.colors.qualitative.Pastel,
                        title=f"Attack Frequency ({selected_year}, {interval_option})",
                        labels={"day": "Date", "Attack Count": "Number of Attacks"}
                    )
                    
                    if len(daily_counts) > days:
                        fig.update_xaxes(range=[daily_counts["day"].iloc[-days], daily_counts["day"].iloc[-1]])
                    
                    fig.update_layout(
                        title_font_size=20,
                        title_x=0.5,
                        xaxis_title="Date",
                        yaxis_title="Number of Attacks",
                        uniformtext_minsize=12,
                        uniformtext_mode='hide'
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                    selected_date = None
                    view_logs = st.checkbox("View logs for a specific date", value=False)
                    
                    if view_logs:
                        available_dates = sorted(daily_counts["day"].unique().tolist())
                        selected_date = st.selectbox("Select date:", available_dates)
                    
                    if selected_date:
                        day_logs = year_df[year_df["day"] == selected_date]
                        
                        st.write(f"### Attack Logs for {selected_date}")
                        if not day_logs.empty:
                            for _, log in day_logs.iterrows():
                                with st.expander(f"Attack at {log['Time'].strftime('%H:%M:%S')}"):
                                    st.write("**Original Text:**")
                                    st.write(log["Input"])
                                    st.write("**Adversarial Text:**")
                                    st.write(log["Adversarial"])
                                    st.write("**Original Prediction:**")
                                    st.write(log["Original Prediction"])
                                    st.write("**Adversarial Prediction:**")
                                    st.write(log["Adversarial Prediction"])
                        else:
                            st.info("No detailed logs available for this date.")
                else:
                    st.info(f"No attack data available for {selected_year}. Try selecting a different year.")
            else:
                st.info("No log data available yet. Perform some attacks to generate log data.")
        except FileNotFoundError:
            st.info("Log file not found. Please perform some attacks to generate log data.")
            
    elif log_type == "Credential Stuffing Logs":
        st.subheader("Credential Stuffing Analysis")
        st.write("Analyze logged credential stuffing attack attempts.")
        
        try:
            with open("credential_honeypot_log.txt", "r") as f:
                cred_logs = f.read().split("--------------------------------------\n")
            
            cred_data = []
            for entry in cred_logs:
                if entry.strip():
                    lines = entry.splitlines()
                    entry_dict = {}
                    for line in lines:
                        if line.startswith("Time:"):
                            entry_dict["Time"] = line.replace("Time: ", "").strip()
                        elif line.startswith("Username:"):
                            entry_dict["Username"] = line.replace("Username: ", "").strip()
                        elif line.startswith("Risk Score:"):
                            entry_dict["Risk Score"] = float(line.replace("Risk Score: ", "").strip())
                        elif line.startswith("Attack Type:"):
                            entry_dict["Attack Type"] = line.replace("Attack Type: ", "").strip()
                    cred_data.append(entry_dict)
            
            if cred_data:
                cred_df = pd.DataFrame(cred_data)
                st.write("### Credential Stuffing Attacks")
                st.dataframe(cred_df)
                
                st.write("### Username Frequency")
                username_counts = cred_df["Username"].value_counts().reset_index()
                username_counts.columns = ["Username", "Count"]
                
                fig = px.bar(
                    username_counts.head(10),
                    x="Username",
                    y="Count",
                    title="Top 10 Attempted Usernames",
                    color="Count"
                )
                st.plotly_chart(fig, use_container_width=True)
                
                st.write("### Attack Type Distribution")
                attack_counts = cred_df["Attack Type"].value_counts().reset_index()
                attack_counts.columns = ["Attack Type", "Count"]
                
                fig = px.pie(
                    attack_counts,
                    values="Count",
                    names="Attack Type",
                    title="Distribution of Attack Types"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            else:
                st.info("No credential stuffing data available yet.")
        except FileNotFoundError:
            st.info("Credential stuffing log file not found.")
    elif log_type == "Web Scraping Logs":
        st.write("### Web Scraping Attack Analysis")
        
        try:
            with open("scraping_log.txt", "r") as f:
                scraping_logs = f.read().split("--------------------------------------\n")
            
            scraping_data = []
            for entry in scraping_logs:
                if entry.strip():
                    lines = entry.splitlines()
                    entry_dict = {}
                    for line in lines:
                        if line.startswith("Time:"):
                            entry_dict["Time"] = line.replace("Time: ", "").strip()
                        elif line.startswith("Target:"):
                            entry_dict["Target"] = line.replace("Target: ", "").strip()
                        elif line.startswith("Is Bot:"):
                            entry_dict["Is Bot"] = line.replace("Is Bot: ", "").strip()
                        elif line.startswith("Confidence:"):
                            entry_dict["Confidence"] = float(line.replace("Confidence: ", "").strip())
                        elif line.startswith("Patterns:"):
                            entry_dict["Patterns"] = line.replace("Patterns: ", "").strip()
                    scraping_data.append(entry_dict)
            
            if scraping_data:
                scraping_df = pd.DataFrame(scraping_data)
                
                st.dataframe(scraping_df)
                
                if "Target" in scraping_df.columns:
                    target_counts = scraping_df["Target"].value_counts().reset_index()
                    target_counts.columns = ["Target", "Count"]
                    
                    fig = px.pie(
                        target_counts,
                        values="Count",
                        names="Target",
                        title="Most Targeted Honeytokens",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
                if "Confidence" in scraping_df.columns:
                    fig = px.histogram(
                        scraping_df,
                        x="Confidence",
                        nbins=20,
                        title="Bot Detection Confidence Distribution",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
            else:
                st.info("No scraping log data available yet.")
            
        except FileNotFoundError:
            st.info("Scraping log file not found. Interact with the Web Scraping tab to generate data.")
    elif log_type == "DDoS Attack Logs":
        st.subheader("DDoS Attack Analysis")
        st.write("Analyze logged DDoS attack data captured by the honeypot.")
        
        ddos_logs = get_attack_logs(days=30, limit=1000)
        
        if ddos_logs:
            logs_df = pd.DataFrame(ddos_logs)
            
            st.write("### Attack Summary")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Attacks", len(logs_df))
            
            with col2:
                unique_ips = logs_df["ip"].nunique()
                st.metric("Unique IPs", unique_ips)
            
            with col3:
                avg_confidence = logs_df["confidence"].mean() if "confidence" in logs_df.columns else 0
                st.metric("Avg. Detection Confidence", f"{avg_confidence:.2f}")
            
            if "attack_type" in logs_df.columns:
                st.write("### Attack Type Distribution")
                attack_counts = logs_df["attack_type"].value_counts().reset_index()
                attack_counts.columns = ["Attack Type", "Count"]
                
                fig = px.pie(
                    attack_counts,
                    values="Count",
                    names="Attack Type",
                    title="Distribution of DDoS Attack Types"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            if "geo_data" in logs_df.columns:
                st.write("### Geographic Distribution")
                
                country_data = []
                for _, row in logs_df.iterrows():
                    if "geo_data" in row and row["geo_data"] and "country" in row["geo_data"]:
                        country_data.append({
                            "country": row["geo_data"]["country"],
                            "country_code": row["geo_data"].get("country_code", "XX"),
                            "attack_type": row.get("attack_type", "Unknown")
                        })
                
                if country_data:
                    country_df = pd.DataFrame(country_data)
                    country_counts = country_df["country"].value_counts().reset_index()
                    country_counts.columns = ["Country", "Count"]
                    
                    fig = px.choropleth(
                        country_counts,
                        locations="Country",
                        locationmode="country names",
                        color="Count",
                        hover_name="Country",
                        color_continuous_scale=px.colors.sequential.Plasma,
                        title="Attack Origins by Country"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            st.write("### Attack Timeline")
            
            if "timestamp" in logs_df.columns:
                logs_df["time"] = pd.to_datetime(logs_df["timestamp"])
                logs_df.sort_values("time", inplace=True)
                
                daily_attacks = logs_df.groupby(logs_df["time"].dt.date).size().reset_index()
                daily_attacks.columns = ["Date", "Attacks"]
                
                fig = px.bar(
                    daily_attacks,
                    x="Date",
                    y="Attacks",
                    title="Daily DDoS Attack Frequency",
                    labels={"Attacks": "Number of Attacks", "Date": "Date"}
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with st.expander("View Raw Attack Logs", expanded=False):
                st.dataframe(logs_df, use_container_width=True)
        else:
            st.info("No DDoS attack logs available yet. Simulate some attacks to generate data.")
    elif log_type == "SQL Injection Logs":
        st.subheader("SQL Injection Attack Analysis")
        st.write("Analyze logged SQL injection attack attempts.")
        
        try:
            with open("sql_injection_log.txt", "r") as f:
                sql_logs = f.read().split("--------------------------------------\n")
            
            sql_data = []
            for entry in sql_logs:
                if entry.strip():
                    lines = entry.splitlines()
                    entry_dict = {}
                    for line in lines:
                        if line.startswith("Time:"):
                            entry_dict["Time"] = line.replace("Time: ", "").strip()
                        elif line.startswith("Query:"):
                            entry_dict["Query"] = line.replace("Query: ", "").strip()
                        elif line.startswith("Injection Type:"):
                            entry_dict["Injection Type"] = line.replace("Injection Type: ", "").strip()
                        elif line.startswith("Confidence:"):
                            entry_dict["Confidence"] = float(line.replace("Confidence: ", "").strip())
                        elif line.startswith("IP:"):
                            entry_dict["IP"] = line.replace("IP: ", "").strip()
                    sql_data.append(entry_dict)
            
            if sql_data:
                sql_df = pd.DataFrame(sql_data)
                
                st.write("### SQL Injection Attacks")
                st.dataframe(sql_df)
                
                st.write("### Injection Type Distribution")
                
                if "Injection Type" in sql_df.columns:
                    type_counts = sql_df["Injection Type"].value_counts().reset_index()
                    type_counts.columns = ["Injection Type", "Count"]
                    
                    fig = px.pie(
                        type_counts,
                        values="Count",
                        names="Injection Type",
                        title="Distribution of SQL Injection Types"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                if "Confidence" in sql_df.columns:
                    fig = px.histogram(
                        sql_df,
                        x="Confidence",
                        nbins=20,
                        title="SQL Injection Detection Confidence Distribution",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                if "Time" in sql_df.columns:
                    sql_df["Time"] = pd.to_datetime(sql_df["Time"], errors='coerce')
                    sql_df["Day"] = sql_df["Time"].dt.date
                    
                    daily_counts = sql_df.groupby("Day").size().reset_index(name="Attack Count")
                    
                    fig = px.line(
                        daily_counts,
                        x="Day",
                        y="Attack Count",
                        title="SQL Injection Attacks Over Time",
                        markers=True
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No SQL injection log data available yet.")
        except FileNotFoundError:
            st.info("SQL injection log file not found. Perform some SQL injection attempts to generate data.")
    elif log_type == "XSS Attack Logs":
        st.subheader("XSS Attack Analysis")
        st.write("Analyze logged Cross-Site Scripting attack attempts.")
        
        try:
            with open("xss_log.txt", "r") as f:
                xss_logs = f.read().split("--------------------------------------\n")
            
            xss_data = []
            for entry in xss_logs:
                if entry.strip():
                    lines = entry.splitlines()
                    entry_dict = {}
                    for line in lines:
                        if line.startswith("Time:"):
                            entry_dict["Time"] = line.replace("Time: ", "").strip()
                        elif line.startswith("Input:"):
                            entry_dict["Input"] = line.replace("Input: ", "").strip()
                        elif line.startswith("Is XSS:"):
                            entry_dict["Is XSS"] = line.replace("Is XSS: ", "").strip()
                        elif line.startswith("XSS Type:"):
                            entry_dict["XSS Type"] = line.replace("XSS Type: ", "").strip()
                        elif line.startswith("Confidence:"):
                            entry_dict["Confidence"] = float(line.replace("Confidence: ", "").strip())
                        elif line.startswith("IP:"):
                            entry_dict["IP"] = line.replace("IP: ", "").strip()
                    xss_data.append(entry_dict)
            
            if xss_data:
                xss_df = pd.DataFrame(xss_data)
                
                st.write("### XSS Attack Attempts")
                st.dataframe(xss_df)
                
                st.write("### XSS Type Distribution")
                
                if "XSS Type" in xss_df.columns:
                    type_counts = xss_df["XSS Type"].value_counts().reset_index()
                    type_counts.columns = ["XSS Type", "Count"]
                    
                    fig = px.pie(
                        type_counts,
                        values="Count",
                        names="XSS Type",
                        title="Distribution of XSS Attack Types"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                if "Confidence" in xss_df.columns:
                    fig = px.histogram(
                        xss_df,
                        x="Confidence",
                        nbins=20,
                        title="XSS Detection Confidence Distribution",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                if "Time" in xss_df.columns:
                    xss_df["Time"] = pd.to_datetime(xss_df["Time"], errors='coerce')
                    xss_df["Day"] = xss_df["Time"].dt.date
                    
                    daily_counts = xss_df.groupby("Day").size().reset_index(name="Attack Count")
                    
                    fig = px.line(
                        daily_counts,
                        x="Day",
                        y="Attack Count",
                        title="XSS Attacks Over Time",
                        markers=True
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No XSS attack log data available yet.")
        except FileNotFoundError:
            st.info("XSS log file not found. Perform some XSS attack attempts to generate data.")
    elif log_type == "Phishing Attack Logs":
        st.subheader("Phishing Attack Analysis")
        st.write("Analyze logged phishing attack detection data.")
        
        try:
            from phishing.logger import get_phishing_logs
            phishing_logs = get_phishing_logs(days=30, limit=1000)
            
            if phishing_logs:
                df = pd.DataFrame(phishing_logs)
                st.write("### Phishing Attack Logs")
                st.dataframe(df)
                
                if "is_phishing" in df.columns:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        phishing_counts = df["is_phishing"].value_counts().reset_index()
                        phishing_counts.columns = ["Is Phishing", "Count"]
                        
                        fig = px.pie(
                            phishing_counts,
                            values="Count",
                            names="Is Phishing",
                            title="Phishing vs Legitimate Emails",
                            color_discrete_sequence=px.colors.qualitative.Pastel
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        if "phishing_type" in df.columns:
                            df["phishing_type"] = df["phishing_type"].fillna("legitimate")
                            
                            type_counts = df["phishing_type"].value_counts().reset_index()
                            type_counts.columns = ["Phishing Type", "Count"]
                            
                            fig = px.bar(
                                type_counts,
                                x="Phishing Type",
                                y="Count",
                                title="Distribution of Phishing Types",
                                color="Count"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                
                if "confidence" in df.columns:
                    phishing_df = df[df["is_phishing"] == True]
                    if not phishing_df.empty:
                        fig = px.histogram(
                            phishing_df,
                            x="confidence",
                            nbins=20,
                            title="Phishing Detection Confidence Distribution",
                            color_discrete_sequence=px.colors.qualitative.Pastel
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                if "timestamp" in df.columns:
                    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
                    df["date"] = df["timestamp"].dt.date
                    
                    daily_counts = df.groupby(["date", "is_phishing"]).size().reset_index(name="count")
                    
                    fig = px.line(
                        daily_counts,
                        x="date",
                        y="count",
                        color="is_phishing",
                        title="Phishing Attempts Over Time",
                        labels={"is_phishing": "Is Phishing", "count": "Number of Emails", "date": "Date"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No phishing log data available yet. Use the Phishing Attack tab to generate logs.")
        except Exception as e:
            st.error(f"Error analyzing phishing logs: {str(e)}")
            st.info("Phishing log file may not exist yet. Use the Phishing Attack tab to generate logs.")
    else:
        st.info("👆 Please select an analysis type from the dropdown above to view attack logs.")

with phishing_tab:
    st.title("Phishing Attack Simulation")
    st.write("This tab simulates and detects phishing attacks in emails.")
    
    phishing_sim_tab, url_analysis_tab, honeypot_tab, training_tab = st.tabs(["Email Simulation", "URL Analysis", "AI Honeypot", "Training"])
    
    with phishing_sim_tab:
        st.subheader("Email Phishing Detection")
        
        sample_emails = get_sample_emails()
        
        col1, col2 = st.columns([3, 2])
        
        with col1:
            st.write("### Email Content")
            
            email_source = st.radio(
                "Email Source",
                ["Sample Phishing Email", "Sample Legitimate Email", "Custom Email"],
                horizontal=True
            )
            
            email_data = {}
            
            if email_source == "Sample Phishing Email":
                sample_idx = st.selectbox(
                    "Select a sample phishing email",
                    range(len(sample_emails["phishing"])),
                    format_func=lambda i: f"{sample_emails['phishing'][i]['subject']}"
                )
                email_data = sample_emails["phishing"][sample_idx]
                st.info("This is a known phishing email sample for demonstration purposes.")
            
            elif email_source == "Sample Legitimate Email":
                sample_idx = st.selectbox(
                    "Select a sample legitimate email",
                    range(len(sample_emails["legitimate"])),
                    format_func=lambda i: f"{sample_emails['legitimate'][i]['subject']}"
                )
                email_data = sample_emails["legitimate"][sample_idx]
                st.info("This is a known legitimate email sample for demonstration purposes.")
            
            elif email_source == "Custom Email":
                with st.form("custom_email_form"):
                    from_address = st.text_input("From Email Address:")
                    subject = st.text_input("Email Subject:")
                    body = st.text_area("Email Body:", height=250)
                    
                    submit_button = st.form_submit_button("Analyze Email")
                    
                    if submit_button:
                        if not from_address or not subject or not body:
                            st.warning("Please fill in all fields.")
                        else:
                            email_data = {
                                "from": from_address,
                                "subject": subject,
                                "body": body
                            }
            
            if email_data:
                st.write("**From:** ", email_data.get("from", ""))
                st.write("**Subject:** ", email_data.get("subject", ""))
                st.write("**Body:**")
                st.text_area("Email Content", email_data.get("body", ""), height=250, disabled=True)
        
        with col2:
            st.write("### Detection Results")
            
            if email_data:
                if st.button("Analyze for Phishing"):
                    detection_result = detect_phishing(email_data)
                    
                    urls = extract_urls_from_email(email_data)
                    
                    log_phishing_attempt(email_data, detection_result)
                    
                    st.session_state.phishing_result = {
                        "email": email_data,
                        "detection": detection_result,
                        "urls": urls
                    }
                
                if "phishing_result" in st.session_state and st.session_state.phishing_result:
                    result = st.session_state.phishing_result
                    detection = result["detection"]
                    
                    if detection["is_phishing"]:
                        st.error(f"⚠️ Phishing Detected! Confidence: {detection['confidence']:.2f}")
                        if detection.get("type"):
                            st.warning(f"**Type:** {detection['type'].replace('_', ' ').title()}")
                    else:
                        st.success("✅ No Phishing Detected")
                    
                    if "indicators" in detection and detection["indicators"]:
                        st.write("**Risk Indicators:**")
                        for indicator in detection["indicators"]:
                            icon = "🔴" if indicator["severity"] == "critical" else "🟠" if indicator["severity"] == "high" else "🟡"
                            st.write(f"{icon} **{indicator['type'].replace('_', ' ').title()}**: {indicator['description']}")
                    
                    if result["urls"]:
                        st.write("**URLs in Email:**")
                        for url in result["urls"]:
                            url_analysis = analyze_url(url)
                            if url_analysis["is_suspicious"]:
                                st.warning(f"⚠️ {url} (Risk Score: {url_analysis['risk_score']:.2f})")
                            else:
                                st.info(f"✓ {url} (Risk Score: {url_analysis['risk_score']:.2f})")
    
    with url_analysis_tab:
        st.subheader("URL Analysis")
        st.write("Analyze URLs for phishing indicators")
        
        url_to_analyze = st.text_input("Enter URL to analyze:")
        
        if st.button("Analyze URL") and url_to_analyze:
            url_result = analyze_url(url_to_analyze)
            
            st.session_state.url_analysis = url_result
        
        if "url_analysis" in st.session_state and st.session_state.url_analysis:
            result = st.session_state.url_analysis
            
            if result["is_suspicious"]:
                st.error(f"⚠️ Suspicious URL detected! Risk Score: {result['risk_score']:.2f}")
            else:
                st.success(f"✅ URL appears safe. Risk Score: {result['risk_score']:.2f}")
            
            st.write(f"**Domain:** {result['domain']}")
            
            if result["indicators"]:
                st.write("**Risk Indicators:**")
                for indicator in result["indicators"]:
                    icon = "🔴" if indicator["severity"] == "critical" else "🟠" if indicator["severity"] == "high" else "🟡" if indicator["severity"] == "medium" else "🔵"
                    st.write(f"{icon} **{indicator['type'].replace('_', ' ').title()}**: {indicator['description']}")
            
            st.write("### URL Analysis Explanation")
            st.info("""
            **How URLs are analyzed:**
            - Domain analysis (suspicious TLDs, IP-based URLs, typosquatting)
            - Path and query parameter inspection
            - URL shortener detection
            - Look-alike domain detection
            - Malicious pattern recognition
            """)
    
    with honeypot_tab:
        st.subheader("AI Honeypot Email Simulation")
        st.write("Create fake company email scenarios to lure and analyze attackers")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            if st.button("Generate Honeypot Email Scenarios", use_container_width=True):
                with st.spinner("Generating fake company email scenarios..."):
                    scenarios = generate_honeypot_scenarios(5)
                    st.session_state.honeypot_scenarios = scenarios
                st.success(f"Generated {len(scenarios)} honeypot email scenarios")
            
            if "honeypot_scenarios" in st.session_state and st.session_state.honeypot_scenarios:
                st.write("### Honeypot Email Scenarios")
                
                for i, scenario in enumerate(st.session_state.honeypot_scenarios):
                    with st.expander(f"Scenario {i+1}: {scenario['subject']}", expanded=i==0):
                        st.write(f"**Company:** {scenario['company']}")
                        st.write(f"**From:** {scenario['from']}")
                        st.write(f"**To:** {scenario['to']}")
                        st.write(f"**Subject:** {scenario['subject']}")
                        st.write("**Body:**")
                        st.text_area(f"Email body {i}", scenario['body'], height=150, disabled=True)
                        st.write(f"**Scenario Type:** {scenario['scenario_type']}")
                        st.write(f"**Trap ID:** {scenario['trap_id']}")
        
        with col2:
            st.write("### Honeypot Controls")
            
            if st.button("Simulate Attacker Interactions", use_container_width=True):
                with st.spinner("Simulating attacker interactions..."):
                    interactions = simulate_attacker_interactions(3, 10)
                st.success(f"Simulated {len(interactions)} attacker interactions")
            
            if st.button("Train AI Model", use_container_width=True):
                with st.spinner("Training AI model..."):
                    result = train_honeypot_ai()
                if result["status"] == "success":
                    st.success(f"AI model trained: {result['message']}")
                else:
                    st.error(f"Training failed: {result['message']}")
            
            if st.button("Analyze Honeypot Effectiveness", use_container_width=True):
                with st.spinner("Analyzing honeypot effectiveness..."):
                    analysis = analyze_honeypot_data()
                st.session_state.honeypot_analysis = analysis
        
        if "honeypot_analysis" in st.session_state and st.session_state.honeypot_analysis:
            analysis = st.session_state.honeypot_analysis
            
            if analysis["status"] == "success":
                st.markdown("---")
                st.subheader("Honeypot Analysis Results")
                
                effectiveness = analysis["effectiveness_score"] * 100
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Effectiveness Score", f"{effectiveness:.1f}%")
                with col2:
                    st.metric("Total Interactions", analysis["total_interactions"])
                with col3:
                    st.metric("Unique Attackers", analysis["unique_attackers"])
                
                st.write("### Interaction Types")
                interaction_df = pd.DataFrame({
                    "Interaction Type": list(analysis["interaction_types"].keys()),
                    "Count": list(analysis["interaction_types"].values())
                })
                
                fig = px.pie(
                    interaction_df,
                    values="Count",
                    names="Interaction Type",
                    title="Distribution of Attacker Interactions",
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                st.plotly_chart(fig, use_container_width=True)
                
                st.write("### Trap Effectiveness")
                trap_data = []
                for trap_type, data in analysis["trap_effectiveness"].items():
                    trap_data.append({
                        "Trap Type": trap_type,
                        "Total": data["count"],
                        "Interactions": data["interactions"],
                        "Effectiveness": data["effectiveness"] * 100
                    })
                
                if trap_data:
                    trap_df = pd.DataFrame(trap_data)
                    fig = px.bar(
                        trap_df,
                        x="Trap Type",
                        y="Effectiveness",
                        title="Effectiveness by Trap Type (%)",
                        color="Effectiveness",
                        text_auto='.1f'
                    )
                    fig.update_traces(texttemplate='%{text}%', textposition='outside')
                    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide')
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning(f"Analysis: {analysis['message']}")
        
        st.subheader("Attacker Profiles")
        if st.button("View Attacker Profiles"):
            honeypot = get_ai_honeypot()
            attacker_profiles = honeypot.get_attacker_profiles()
            
            if attacker_profiles:
                st.write(f"### {len(attacker_profiles)} Attacker Profiles")
                for profile in attacker_profiles:
                    threat_color = {
                        "critical": "🔴", 
                        "high": "🟠", 
                        "medium": "🟡", 
                        "low": "🔵",
                        "unknown": "⚪"
                    }.get(profile["threat_level"], "⚪")
                    
                    with st.expander(f"{threat_color} IP: {profile['ip']} ({profile['threat_level'].title()} Threat)"):
                        st.write(f"**Interactions:** {profile['interactions']}")
                        st.write(f"**First Seen:** {profile['first_seen']}")
                        st.write(f"**Last Seen:** {profile['last_seen']}")
                        
                        if "interaction_types" in profile:
                            st.write("**Interaction Types:**")
                            for itype, count in profile["interaction_types"].items():
                                st.write(f"- {itype}: {count}")
                        
                        if "patterns" in profile and profile["patterns"]:
                            st.write("**Behavior Patterns:**")
                            for pattern in profile["patterns"]:
                                st.write(f"- {pattern.replace('_', ' ').title()}")
            else:
                st.info("No attacker profiles available yet. Generate scenarios and simulate interactions first.")
    
    with training_tab:
        st.subheader("Training & Awareness")
        st.write("Learn how to identify and protect against phishing attacks")
        
        st.write("### Common Phishing Indicators")
        
        indicators = [
            {
                "name": "Suspicious Sender",
                "description": "The email comes from a domain that doesn't match the organization it claims to be from",
                "example": "apple-support@secure-verify.com instead of support@apple.com"
            },
            {
                "name": "Urgency",
                "description": "The email creates a false sense of urgency to pressure you into acting quickly",
                "example": "URGENT: Your account will be closed in 24 hours if you don't verify..."
            },
            {
                "name": "Poor Grammar/Spelling",
                "description": "Legitimate organizations rarely send emails with obvious grammar mistakes",
                "example": "Dear customer, we need your verification urgent."
            },
            {
                "name": "Suspicious Links",
                "description": "Links that don't go where they claim to go, or use URL shorteners",
                "example": "paypal.com-secure.verify-now.net"
            },
            {
                "name": "Personal Information Requests",
                "description": "Legitimate organizations rarely ask for sensitive information via email",
                "example": "Please reply with your Social Security Number and credit card details..."
            }
        ]
        
        for idx, indicator in enumerate(indicators):
            with st.expander(f"{idx+1}. {indicator['name']}", expanded=idx==0):
                st.write(f"**Description:** {indicator['description']}")
                st.write(f"**Example:** *{indicator['example']}*")
        
        st.write("### How to Protect Yourself")
        
        protection_tips = [
            "**Verify the sender's email address**: Check that it comes from an official domain",
            "**Hover before clicking**: Hover over links to see where they actually go",
            "**Never provide sensitive information**: Legitimate organizations won't ask for passwords or financial details via email",
            "**Check for personalization**: Phishing emails often use generic greetings like 'Dear Customer'",
            "**Be wary of unexpected attachments**: Don't open attachments you weren't expecting",
            "**Contact the company directly**: Use official contact methods from their website, not from the email"
        ]
        
        for tip in protection_tips:
            st.markdown(f"- {tip}")
        
        st.write("### Phishing Simulation Exercise")
        
        if st.button("Start Phishing Quiz"):
            quiz_emails = [
                {
                    "from": "customer.service@paypa1.com",
                    "subject": "Your PayPal account has been limited!",
                    "body": "Dear Customer,\n\nWe've noticed unusual activity in your PayPal account. Your account has been limited until you confirm your information. Please click below to verify your identity.\n\n[Confirm Your Information Now](https://paypal-secure-center.com/verify)",
                    "is_phishing": True,
                    "explanation": "This is a phishing email. Notice the sender domain 'paypa1.com' uses a number '1' instead of the letter 'l'. The email also creates urgency and the link doesn't go to the official PayPal domain."
                },
                {
                    "from": "no-reply@github.com",
                    "subject": "Security alert: new sign-in to your GitHub account",
                    "body": "We noticed a new sign-in to your GitHub account from a new device on July 7, 2023.\n\nLocation: San Francisco, CA\nDevice: Chrome on Mac\n\nIf this was you, you can ignore this message. If not, you can secure your account here: https://github.com/settings/security",
                    "is_phishing": False,
                    "explanation": "This is a legitimate security alert from GitHub. It comes from an official GitHub domain, doesn't create excessive urgency, and the link goes directly to github.com."
                }
            ]
            
            st.session_state.quiz_idx = 0
            st.session_state.quiz_emails = quiz_emails
            st.session_state.quiz_score = 0
            st.session_state.quiz_answered = False
        
        if "quiz_emails" in st.session_state and "quiz_idx" in st.session_state:
            if st.session_state.quiz_idx < len(st.session_state.quiz_emails):
                quiz_email = st.session_state.quiz_emails[st.session_state.quiz_idx]
                
                st.write(f"**Email {st.session_state.quiz_idx + 1}/{len(st.session_state.quiz_emails)}**")
                st.write(f"**From:** {quiz_email['from']}")
                st.write(f"**Subject:** {quiz_email['subject']}")
                st.write(f"**Body:**")
                st.text_area("Email Body", quiz_email['body'], height=150, disabled=True)
                
                if not st.session_state.quiz_answered:
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("This is a phishing email"):
                            st.session_state.user_answer = True
                            st.session_state.quiz_answered = True
                    with col2:
                        if st.button("This is a legitimate email"):
                            st.session_state.user_answer = False
                            st.session_state.quiz_answered = True
                
                if st.session_state.quiz_answered:
                    if st.session_state.user_answer == quiz_email["is_phishing"]:
                        st.success("✅ Correct!")
                        st.session_state.quiz_score += 1
                    else:
                        st.error("❌ Incorrect!")
                    
                    st.info(f"**Explanation:** {quiz_email['explanation']}")
                    
                    if st.button("Next Email"):
                        st.session_state.quiz_idx += 1
                        st.session_state.quiz_answered = False
                        st.experimental_rerun()
            else:
                st.write(f"### Quiz Complete!")
                st.write(f"Your score: {st.session_state.quiz_score}/{len(st.session_state.quiz_emails)}")
                
                if st.session_state.quiz_score == len(st.session_state.quiz_emails):
                    st.success("Perfect score! You're well-prepared to spot phishing attempts.")
                elif st.session_state.quiz_score >= len(st.session_state.quiz_emails) * 0.7:
                    st.success("Good job! You caught most of the phishing attempts.")
                else:
                    st.warning("You might need more practice to identify phishing emails reliably.")
                
                if st.button("Restart Quiz"):
                    st.session_state.quiz_idx = 0
                    st.session_state.quiz_score = 0
                    st.session_state.quiz_answered = False
                    st.experimental_rerun()