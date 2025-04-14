import streamlit as st
from .rest_api import analyze_sentiment, get_users, get_stats
from .admin_dashboard import render_api_admin

def add_api_security_tab():
    api_tab = st.container()
    
    with api_tab:
        render_api_admin()
        
        st.write("---")
        st.subheader("API Endpoint Testing")
        
        test_endpoint = st.selectbox(
            "Select endpoint to test",
            ["/api/v1/sentiment", "/api/v1/users", "/api/v1/stats"]
        )
        
        api_key = st.text_input("API Key")
        
        if test_endpoint == "/api/v1/sentiment":
            text = st.text_area("Text to analyze")
            if st.button("Test Endpoint") and api_key and text:
                result = analyze_sentiment(text=text, api_key=api_key, client_ip="127.0.0.1")
                st.json(result)
        
        elif test_endpoint == "/api/v1/users":
            if st.button("Test Endpoint") and api_key:
                result = get_users(api_key=api_key, client_ip="127.0.0.1")
                st.json(result)
        
        elif test_endpoint == "/api/v1/stats":
            if st.button("Test Endpoint") and api_key:
                result = get_stats(api_key=api_key, client_ip="127.0.0.1")
                st.json(result)