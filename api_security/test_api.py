import streamlit as st
from api_security.app_integration import add_api_security_tab

if __name__ == "__main__":
    st.title("API Security Module Test")
    add_api_security_tab() 