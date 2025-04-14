import random

def evaluate_scraper_effectiveness(features):
    has_bot_agent = (
        "Python" in features["headers"]["user-agent"] or 
        "bot" in features["headers"]["user-agent"].lower() or 
        "Custom" in features["headers"]["user-agent"]
    )
    
    is_direct_access = features["request_pattern"] == "direct"
    is_fast = features.get("click_count", 0) > 20
    has_minimal_movement = features.get("movement_count", 0) < 10
    has_short_visit = features.get("time_on_page", 0) < 10.0
    
    bot_characteristics = [
        has_bot_agent,
        is_direct_access,
        is_fast,
        has_minimal_movement,
        has_short_visit
    ]
    
    return sum(bot_characteristics) >= 3

def display_attack_results(custom_attack_result, st):
    if custom_attack_result:
        result = custom_attack_result["result"]
        features = custom_attack_result["features"]
        is_effective = custom_attack_result.get("is_effective_scraper", False)
        
        st.subheader("Attack Test Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if result["is_bot"]:
                st.error("🤖 Bot-like behavior detected!")
            else:
                st.success("👤 Human-like behavior detected")
            st.write(f"**Confidence:** {result['confidence']:.2f}")
        
        with col2:
            if not result["is_bot"] or (is_effective and result["confidence"] < 0.6):
                st.success("✅ Scraping would be successful")
                st.write("Your configuration appears human-like enough to bypass detection")
            else:
                st.error("🚫 Scraping would be blocked")
                st.write("Your bot-like configuration has been detected")
        
        st.subheader("Suspicious Patterns Identified")
        
        if not result["suspicious_patterns"]:
            st.success("✓ No suspicious patterns detected")
        else:
            for pattern in result["suspicious_patterns"]:
                st.warning(f"⚠️ {pattern}")
        
        st.subheader("Configuration Analysis")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.write("### 🖱️ User Interaction")
            st.write(f"**Mouse Movements:** {features['movement_count']}")
            st.write(f"**Click Count:** {features['click_count']}")
            st.write(f"**Time on Page:** {features['time_on_page']} seconds")
        
        with col2:
            st.write("### 🔄 Navigation Behavior")
            st.write(f"**Access Pattern:** {features['request_pattern']}")
            st.write(f"**Referrer:** {features['headers']['referer'] or 'None'}")
        
        with col3:
            st.write("### 🌐 Technical Fingerprint")
            user_agent = features['headers']['user-agent']
            if len(user_agent) > 35:
                user_agent = user_agent[:35] + "..."
            st.write(f"**User Agent:** {user_agent}")
            st.write(f"**Accept Header:** {features['headers']['accept'] or 'None'}")
        
        if not (is_effective and result["is_bot"]):
            st.subheader("Recommendations to Improve")
            
            st.info("**How to optimize your scraper configuration:**")
            
            improvement_tips = []
            
            if not is_effective:
                improvement_tips.append("Configure at least 3 bot-like characteristics to create an effective scraper")
            
            if "no_mouse_movement" not in result["suspicious_patterns"] and features['movement_count'] > 10:
                improvement_tips.append("Decrease mouse movements to appear more bot-like")
            
            if "rapid_clicking" not in result["suspicious_patterns"]:
                improvement_tips.append("Increase click speed or reduce time on page")
            
            if "direct_resource_access" not in result["suspicious_patterns"]:
                improvement_tips.append("Use direct resource access pattern instead of normal navigation")
            
            if "Python" not in features["headers"]["user-agent"] and "bot" not in features["headers"]["user-agent"].lower():
                improvement_tips.append("Use a more efficient (less human-like) user agent")
            
            if not improvement_tips:
                improvement_tips = [
                    "Use a bot-like user agent (e.g., Python-requests)",
                    "Use direct resource access patterns", 
                    "Minimize mouse movements",
                    "Decrease time spent on pages",
                    "Use generic accept headers"
                ]
            
            for tip in improvement_tips:
                st.write(f"• {tip}")