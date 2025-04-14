# AI Honeypot System

A sophisticated honeypot system designed to detect, analyze, and study various types of cyber attacks using AI/ML techniques. This system simulates vulnerable endpoints while monitoring and analyzing attack patterns.

## Features

### 1. Text Attack Detection
- Simulates a sentiment analysis service
- Detects and analyzes adversarial text attacks
- Implements style transfer for attack simulation
- Tracks and visualizes attack patterns

### 2. DDoS Protection
- Real-time DDoS attack detection
- Multiple attack type simulation (HTTP Flood, Slow Loris, TCP SYN Flood, UDP Flood)
- Geographic attack visualization
- ML-based anomaly detection
- Configurable throttling and blocking mechanisms

### 3. Web Scraping Detection
- Bot behavior analysis
- Honeytokens for scraper detection
- Request pattern analysis
- User-agent and header validation
- Configurable rate limiting

### 4. SQL Injection Protection
- SQL injection attempt detection
- Query pattern analysis
- Risk scoring system
- Dummy database schema simulation

### 5. XSS Attack Detection
- Cross-site scripting (XSS) pattern recognition
- Input sanitization demonstration
- Attack impact simulation
- Multiple XSS vector detection

### 6. Credential Stuffing Protection
- Brute force attack detection
- Password pattern analysis
- Risk scoring system
- IP-based rate limiting

### 7. Analysis Dashboard
- Real-time attack visualization
- Historical attack data analysis
- Geographic attack distribution
- Attack pattern trends
- Exportable attack logs

## Technical Stack

- **Backend Framework**: Python with Streamlit
- **Machine Learning**: scikit-learn for anomaly detection and classification
- **Visualization**: Plotly for interactive charts
- **Data Storage**: File-based logging system
- **Rate Limiting**: Custom implementation with IP tracking

## Installation

1. Clone the repository:
```bash
git clone https://github.com/benjamin-githubprofile/ai_honeypot.git
cd ai_honeypot
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirement.txt
```

## Usage

1. Start the application:
```bash
streamlit run app.py
```

2. Access the dashboard at `http://localhost:8501`

3. Navigate through different attack simulation tabs:
   - Text Attack
   - Credential Stuffing
   - Web Scraping
   - DDoS Attack
   - SQL Injection
   - XSS Attack
   - Analysis

## Configuration

The system supports various configuration options:

- DDoS detection thresholds
- Rate limiting parameters
- ML model parameters
- Logging settings
- Blocking rules

Configuration can be modified through the UI in the respective tabs.

## Directory Structure

```
.
├── app.py                  # Main application file
├── models/                 # ML models and detectors
├── attacks/               # Attack simulation modules
├── web_scraping/          # Web scraping detection
├── sql_inject/            # SQL injection modules
├── xss/                   # XSS attack modules
├── ddos/                  # DDoS attack modules
├── utils/                 # Utility functions
├── logs/                  # Log files
└── config/                # Configuration files
```

## Security Notice

This system is designed for educational and research purposes only. Do not deploy it on production systems or use it for malicious purposes. The simulated vulnerabilities are for learning and testing purposes only.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Streamlit
- Uses scikit-learn for ML components
- Plotly for visualizations
- Inspired by real-world honeypot systems

## Contact

Benjamin - [GitHub Profile](https://github.com/benjamin-githubprofile)

Project Link: [https://github.com/benjamin-githubprofile/ai_honeypot](https://github.com/benjamin-githubprofile/ai_honeypot)
