# AI Honeypot System

A sophisticated honeypot system designed to detect, analyze, and study various types of cyber attacks using AI/ML techniques. This system simulates vulnerable endpoints while monitoring and analyzing attack patterns.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
- [System Architecture](#system-architecture)
- [Development](#development)
- [Security Notice](#security-notice)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Overview

The AI Honeypot System is an educational and research tool that simulates vulnerable services to attract and analyze cyber attacks. Using advanced machine learning algorithms, the system can detect patterns, classify attack types, and provide comprehensive analytics on attack methodologies.

Key capabilities include:
- Simulation of multiple vulnerable endpoints
- Real-time attack detection and analysis
- Interactive visualizations of attack patterns
- ML-based attack classification
- Comprehensive logging and reporting

## Features

### 1. Text Attack Detection
- Sentiment analysis service simulation
- Adversarial text attack detection
- Style transfer implementation for attack simulation
- Support for TextFooler, DeepWordBug, and custom Negative Model attacks
- Comprehensive attack visualization and logging

### 2. Credential Stuffing Protection
- Login form honeypot with credential stuffing detection
- Advanced password pattern analysis
- Risk scoring system with multiple factors
- IP and user-agent based tracking
- ML-based attack pattern recognition
- Real-time statistics and reporting

### 3. Web Scraping Detection
- Sophisticated bot behavior analysis
- Strategic honeytoken placement
- Decoy data endpoints (financial data, customer lists, API keys)
- Request pattern analysis and fingerprinting
- Bot detection model with high accuracy
- Attack effectiveness evaluation metrics

### 4. DDoS Protection
- Real-time DDoS attack detection system
- Multiple attack vector simulation capabilities
- Geographic attack visualization with IP mapping
- ML-based traffic anomaly detection
- Request pattern analysis and fingerprinting
- IP geolocation tracking and blocking

### 5. SQL Injection Protection
- SQL injection attempt detection and classification
- Query pattern analysis with risk scoring
- Sophisticated injection detection model
- Dummy database schema simulation
- Attack vector categorization

### 6. XSS Attack Detection
- Cross-site scripting (XSS) pattern recognition
- Input sanitization demonstration and education
- Attack impact simulation with context
- Web context rendering for demonstration
- Comprehensive XSS pattern library

### 7. Phishing Attack Detection
- Email phishing simulation with realistic templates
- Machine learning-based phishing content analysis
- URL analysis for phishing indicators and risk scoring
- Domain spoofing and typosquatting detection
- Interactive phishing awareness training module
- Phishing type classification (banking, credential, delivery, etc.)
- Multi-factor risk assessment with visual indicators
- Educational resources on how to identify phishing attempts
- Interactive phishing detection quiz with scoring
- Comprehensive phishing attempt logging and analytics

### 8. API Security Protection
- Advanced API key management system
- Intelligent rate limiting and throttling
- Strategic honeypot/decoy endpoints
- ML-based API threat detection
- Administrative dashboard for monitoring
- REST API integration with security controls

### 9. Analysis Dashboard
- Real-time attack visualization with interactive charts
- Historical attack data analysis with filtering
- Geographic attack distribution mapping
- Attack pattern trend analysis
- Exportable attack logs in multiple formats

## Getting Started

### Prerequisites

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- Internet connection for geolocation services
- Git

### Installation

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

4. Download the dataset:
   The sentiment analysis model requires a dataset that is not included in the repository due to its size.
   Download the dataset from Kaggle: [Yelp Review Dataset](https://www.kaggle.com/datasets/ilhamfp31/yelp-review-dataset)
   Place the downloaded `sentiment.csv` file in the root directory of the project.

5. Verify installation:
   ```bash
   python -c "import streamlit, pandas, torch, transformers; print('Installation successful!')"
   ```

### Configuration

The system can be configured through the web interface, but you can also modify these files:

1. Geographic IP mapping:
   - Update `config/geoip.conf` with your ipinfo API key for more accurate geolocation

2. Attack thresholds:
   - Adjust detection sensitivity in `config/detection_thresholds.json`

3. Logging:
   - Configure logging behavior in `config/logging.conf`

## Usage

1. Start the application:
   ```bash
   streamlit run app.py
   ```

2. Access the dashboard in your browser:
   ```
   http://localhost:8501
   ```

3. Navigate through the different attack simulation tabs:
   - **Text Attack**: Test adversarial text attacks on sentiment analysis
   - **Credential Stuffing**: Simulate login attacks and view detection metrics
   - **Web Scraping**: Test bot detection with honeytokens
   - **DDoS Attack**: Simulate and visualize DDoS attack patterns
   - **SQL Injection**: Test SQL injection detection capabilities
   - **XSS Attack**: Experiment with cross-site scripting detection
   - **Phishing Attack**: Analyze and detect email phishing attempts
   - **API Security**: Explore API security mechanisms
   - **Analysis**: View aggregated data across all attack types

4. For each module:
   - Review the detection capabilities
   - Try different attack parameters
   - View real-time analytics
   - Export detection logs for further analysis

## System Architecture

```
.
├── app.py                  # Main application file
├── models/                 # ML models and detectors
│   ├── text_classifier.py  # Sentiment analysis model
│   ├── style_transfer.py   # Text style transfer model
│   ├── ddos_detector.py    # DDoS detection model
│   ├── bot_detector.py     # Web scraping detection model
│   └── api_security/       # API security models
├── text_attacks/                # Attack simulation modules
│   ├── text_attack.py      # Adversarial text attack generator
│   └── credential_attack.py # Credential stuffing simulation
├── web_scraping/           # Web scraping detection
├── sql_inject/             # SQL injection modules
├── xss/                    # XSS attack modules
├── ddos/                   # DDoS attack modules
├── phishing/               # Phishing attack detection
│   ├── email_simulation.py # Email phishing simulation
│   ├── detector.py         # ML-based phishing detection
│   ├── url_analyzer.py     # URL analysis for phishing 
│   ├── logger.py           # Phishing attempt logging
│   └── utils.py            # Email rendering and analysis utilities
├── api_security/           # API security protection modules
│   ├── rest_api.py         # REST API implementation
│   ├── ml_detector.py      # ML-based API attack detection
│   ├── honeypot.py         # API honeypot endpoints
│   └── admin_dashboard.py  # Admin monitoring interface
├── utils/                  # Utility functions
├── logs/                   # Log files
├── config/                 # Configuration files
└── style_transfer_model/   # Trained style transfer model
```

## Development

### Setting Up Development Environment

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/ai_honeypot.git
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Contribution Guidelines

1. Follow the existing code style and patterns
2. Add tests for new features
3. Update documentation for changes
4. Submit a pull request with a clear description of changes

### Running Tests

```bash
python -m unittest discover tests
```

## Security Notice

This system is designed for educational and research purposes only. Do not deploy it on production systems or use it for malicious purposes. The simulated vulnerabilities are for learning and testing purposes only.

Researchers using this tool should:
- Operate in controlled environments only
- Obtain proper authorization before testing
- Follow responsible disclosure procedures for any discovered vulnerabilities
- Comply with all applicable laws and regulations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Visualization powered by [Plotly](https://plotly.com/)
- Custom machine learning models for attack detection
- Adversarial text generation techniques
- Honeypot methodologies for cyber defense research

## Contact

Benjamin - [GitHub Profile](https://github.com/benjamin-githubprofile)

Project Link: [https://github.com/benjamin-githubprofile/ai_honeypot](https://github.com/benjamin-githubprofile/ai_honeypot)