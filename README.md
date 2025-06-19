# PhishSentry 🛡️

PhishSentry is an advanced URL scanner and reputation engine that combines cybersecurity, OSINT, and automation to detect phishing, malware, and suspicious web content.

## Features

- 🔍 **Comprehensive URL Analysis**: Deep scanning of web content, structure, and behavior
- 🧠 **AI-Powered Scoring**: Advanced reputation scoring algorithm
- 🔒 **Security Assessment**: SSL/TLS analysis, security headers validation
- 🌐 **VirusTotal Integration**: External threat intelligence from VirusTotal API
- 📊 **Detailed Reports**: Rich visualization of scan results and threat indicators
- 🚀 **REST API**: JSON API endpoints for programmatic access
- 💻 **Web Interface**: Beautiful, responsive web dashboard

## Technology Stack

- **Backend**: Python 3.8+, Flask
- **Web Scraping**: BeautifulSoup4, Requests
- **Frontend**: Bootstrap 5, Font Awesome
- **External APIs**: VirusTotal API
- **Security**: HTTPS enforcement, security headers validation

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/noahwilliamshaffer/PhishSentry.git
   cd PhishSentry
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env and add your VirusTotal API key (optional)
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

5. **Run the application**:
   ```bash
   python app.py
   ```

The application will be available at `http://localhost:5000`

## Usage

### Web Interface

1. Navigate to `http://localhost:5000`
2. Click "Start Scanning" or go to `/scan`
3. Enter a URL to analyze
4. View the detailed security report

### REST API

#### Scan URL

**Endpoint**: `POST /api/scan`

**Request Body**:
```json
{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "url": "https://example.com",
  "scan_result": {
    "accessible": true,
    "status_code": 200,
    "response_time": 0.85,
    "content_analysis": {
      "title": "Example Domain",
      "has_forms": false,
      "login_forms": 0,
      "external_links": 5,
      "suspicious_scripts": 0
    },
    "security_indicators": {
      "https": true,
      "has_security_headers": true,
      "url_length": 19,
      "subdomain_count": 0
    }
  },
  "reputation_score": {
    "total_score": 1.2,
    "risk_level": "low",
    "threats": []
  }
}
```

#### Health Check

**Endpoint**: `GET /api/health`

**Response**:
```json
{
  "status": "healthy",
  "service": "PhishSentry"
}
```

## Detection Logic

PhishSentry uses a multi-layered approach to assess URL reputation:

### Scoring Components

1. **Base URL Analysis (0-4 points)**:
   - URL length (excessive length indicates obfuscation)
   - Suspicious TLDs (.tk, .ml, .ga, .cf, etc.)
   - Subdomain count (excessive subdomains)
   - Redirect chain analysis

2. **Content Analysis (0-4 points)**:
   - Login form detection (phishing indicator)
   - Suspicious JavaScript patterns
   - External link analysis
   - iframe usage (clickjacking potential)

3. **Security Indicators (0-2 points)**:
   - HTTPS enforcement
   - Security headers presence
   - Certificate validation

4. **VirusTotal Score (0-4 points)**:
   - External threat intelligence
   - Multi-engine malware detection

### Risk Levels

- **Low (0-2)**: Generally safe
- **Medium (3-4)**: Potentially suspicious
- **High (5-6)**: Likely malicious
- **Critical (7-10)**: Definitely malicious

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for enhanced scanning | None |
| `FLASK_ENV` | Flask environment mode | development |
| `FLASK_DEBUG` | Enable Flask debug mode | True |
| `SECRET_KEY` | Flask secret key for sessions | auto-generated |
| `MAX_SCAN_REQUESTS` | Maximum concurrent scan requests | 100 |
| `SCAN_TIMEOUT` | HTTP request timeout in seconds | 30 |

## API Rate Limits

- **VirusTotal Free**: 4 requests/minute
- **VirusTotal Premium**: Higher limits available

## Security Considerations

- All scanned URLs are processed server-side for security
- No user data is permanently stored
- SSL/TLS verification enforced for production
- Input validation and sanitization implemented

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -am 'Add some feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

PhishSentry is for educational and security research purposes. Always verify results with multiple sources and follow responsible disclosure practices when reporting security issues.

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/noahwilliamshaffer/PhishSentry/issues) page
2. Create a new issue with detailed information
3. Include logs and reproduction steps

---

**⚠️ Important**: This tool performs active scanning of URLs. Use responsibly and in accordance with applicable laws and terms of service. 