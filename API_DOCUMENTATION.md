# PhishSentry API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication
No authentication required for basic usage. VirusTotal integration requires API key configuration.

## Endpoints

### 1. Health Check
Check if the API is running and healthy.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "service": "PhishSentry"
}
```

### 2. Scan URL
Analyze a URL for security threats and reputation scoring.

**Endpoint:** `POST /scan`

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "scan_result": {
    "url": "https://example.com",
    "is_valid": true,
    "accessible": true,
    "redirects": [],
    "final_url": "https://example.com",
    "response_time": 0.85,
    "status_code": 200,
    "content_analysis": {
      "has_forms": false,
      "login_forms": 0,
      "external_links": 3,
      "suspicious_scripts": 0,
      "iframe_count": 0,
      "title": "Example Domain",
      "meta_description": "Example description",
      "content_length": 1256
    },
    "security_indicators": {
      "https": true,
      "has_security_headers": true,
      "suspicious_tld": false,
      "url_length": 19,
      "subdomain_count": 0,
      "domain_age_suspicious": false
    },
    "timestamp": 1640995200.0
  },
  "reputation_score": {
    "base_score": 0,
    "content_score": 0,
    "security_score": 0,
    "virustotal_score": 0,
    "total_score": 0,
    "risk_level": "low",
    "threats": []
  },
  "status": "completed"
}
```

### 3. VirusTotal Information
Get information about VirusTotal API status and rate limits.

**Endpoint:** `GET /virustotal/info`

**Response (API Available):**
```json
{
  "status": "available",
  "rate_limit_remaining": "4",
  "rate_limit_reset": "1640995800"
}
```

**Response (API Not Configured):**
```json
{
  "error": "API key not configured"
}
```

## Response Codes

| Code | Description |
|------|-------------|
| 200  | Success |
| 400  | Bad Request (invalid URL or missing parameters) |
| 500  | Internal Server Error |

## Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| low | 0-2 | Generally safe, minimal risk indicators |
| medium | 3-4 | Some suspicious characteristics detected |
| high | 5-6 | Multiple risk factors, likely malicious |
| critical | 7-10 | High confidence of malicious intent |

## Threat Types

| Threat | Description |
|--------|-------------|
| potential_phishing | Login forms detected, possible phishing site |
| suspicious_scripts | JavaScript patterns that may indicate malware |
| insecure_connection | No HTTPS encryption |
| suspicious_domain | Unusual TLD or domain characteristics |
| excessive_redirects | Multiple redirects that may indicate cloaking |

## Score Components

### Base Score (0-4 points)
- URL length analysis
- Suspicious top-level domains
- Subdomain count
- Redirect chain analysis

### Content Score (0-4 points)
- Login form detection
- Suspicious JavaScript patterns
- External link analysis
- iframe usage

### Security Score (0-2 points)
- HTTPS enforcement
- Security headers presence

### VirusTotal Score (0-4 points)
- External threat intelligence
- Multi-engine detection results

## Rate Limits

- **General API**: No rate limits
- **VirusTotal Free**: 4 requests/minute
- **VirusTotal Premium**: Higher limits based on subscription

## Error Handling

All errors return JSON with an error message:

```json
{
  "error": "Error description",
  "details": "Additional error details (if available)"
}
```

## Example Usage

### cURL
```bash
# Health check
curl -X GET http://localhost:5000/api/health

# Scan URL
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# VirusTotal info
curl -X GET http://localhost:5000/api/virustotal/info
```

### Python
```python
import requests

# Scan a URL
response = requests.post('http://localhost:5000/api/scan', 
                        json={'url': 'https://example.com'})
result = response.json()
print(f"Risk Level: {result['reputation_score']['risk_level']}")
```

### JavaScript
```javascript
// Scan a URL
fetch('http://localhost:5000/api/scan', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'https://example.com'})
})
.then(response => response.json())
.then(data => console.log('Risk Level:', data.reputation_score.risk_level));
``` 