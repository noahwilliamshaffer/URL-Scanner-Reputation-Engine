import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration class."""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'phishsentry-development-key-2024'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # API Configuration
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2/url'
    
    # Application Settings
    MAX_SCAN_REQUESTS = int(os.environ.get('MAX_SCAN_REQUESTS', 100))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 30))
    
    # Scoring thresholds
    SUSPICIOUS_SCORE_THRESHOLD = 3
    MALICIOUS_SCORE_THRESHOLD = 6 