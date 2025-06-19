import requests
import time
import logging
from typing import Dict, Optional
from config import Config

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """VirusTotal API client for URL reputation checking."""
    
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishSentry/1.0'
        })
        
    def is_available(self) -> bool:
        """Check if VirusTotal API is available (API key configured)."""
        return bool(self.api_key)
    
    def scan_url(self, url: str) -> Dict:
        """Submit URL for scanning and get results."""
        if not self.is_available():
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            # Submit URL for scanning
            scan_result = self._submit_url(url)
            if scan_result.get('response_code') != 1:
                return {'error': 'Failed to submit URL for scanning'}
            
            # Wait briefly for scan to process
            time.sleep(3)
            
            # Get scan report
            report = self._get_report(url)
            return self._process_report(report)
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return {'error': str(e)}
    
    def _submit_url(self, url: str) -> Dict:
        """Submit URL to VirusTotal for scanning."""
        params = {
            'apikey': self.api_key,
            'url': url
        }
        
        response = self.session.post(
            f"{self.base_url}/url/scan",
            data=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def _get_report(self, url: str) -> Dict:
        """Get scan report for URL."""
        params = {
            'apikey': self.api_key,
            'resource': url
        }
        
        response = self.session.get(
            f"{self.base_url}/url/report",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def _process_report(self, report: Dict) -> Dict:
        """Process VirusTotal report into standardized format."""
        processed = {
            'available': True,
            'scan_date': report.get('scan_date', ''),
            'total_scans': report.get('total', 0),
            'positive_detections': report.get('positives', 0),
            'detection_ratio': 0,
            'risk_score': 0,
            'engines': {},
            'permalink': report.get('permalink', '')
        }
        
        if report.get('response_code') == 1:
            total = processed['total_scans']
            positives = processed['positive_detections']
            
            if total > 0:
                processed['detection_ratio'] = round((positives / total) * 100, 2)
                
                # Calculate risk score (0-4 scale)
                if positives == 0:
                    processed['risk_score'] = 0
                elif positives <= 2:
                    processed['risk_score'] = 1
                elif positives <= 5:
                    processed['risk_score'] = 2
                elif positives <= 10:
                    processed['risk_score'] = 3
                else:
                    processed['risk_score'] = 4
            
            # Extract individual engine results
            scans = report.get('scans', {})
            for engine, result in scans.items():
                if result.get('detected'):
                    processed['engines'][engine] = {
                        'detected': True,
                        'result': result.get('result', 'Malware'),
                        'version': result.get('version', 'Unknown')
                    }
        
        elif report.get('response_code') == 0:
            processed['error'] = 'URL not found in VirusTotal database'
        elif report.get('response_code') == -2:
            processed['error'] = 'URL still being analyzed'
        else:
            processed['error'] = f"Unknown response code: {report.get('response_code')}"
        
        return processed
    
    def get_api_info(self) -> Dict:
        """Get API usage information."""
        if not self.is_available():
            return {'error': 'API key not configured'}
        
        try:
            response = self.session.get(
                f"{self.base_url}/url/report",
                params={'apikey': self.api_key, 'resource': 'https://google.com'},
                timeout=10
            )
            
            return {
                'status': 'available',
                'rate_limit_remaining': response.headers.get('X-RateLimit-Remaining', 'Unknown'),
                'rate_limit_reset': response.headers.get('X-RateLimit-Reset', 'Unknown')
            }
            
        except Exception as e:
            return {'error': str(e)} 