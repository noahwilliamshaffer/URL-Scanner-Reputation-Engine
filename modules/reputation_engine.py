import requests
import logging
from config import Config
from urllib.parse import urlparse
import time

logger = logging.getLogger(__name__)

class ReputationEngine:
    """URL reputation scoring and threat assessment engine."""
    
    def __init__(self):
        self.virustotal_api_key = Config.VIRUSTOTAL_API_KEY
        self.virustotal_url = Config.VIRUSTOTAL_API_URL
        
    def calculate_score(self, scan_result):
        """Calculate comprehensive reputation score (0-10, higher = more suspicious)."""
        score_breakdown = {
            'base_score': 0,
            'content_score': 0,
            'security_score': 0,
            'virustotal_score': 0,
            'total_score': 0,
            'risk_level': 'unknown',
            'threats': []
        }
        
        if not scan_result.get('accessible'):
            score_breakdown['risk_level'] = 'inaccessible'
            return score_breakdown
        
        # Base URL analysis
        score_breakdown['base_score'] = self._calculate_base_score(scan_result)
        
        # Content analysis scoring
        score_breakdown['content_score'] = self._calculate_content_score(scan_result.get('content_analysis', {}))
        
        # Security indicators scoring
        score_breakdown['security_score'] = self._calculate_security_score(scan_result.get('security_indicators', {}))
        
        # VirusTotal integration (if API key available)
        if self.virustotal_api_key:
            score_breakdown['virustotal_score'] = self._get_virustotal_score(scan_result['url'])
        
        # Calculate total score
        total = (score_breakdown['base_score'] + 
                score_breakdown['content_score'] + 
                score_breakdown['security_score'] + 
                score_breakdown['virustotal_score'])
        
        score_breakdown['total_score'] = min(total, 10)  # Cap at 10
        
        # Determine risk level
        score_breakdown['risk_level'] = self._determine_risk_level(score_breakdown['total_score'])
        
        # Identify specific threats
        score_breakdown['threats'] = self._identify_threats(scan_result, score_breakdown)
        
        return score_breakdown
    
    def _calculate_base_score(self, scan_result):
        """Calculate base score from URL characteristics."""
        score = 0
        
        url = scan_result.get('url', '')
        security_indicators = scan_result.get('security_indicators', {})
        
        # URL length penalty
        if security_indicators.get('url_length', 0) > 100:
            score += 1
        if security_indicators.get('url_length', 0) > 200:
            score += 1
        
        # Suspicious TLD
        if security_indicators.get('suspicious_tld'):
            score += 2
        
        # Excessive subdomains
        subdomain_count = security_indicators.get('subdomain_count', 0)
        if subdomain_count > 3:
            score += 1
        if subdomain_count > 5:
            score += 1
        
        # Redirect analysis
        redirects = scan_result.get('redirects', [])
        if len(redirects) > 3:
            score += 1
        if len(redirects) > 5:
            score += 2
        
        return min(score, 4)  # Max 4 points for base score
    
    def _calculate_content_score(self, content_analysis):
        """Calculate score based on content analysis."""
        score = 0
        
        # Login forms (potential phishing)
        login_forms = content_analysis.get('login_forms', 0)
        if login_forms > 0:
            score += 2
        if login_forms > 2:
            score += 1
        
        # Suspicious scripts
        suspicious_scripts = content_analysis.get('suspicious_scripts', 0)
        score += min(suspicious_scripts, 2)
        
        # Excessive external links
        external_links = content_analysis.get('external_links', 0)
        if external_links > 20:
            score += 1
        
        # iframes (potential clickjacking)
        iframe_count = content_analysis.get('iframe_count', 0)
        if iframe_count > 5:
            score += 1
        
        return min(score, 4)  # Max 4 points for content score
    
    def _calculate_security_score(self, security_indicators):
        """Calculate score based on security indicators."""
        score = 0
        
        # No HTTPS
        if not security_indicators.get('https', False):
            score += 1
        
        # Missing security headers
        if not security_indicators.get('has_security_headers', False):
            score += 1
        
        return min(score, 2)  # Max 2 points for security score
    
    def _get_virustotal_score(self, url):
        """Get VirusTotal reputation score."""
        try:
            # Submit URL for scanning
            params = {
                'apikey': self.virustotal_api_key,
                'url': url
            }
            
            response = requests.post(self.virustotal_url + '/scan', params=params, timeout=10)
            
            if response.status_code == 200:
                scan_data = response.json()
                
                # Wait a moment then get report
                time.sleep(2)
                
                report_params = {
                    'apikey': self.virustotal_api_key,
                    'resource': url
                }
                
                report_response = requests.get(self.virustotal_url + '/report', params=report_params, timeout=10)
                
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    
                    if report_data.get('response_code') == 1:
                        positives = report_data.get('positives', 0)
                        total = report_data.get('total', 1)
                        
                        # Convert to 0-4 scale
                        if positives == 0:
                            return 0
                        elif positives <= 2:
                            return 1
                        elif positives <= 5:
                            return 2
                        elif positives <= 10:
                            return 3
                        else:
                            return 4
                            
        except Exception as e:
            logger.warning(f"VirusTotal API error: {str(e)}")
        
        return 0  # Default if API unavailable
    
    def _determine_risk_level(self, total_score):
        """Determine risk level based on total score."""
        if total_score <= 2:
            return 'low'
        elif total_score <= 4:
            return 'medium'
        elif total_score <= 6:
            return 'high'
        else:
            return 'critical'
    
    def _identify_threats(self, scan_result, score_breakdown):
        """Identify specific threat types based on analysis."""
        threats = []
        
        content_analysis = scan_result.get('content_analysis', {})
        security_indicators = scan_result.get('security_indicators', {})
        
        # Phishing indicators
        if content_analysis.get('login_forms', 0) > 0:
            threats.append('potential_phishing')
        
        # Malware indicators
        if content_analysis.get('suspicious_scripts', 0) > 0:
            threats.append('suspicious_scripts')
        
        # Security issues
        if not security_indicators.get('https', False):
            threats.append('insecure_connection')
        
        if security_indicators.get('suspicious_tld', False):
            threats.append('suspicious_domain')
        
        # Redirect chains
        if len(scan_result.get('redirects', [])) > 3:
            threats.append('excessive_redirects')
        
        return threats 