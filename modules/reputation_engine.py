import requests
import logging
from config import Config
from urllib.parse import urlparse
import time
from .virustotal_client import VirusTotalClient

logger = logging.getLogger(__name__)

class ReputationEngine:
    """URL reputation scoring and threat assessment engine."""
    
    def __init__(self):
        self.virustotal_client = VirusTotalClient()
        
    def calculate_score(self, scan_result):
        """Calculate comprehensive reputation score (0-10, higher = more suspicious)."""
        score_breakdown = {
            'base_score': 0,
            'content_score': 0,
            'security_score': 0,
            'pattern_score': 0,
            'virustotal_score': 0,
            'total_score': 0,
            'risk_level': 'unknown',
            'threats': [],
            'pattern_threats': []
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
        
        # Pattern analysis scoring (new)
        pattern_analysis = scan_result.get('pattern_analysis', {})
        if pattern_analysis:
            pattern_result = self._calculate_pattern_score(pattern_analysis)
            score_breakdown['pattern_score'] = pattern_result.get('total_pattern_score', 0)
            score_breakdown['pattern_threats'] = pattern_result.get('high_risk_patterns', [])
        
        # VirusTotal integration (if API key available)
        if self.virustotal_client.is_available():
            vt_result = self.virustotal_client.scan_url(scan_result['url'])
            score_breakdown['virustotal_score'] = vt_result.get('risk_score', 0)
            score_breakdown['virustotal_data'] = vt_result
        
        # Calculate total score (adjusted for new pattern score)
        total = (score_breakdown['base_score'] + 
                score_breakdown['content_score'] + 
                score_breakdown['security_score'] + 
                score_breakdown['pattern_score'] +
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
    
    def _calculate_pattern_score(self, pattern_analysis):
        """Calculate score based on advanced pattern analysis."""
        url_patterns = pattern_analysis.get('url_patterns', {})
        content_patterns = pattern_analysis.get('content_patterns', {})
        
        score_breakdown = {
            'url_score': 0,
            'content_score': 0,
            'total_pattern_score': 0,
            'high_risk_patterns': []
        }
        
        # URL pattern scoring
        url_score = 0
        if url_patterns.get('suspicious_chars', 0) > 2:
            url_score += 1
        if url_patterns.get('subdomain_abuse', 0) > 2:
            url_score += 1
        if url_patterns.get('url_shortener', False):
            url_score += 1
        if url_patterns.get('deceptive_path', False):
            url_score += 1
            score_breakdown['high_risk_patterns'].append('deceptive_path')
        if url_patterns.get('ip_address', False):
            url_score += 1
            score_breakdown['high_risk_patterns'].append('ip_address')
        
        # Content pattern scoring (if available)
        content_score = 0
        if content_patterns:
            if content_patterns.get('phishing_keywords', 0) > 3:
                content_score += 1
            if content_patterns.get('urgency_indicators', 0) > 0:
                content_score += 1
                score_breakdown['high_risk_patterns'].append('urgency_tactics')
            if content_patterns.get('fake_login_forms', 0) > 0:
                content_score += 2
                score_breakdown['high_risk_patterns'].append('fake_login_forms')
            if content_patterns.get('social_engineering', 0) > 0:
                content_score += 2
                score_breakdown['high_risk_patterns'].append('social_engineering')
            if content_patterns.get('javascript_obfuscation', 0) > 2:
                content_score += 1
                score_breakdown['high_risk_patterns'].append('obfuscated_javascript')
        
        score_breakdown['url_score'] = min(url_score, 3)
        score_breakdown['content_score'] = min(content_score, 3)
        score_breakdown['total_pattern_score'] = min(url_score + content_score, 4)  # Max 4 points
        
        return score_breakdown

    def _determine_risk_level(self, total_score):
        """Determine risk level based on total score."""
        if total_score <= 2:
            return 'low'
        elif total_score <= 4:
            return 'medium'
        elif total_score <= 7:
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
        
        # Add pattern-based threats
        pattern_threats = score_breakdown.get('pattern_threats', [])
        threats.extend(pattern_threats)
        
        return list(set(threats))  # Remove duplicates 