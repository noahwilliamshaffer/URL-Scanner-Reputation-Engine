import re
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

class PatternDetector:
    """Advanced pattern detection for phishing, malware, and suspicious content."""
    
    def __init__(self):
        self.phishing_keywords = {
            'urgent', 'verify', 'suspend', 'account', 'login', 'update', 
            'confirm', 'security', 'alert', 'warning', 'expire', 'click',
            'winner', 'congratulations', 'prize', 'free', 'limited', 'act now'
        }
        
        self.suspicious_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'short.link', 'cutt.ly', 'tiny.cc'
        }
        
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'netflix.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'youtube.com', 'twitter.com', 'linkedin.com'
        }
    
    def analyze_url_patterns(self, url: str) -> Dict:
        """Analyze URL for suspicious patterns."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        patterns = {
            'suspicious_chars': self._check_suspicious_characters(url),
            'subdomain_abuse': self._check_subdomain_abuse(domain),
            'url_shortener': domain in self.suspicious_domains,
            'deceptive_path': self._check_deceptive_path(path),
            'ip_address': self._is_ip_address(domain)
        }
        
        return patterns
    
    def analyze_content_patterns(self, html_content: str, page_text: str) -> Dict:
        """Analyze page content for suspicious patterns."""
        patterns = {
            'phishing_keywords': self._count_phishing_keywords(page_text),
            'urgency_indicators': self._check_urgency_patterns(page_text),
            'fake_login_forms': self._detect_fake_login_forms(html_content),
            'suspicious_links': self._analyze_suspicious_links(html_content),
            'social_engineering': self._detect_social_engineering(page_text),
            'credential_harvesting': self._detect_credential_harvesting(html_content),
            'javascript_obfuscation': self._detect_js_obfuscation(html_content),
            'iframe_injection': self._detect_iframe_injection(html_content)
        }
        
        return patterns
    
    def _check_suspicious_characters(self, url: str) -> int:
        """Check for suspicious characters in URL."""
        suspicious_chars = ['@', '%', '\\', '<', '>', '"', "'", '`']
        count = sum(url.count(char) for char in suspicious_chars)
        return min(count, 5)
    
    def _check_subdomain_abuse(self, domain: str) -> int:
        """Check for excessive subdomain usage."""
        parts = domain.split('.')
        subdomain_count = len(parts) - 2
        return max(0, subdomain_count - 1)
    
    def _check_deceptive_path(self, path: str) -> bool:
        """Check for deceptive path patterns."""
        deceptive_patterns = ['/login/', '/signin/', '/account/', '/verify/']
        return any(pattern in path for pattern in deceptive_patterns)
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _count_phishing_keywords(self, text: str) -> int:
        """Count phishing-related keywords in text."""
        text_lower = text.lower()
        count = sum(1 for keyword in self.phishing_keywords if keyword in text_lower)
        return min(count, 10)
    
    def _check_urgency_patterns(self, text: str) -> int:
        """Check for urgency/pressure patterns."""
        urgency_patterns = [
            r'urgent.*action.*required',
            r'act.*now',
            r'expires.*today',
            r'limited.*time.*offer',
            r'immediate.*attention',
            r'suspend.*account',
            r'verify.*immediately'
        ]
        
        text_lower = text.lower()
        count = sum(1 for pattern in urgency_patterns if re.search(pattern, text_lower))
        return min(count, 5)
    
    def _detect_fake_login_forms(self, html: str) -> int:
        """Detect potentially fake login forms."""
        form_pattern = r'<form[^>]*>(.*?)</form>'
        password_pattern = r'type=["\']password["\']'
        
        forms = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
        fake_forms = 0
        
        for form in forms:
            if re.search(password_pattern, form, re.IGNORECASE):
                action_match = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
                if action_match:
                    action = action_match.group(1)
                    if any(suspicious in action.lower() for suspicious in ['bit.ly', 'tinyurl', 'goo.gl']):
                        fake_forms += 1
                else:
                    fake_forms += 1
        
        return fake_forms
    
    def _analyze_suspicious_links(self, html: str) -> int:
        """Analyze links for suspicious patterns."""
        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
        links = re.findall(link_pattern, html, re.DOTALL | re.IGNORECASE)
        
        suspicious_count = 0
        for href, text in links:
            if any(shortener in href.lower() for shortener in self.suspicious_domains):
                suspicious_count += 1
            
            if 'click here' in text.lower() or 'download now' in text.lower():
                suspicious_count += 1
        
        return min(suspicious_count, 10)
    
    def _detect_social_engineering(self, text: str) -> int:
        """Detect social engineering patterns."""
        social_patterns = [
            r'you.*have.*won',
            r'congratulations.*winner',
            r'claim.*prize',
            r'tax.*refund',
            r'lottery.*winner',
            r'inheritance.*money',
            r'nigerian.*prince',
            r'advance.*fee'
        ]
        
        text_lower = text.lower()
        count = sum(1 for pattern in social_patterns if re.search(pattern, text_lower))
        return min(count, 5)
    
    def _detect_credential_harvesting(self, html: str) -> int:
        """Detect credential harvesting patterns."""
        sensitive_patterns = [
            r'social.*security.*number',
            r'credit.*card.*number',
            r'bank.*account.*number',
            r'routing.*number',
            r'mother.*maiden.*name',
            r'date.*of.*birth'
        ]
        
        html_lower = html.lower()
        count = sum(1 for pattern in sensitive_patterns if re.search(pattern, html_lower))
        return min(count, 5)
    
    def _detect_js_obfuscation(self, html: str) -> int:
        """Detect JavaScript obfuscation patterns."""
        js_patterns = [
            r'eval\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode',
            r'document\.write\s*\(',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'atob\s*\(',
        ]
        
        count = sum(1 for pattern in js_patterns if re.search(pattern, html, re.IGNORECASE))
        return min(count, 5)
    
    def _detect_iframe_injection(self, html: str) -> int:
        """Detect suspicious iframe usage."""
        iframe_pattern = r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>'
        iframes = re.findall(iframe_pattern, html, re.IGNORECASE)
        
        suspicious_iframes = 0
        for src in iframes:
            if any(suspicious in src.lower() for suspicious in ['bit.ly', 'tinyurl', 'data:']):
                suspicious_iframes += 1
            
            if 'width="0"' in html.lower() or 'height="0"' in html.lower():
                suspicious_iframes += 1
        
        return suspicious_iframes
    
    def _is_similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are similar (simple similarity check)."""
        if len(domain1) != len(domain2):
            return False
        
        differences = sum(1 for a, b in zip(domain1, domain2) if a != b)
        return differences == 1 and len(domain1) > 4
    
    def calculate_pattern_score(self, url_patterns: Dict, content_patterns: Dict) -> Dict:
        """Calculate overall pattern-based risk score."""
        score_breakdown = {
            'url_score': 0,
            'content_score': 0,
            'total_pattern_score': 0,
            'high_risk_patterns': []
        }
        
        url_score = 0
        if url_patterns.get('suspicious_chars', 0) > 2:
            url_score += 1
        if url_patterns.get('subdomain_abuse', 0) > 2:
            url_score += 1
        if url_patterns.get('url_shortener', False):
            url_score += 1
        if url_patterns.get('deceptive_path', False):
            url_score += 1
        if url_patterns.get('ip_address', False):
            url_score += 1
        
        content_score = 0
        if content_patterns.get('phishing_keywords', 0) > 3:
            content_score += 1
        if content_patterns.get('urgency_indicators', 0) > 0:
            content_score += 1
        if content_patterns.get('fake_login_forms', 0) > 0:
            content_score += 2
            score_breakdown['high_risk_patterns'].append('fake_login_forms')
        if content_patterns.get('social_engineering', 0) > 0:
            content_score += 2
            score_breakdown['high_risk_patterns'].append('social_engineering')
        if content_patterns.get('credential_harvesting', 0) > 0:
            content_score += 2
            score_breakdown['high_risk_patterns'].append('credential_harvesting')
        if content_patterns.get('javascript_obfuscation', 0) > 2:
            content_score += 1
        
        score_breakdown['url_score'] = min(url_score, 5)
        score_breakdown['content_score'] = min(content_score, 5)
        score_breakdown['total_pattern_score'] = min(url_score + content_score, 8)
        
        return score_breakdown 