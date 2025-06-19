import requests
from bs4 import BeautifulSoup
import validators
import re
from urllib.parse import urlparse, urljoin
import time
import logging
from config import Config

logger = logging.getLogger(__name__)

class URLScanner:
    """URL scanning and analysis engine."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 PhishSentry/1.0'
        })
        self.timeout = Config.SCAN_TIMEOUT
        
    def scan_url(self, url):
        """Perform comprehensive URL scan."""
        result = {
            'url': url,
            'is_valid': False,
            'accessible': False,
            'redirects': [],
            'final_url': url,
            'response_time': 0,
            'status_code': None,
            'content_analysis': {},
            'security_indicators': {},
            'timestamp': time.time()
        }
        
        try:
            # Validate URL format
            if not validators.url(url):
                result['error'] = 'Invalid URL format'
                return result
            
            result['is_valid'] = True
            
            # Perform HTTP request with redirect tracking
            start_time = time.time()
            response = self._make_request(url, result)
            
            if response:
                result['accessible'] = True
                result['status_code'] = response.status_code
                result['response_time'] = time.time() - start_time
                result['final_url'] = response.url
                
                # Analyze content
                result['content_analysis'] = self._analyze_content(response)
                result['security_indicators'] = self._check_security_indicators(response, url)
                
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            result['error'] = str(e)
            
        return result
    
    def _make_request(self, url, result):
        """Make HTTP request and track redirects."""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Track redirect chain
            if response.history:
                for redirect in response.history:
                    result['redirects'].append({
                        'from': redirect.url,
                        'to': redirect.headers.get('location', ''),
                        'status': redirect.status_code
                    })
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {url}: {str(e)}")
            result['error'] = f"Request failed: {str(e)}"
            return None
    
    def _analyze_content(self, response):
        """Analyze HTML content for suspicious patterns."""
        analysis = {
            'has_forms': False,
            'login_forms': 0,
            'external_links': 0,
            'suspicious_scripts': 0,
            'iframe_count': 0,
            'title': '',
            'meta_description': '',
            'content_length': len(response.content)
        }
        
        try:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Basic page info
            title_tag = soup.find('title')
            analysis['title'] = title_tag.get_text().strip() if title_tag else ''
            
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            analysis['meta_description'] = meta_desc.get('content', '') if meta_desc else ''
            
            # Form analysis
            forms = soup.find_all('form')
            analysis['has_forms'] = len(forms) > 0
            
            for form in forms:
                # Check for login-related forms
                form_text = str(form).lower()
                if any(keyword in form_text for keyword in ['password', 'login', 'signin', 'email']):
                    analysis['login_forms'] += 1
            
            # External links analysis
            base_domain = urlparse(response.url).netloc
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http') and urlparse(href).netloc != base_domain:
                    analysis['external_links'] += 1
            
            # Script analysis
            scripts = soup.find_all('script')
            for script in scripts:
                script_content = script.get_text() if script.get_text() else script.get('src', '')
                if self._is_suspicious_script(script_content):
                    analysis['suspicious_scripts'] += 1
            
            # iframe count
            analysis['iframe_count'] = len(soup.find_all('iframe'))
            
        except Exception as e:
            logger.error(f"Content analysis failed: {str(e)}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _check_security_indicators(self, response, original_url):
        """Check for security-related indicators."""
        indicators = {
            'https': False,
            'has_security_headers': False,
            'suspicious_tld': False,
            'url_length': len(original_url),
            'subdomain_count': 0,
            'domain_age_suspicious': False
        }
        
        try:
            # HTTPS check
            indicators['https'] = original_url.startswith('https://')
            
            # Security headers check
            security_headers = ['strict-transport-security', 'x-frame-options', 'x-content-type-options']
            indicators['has_security_headers'] = any(header in response.headers for header in security_headers)
            
            # URL analysis
            parsed_url = urlparse(original_url)
            domain = parsed_url.netloc
            
            # Subdomain count
            indicators['subdomain_count'] = len(domain.split('.')) - 2
            
            # Suspicious TLD check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            indicators['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
            
        except Exception as e:
            logger.error(f"Security indicator check failed: {str(e)}")
            indicators['error'] = str(e)
            
        return indicators
    
    def _is_suspicious_script(self, script_content):
        """Check if script content contains suspicious patterns."""
        if not script_content:
            return False
            
        suspicious_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'fromCharCode',
            r'base64',
            r'atob\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode'
        ]
        
        return any(re.search(pattern, script_content, re.IGNORECASE) for pattern in suspicious_patterns) 