"""
Threat Patterns Configuration
Centralized configuration for threat detection patterns and rules.
"""

# Phishing Keywords
PHISHING_KEYWORDS = {
    'urgent', 'verify', 'suspend', 'account', 'login', 'update', 
    'confirm', 'security', 'alert', 'warning', 'expire', 'click'
}

# Suspicious Domain Indicators
SUSPICIOUS_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'
}

# Legitimate domains for typosquatting detection
LEGITIMATE_DOMAINS = {
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'netflix.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'youtube.com', 'twitter.com', 'linkedin.com',
    'instagram.com', 'reddit.com', 'ebay.com', 'paypal.com',
    'dropbox.com', 'spotify.com', 'discord.com', 'zoom.us'
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.click', '.download'
}

# Deceptive path patterns
DECEPTIVE_PATHS = [
    r'/login/', r'/signin/', r'/account/', r'/verify/', r'/update/',
    r'/security/', r'/paypal/', r'/amazon/', r'/microsoft/', r'/apple/',
    r'/google/', r'/facebook/', r'/twitter/', r'/instagram/', r'/netflix/',
    r'/banking/', r'/wallet/', r'/payment/', r'/billing/'
]

# Suspicious query parameters
SUSPICIOUS_QUERY_PARAMS = [
    'redirect', 'return', 'next', 'continue', 'goto', 'forward',
    'target', 'destination', 'callback', 'returnto', 'ref', 'redir'
]

# Urgency patterns for social engineering detection
URGENCY_PATTERNS = [
    r'urgent.*action.*required', r'act.*now', r'expires.*today',
    r'limited.*time.*offer', r'immediate.*attention', r'suspend.*account',
    r'verify.*immediately', r'click.*here.*now', r'expires.*soon',
    r'final.*notice', r'last.*chance', r'time.*sensitive'
]

# Social engineering patterns
SOCIAL_ENGINEERING_PATTERNS = [
    r'you.*have.*won', r'congratulations.*winner', r'claim.*prize',
    r'tax.*refund', r'lottery.*winner', r'inheritance.*money',
    r'nigerian.*prince', r'advance.*fee', r'free.*money',
    r'gift.*card', r'reward.*program', r'cash.*prize'
]

# Credential harvesting patterns
CREDENTIAL_PATTERNS = [
    r'social.*security.*number', r'ssn', r'credit.*card.*number',
    r'bank.*account.*number', r'routing.*number', r'sort.*code',
    r'mother.*maiden.*name', r'date.*of.*birth', r'driver.*license',
    r'passport.*number', r'national.*id', r'tax.*id'
]

# JavaScript obfuscation patterns
JS_OBFUSCATION_PATTERNS = [
    r'eval\s*\(', r'unescape\s*\(', r'String\.fromCharCode',
    r'document\.write\s*\(', r'\\x[0-9a-fA-F]{2}', r'\\u[0-9a-fA-F]{4}',
    r'atob\s*\(', r'btoa\s*\(', r'escape\s*\(', r'Function\s*\(',
    r'setTimeout\s*\(\s*["\']', r'setInterval\s*\(\s*["\']'
]

# Malicious script indicators
MALICIOUS_SCRIPT_PATTERNS = [
    r'document\.location\s*=', r'window\.location\s*=',
    r'location\.href\s*=', r'location\.replace\s*\(',
    r'document\.cookie\s*=', r'localStorage\.setItem',
    r'sessionStorage\.setItem', r'XMLHttpRequest',
    r'fetch\s*\(.*POST', r'navigator\.sendBeacon'
]

# Form action suspicious patterns
SUSPICIOUS_FORM_ACTIONS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'data:',
    r'javascript:', r'vbscript:', r'mailto:', r'file:',
    r'ftp:', r'about:blank'
]

# Risk scoring weights
RISK_WEIGHTS = {
    'url_length_threshold': 100,
    'url_length_high_threshold': 200,
    'subdomain_threshold': 3,
    'subdomain_high_threshold': 5,
    'redirect_threshold': 3,
    'redirect_high_threshold': 5,
    'external_links_threshold': 20,
    'iframe_threshold': 5,
    'phishing_keywords_threshold': 3,
    'suspicious_scripts_cap': 2,
    'js_obfuscation_threshold': 2
}

# Risk level thresholds
RISK_THRESHOLDS = {
    'low_max': 2,
    'medium_max': 4,
    'high_max': 7,
    'critical_min': 8
} 