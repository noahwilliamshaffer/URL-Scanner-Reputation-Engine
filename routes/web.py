from flask import Blueprint, render_template, request, jsonify
from modules.url_scanner import URLScanner
from modules.reputation_engine import ReputationEngine
from modules.scan_history import ScanHistory
import logging

logger = logging.getLogger(__name__)

web_bp = Blueprint('web', __name__)

# Initialize scan history
scan_history = ScanHistory()

@web_bp.route('/')
def index():
    """Main dashboard page."""
    recent_scans = scan_history.get_recent_scans(5)
    stats = scan_history.get_stats()
    return render_template('index.html', recent_scans=recent_scans, stats=stats)

@web_bp.route('/scan', methods=['GET', 'POST'])
def scan_page():
    """URL scanning page with form."""
    if request.method == 'GET':
        return render_template('scan.html')
    
    # Handle POST request from form
    try:
        url = request.form.get('url', '').strip()
        
        if not url:
            return render_template('scan.html', error='URL is required')
        
        # Initialize scanner and reputation engine
        scanner = URLScanner()
        reputation_engine = ReputationEngine()
        
        # Perform scan
        scan_result = scanner.scan_url(url)
        reputation_score = reputation_engine.calculate_score(scan_result)
        
        # Add to scan history
        scan_history.add_scan(url, scan_result, reputation_score)
        
        return render_template('results.html', 
                             url=url,
                             scan_result=scan_result,
                             reputation_score=reputation_score)
        
    except Exception as e:
        logger.error(f"Error in web scan: {str(e)}")
        return render_template('scan.html', error=f'Scan failed: {str(e)}')

@web_bp.route('/history')
def history_page():
    """Scan history page."""
    recent_scans = scan_history.get_recent_scans(20)
    return render_template('history.html', recent_scans=recent_scans) 