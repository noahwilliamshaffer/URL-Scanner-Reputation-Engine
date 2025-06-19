from flask import Blueprint, request, jsonify
from modules.url_scanner import URLScanner
from modules.reputation_engine import ReputationEngine
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)

@api_bp.route('/scan', methods=['POST'])
def scan_url():
    """Scan a URL for malicious content and return reputation score."""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Initialize scanner and reputation engine
        scanner = URLScanner()
        reputation_engine = ReputationEngine()
        
        # Perform URL scan
        scan_result = scanner.scan_url(url)
        
        # Calculate reputation score
        reputation_score = reputation_engine.calculate_score(scan_result)
        
        # Prepare response
        response = {
            'url': url,
            'scan_result': scan_result,
            'reputation_score': reputation_score,
            'status': 'completed'
        }
        
        logger.info(f"Scan completed for URL: {url}")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error scanning URL: {str(e)}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'PhishSentry'}), 200 