from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from config import Config
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enable CORS for API endpoints
    CORS(app)
    
    # Import blueprints (will be created later)
    from routes.api import api_bp
    from routes.web import web_bp
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(web_bp)
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    logger.info("Starting PhishSentry application...")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG']) 