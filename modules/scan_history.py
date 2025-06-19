import json
import time
import os
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class ScanHistory:
    """Simple scan history manager for dashboard functionality."""
    
    def __init__(self):
        self.history_file = 'scan_history.json'
        self.history = self._load_history()
    
    def add_scan(self, url: str, scan_result: Dict, reputation_score: Dict):
        """Add a scan result to history."""
        scan_entry = {
            'timestamp': time.time(),
            'url': url,
            'risk_level': reputation_score.get('risk_level', 'unknown'),
            'total_score': reputation_score.get('total_score', 0),
            'accessible': scan_result.get('accessible', False),
            'status_code': scan_result.get('status_code'),
            'threats': reputation_score.get('threats', []),
            'response_time': scan_result.get('response_time', 0)
        }
        
        # Add to beginning of list
        self.history.insert(0, scan_entry)
        
        # Keep only max_history items
        if len(self.history) > 100:
            self.history = self.history[:100]
        
        self._save_history()
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent scans for dashboard."""
        return self.history[:limit]
    
    def get_stats(self) -> Dict:
        """Get statistics for dashboard."""
        if not self.history:
            return {
                'total_scans': 0,
                'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'avg_response_time': 0,
                'top_threats': []
            }
        
        stats = {
            'total_scans': len(self.history),
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'avg_response_time': 0,
            'top_threats': []
        }
        
        # Calculate risk distribution
        for scan in self.history:
            risk_level = scan.get('risk_level', 'unknown')
            if risk_level in stats['risk_distribution']:
                stats['risk_distribution'][risk_level] += 1
        
        # Calculate average response time
        response_times = [scan.get('response_time', 0) for scan in self.history if scan.get('response_time')]
        if response_times:
            stats['avg_response_time'] = sum(response_times) / len(response_times)
        
        # Count threats
        threat_counts = {}
        for scan in self.history:
            for threat in scan.get('threats', []):
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        # Get top 5 threats
        stats['top_threats'] = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return stats
    
    def clear_history(self):
        """Clear all scan history."""
        self.history = []
        self._save_history()
    
    def _load_history(self) -> List[Dict]:
        """Load history from file."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load scan history: {e}")
        return []
    
    def _save_history(self):
        """Save history to file."""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save scan history: {e}") 