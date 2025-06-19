#!/usr/bin/env python3
"""
PhishSentry Test Script
Simple test script to demonstrate URL scanning functionality.
"""

import os
import sys
import json
from modules.url_scanner import URLScanner
from modules.reputation_engine import ReputationEngine

def test_url_scan(url):
    """Test URL scanning functionality."""
    print(f"\n{'='*60}")
    print(f"SCANNING URL: {url}")
    print(f"{'='*60}")
    
    try:
        # Initialize scanner and reputation engine
        scanner = URLScanner()
        reputation_engine = ReputationEngine()
        
        print("🔍 Starting URL scan...")
        scan_result = scanner.scan_url(url)
        
        print("📊 Calculating reputation score...")
        reputation_score = reputation_engine.calculate_score(scan_result)
        
        # Print basic results
        print(f"\n📋 SCAN RESULTS:")
        print(f"   URL: {scan_result.get('url', 'N/A')}")
        print(f"   Accessible: {'✅' if scan_result.get('accessible') else '❌'}")
        print(f"   Status Code: {scan_result.get('status_code', 'N/A')}")
        print(f"   Response Time: {scan_result.get('response_time', 0):.2f}s")
        
        # Print reputation score
        risk_level = reputation_score.get('risk_level', 'unknown')
        total_score = reputation_score.get('total_score', 0)
        
        risk_emoji = {
            'low': '🟢',
            'medium': '🟡', 
            'high': '🟠',
            'critical': '🔴'
        }.get(risk_level, '⚪')
        
        print(f"\n🛡️ REPUTATION ASSESSMENT:")
        print(f"   Risk Level: {risk_emoji} {risk_level.upper()}")
        print(f"   Total Score: {total_score:.1f}/10")
        
        # Print threats if any
        threats = reputation_score.get('threats', [])
        if threats:
            print(f"   Threats: {', '.join(threats)}")
        
        # Print pattern threats if any
        pattern_threats = reputation_score.get('pattern_threats', [])
        if pattern_threats:
            print(f"   Pattern Threats: {', '.join(pattern_threats)}")
        
        # Print detailed scores
        print(f"\n📈 SCORE BREAKDOWN:")
        print(f"   Base Score: {reputation_score.get('base_score', 0):.1f}/4")
        print(f"   Content Score: {reputation_score.get('content_score', 0):.1f}/4")
        print(f"   Security Score: {reputation_score.get('security_score', 0):.1f}/2")
        print(f"   Pattern Score: {reputation_score.get('pattern_score', 0):.1f}/4")
        print(f"   VirusTotal Score: {reputation_score.get('virustotal_score', 0):.1f}/4")
        
        # Print pattern analysis if available
        pattern_analysis = scan_result.get('pattern_analysis', {})
        if pattern_analysis:
            print(f"\n🔍 PATTERN ANALYSIS:")
            
            url_patterns = pattern_analysis.get('url_patterns', {})
            if url_patterns:
                print(f"   URL Patterns:")
                for pattern, value in url_patterns.items():
                    if value:
                        if isinstance(value, bool):
                            print(f"     • {pattern.replace('_', ' ').title()}: ⚠️")
                        else:
                            print(f"     • {pattern.replace('_', ' ').title()}: {value}")
            
            content_patterns = pattern_analysis.get('content_patterns', {})
            if content_patterns:
                print(f"   Content Patterns:")
                for pattern, value in content_patterns.items():
                    if value and value > 0:
                        print(f"     • {pattern.replace('_', ' ').title()}: {value}")
        
        # Print content analysis if available
        if scan_result.get('accessible') and scan_result.get('content_analysis'):
            content = scan_result['content_analysis']
            print(f"\n🔍 CONTENT ANALYSIS:")
            print(f"   Title: {content.get('title', 'N/A')[:50]}")
            print(f"   Forms: {'Yes' if content.get('has_forms') else 'No'}")
            print(f"   Login Forms: {content.get('login_forms', 0)}")
            print(f"   External Links: {content.get('external_links', 0)}")
            print(f"   Suspicious Scripts: {content.get('suspicious_scripts', 0)}")
            print(f"   iFrames: {content.get('iframe_count', 0)}")
        
        # Print security indicators
        if scan_result.get('security_indicators'):
            security = scan_result['security_indicators']
            print(f"\n🔒 SECURITY INDICATORS:")
            print(f"   HTTPS: {'✅' if security.get('https') else '❌'}")
            print(f"   Security Headers: {'✅' if security.get('has_security_headers') else '❌'}")
            print(f"   URL Length: {security.get('url_length', 0)} chars")
            print(f"   Subdomains: {security.get('subdomain_count', 0)}")
            if security.get('suspicious_tld'):
                print(f"   Suspicious TLD: ⚠️")
        
        # Print redirects if any
        redirects = scan_result.get('redirects', [])
        if redirects:
            print(f"\n🔄 REDIRECTS ({len(redirects)}):")
            for i, redirect in enumerate(redirects[:3], 1):  # Show first 3
                print(f"   {i}. {redirect.get('status', 'N/A')} → {redirect.get('to', 'N/A')[:60]}")
            if len(redirects) > 3:
                print(f"   ... and {len(redirects) - 3} more")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False

def main():
    """Main test function."""
    print("🛡️  PhishSentry URL Scanner Test")
    print("================================")
    
    # Test URLs - including some potentially suspicious ones for demonstration
    test_urls = [
        "https://google.com",
        "https://github.com",
        "http://example.com",
        "https://stackoverflow.com",
        "https://bit.ly/3example"  # URL shortener example
    ]
    
    # Allow custom URL from command line
    if len(sys.argv) > 1:
        test_urls = [sys.argv[1]]
        print(f"Testing custom URL: {sys.argv[1]}")
    else:
        print("Testing default URLs...")
        print("Usage: python test_scanner.py <url> to test a specific URL")
    
    success_count = 0
    total_count = len(test_urls)
    
    for url in test_urls:
        if test_url_scan(url):
            success_count += 1
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY: {success_count}/{total_count} URLs scanned successfully")
    print(f"{'='*60}")
    
    print(f"\n📝 NOTE: This tool is for educational and security research purposes.")
    print(f"Always verify results with multiple sources and use responsibly.")

if __name__ == "__main__":
    main() 