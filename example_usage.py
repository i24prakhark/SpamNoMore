#!/usr/bin/env python3
"""
Example script demonstrating how to use the SpamNoMore API
"""
import requests
import sys


def scan_domain(domain: str, api_url: str = "http://localhost:8000"):
    """
    Scan a domain using the SpamNoMore API
    
    Args:
        domain: Domain to scan (e.g., "example.com")
        api_url: Base URL of the API (default: "http://localhost:8000")
    """
    endpoint = f"{api_url}/api/scan-domain"
    
    payload = {
        "domain": domain
    }
    
    try:
        print(f"Scanning domain: {domain}...")
        response = requests.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        # Print results
        print("\n" + "="*60)
        print(f"Domain: {result['domain']}")
        print(f"Trust Score: {result['trust_percentage']}%")
        print("="*60)
        
        print(f"\n{result['summary']}\n")
        
        # Print score breakdown
        print("Score Breakdown:")
        print("-" * 60)
        for category, score_data in result['scores'].items():
            print(f"\n{category.replace('_', ' ').title()}:")
            print(f"  Score: {score_data['score']}/{score_data['max_score']} ({score_data['percentage']}%)")
            for detail in score_data['details']:
                print(f"  • {detail}")
        
        # Print top suggestions
        if result['top_suggestions']:
            print("\n" + "="*60)
            print("Top Recommendations:")
            print("="*60)
            for i, suggestion in enumerate(result['top_suggestions'], 1):
                print(f"\n{i}. [{suggestion['priority'].upper()}] {suggestion['issue']}")
                print(f"   Action: {suggestion['action']}")
                print(f"   Impact: {suggestion['impact']}")
        
        print("\n")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to API: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python example_usage.py <domain> [api_url]")
        print("\nExample:")
        print("  python example_usage.py google.com")
        print("  python example_usage.py example.org http://api.example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    api_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
    
    scan_domain(domain, api_url)


if __name__ == "__main__":
    main()
