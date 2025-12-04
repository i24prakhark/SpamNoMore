"""
Scoring module for calculating trust scores based on DNS checks and email analysis.
"""
from typing import Dict, Any, Optional, List

from app.config import settings


class TrustScorer:
    """Calculates trust scores for email deliverability."""
    
    def __init__(self, dns_results: Dict[str, Any], headers: Optional[str] = None, body: Optional[str] = None):
        self.dns_results = dns_results
        self.headers = headers
        self.body = body
    
    def calculate_authentication_score(self) -> Dict[str, Any]:
        """
        Calculate authentication score based on SPF, DKIM, and DMARC.
        Max score: 40 points
        """
        score = 0
        max_score = 40
        details = []
        
        # SPF scoring (15 points)
        spf = self.dns_results.get('spf', {})
        if spf.get('exists'):
            if spf.get('valid'):
                score += 15
                details.append('SPF record exists and is properly configured')
            else:
                score += 8
                details.append('SPF record exists but may need optimization')
        else:
            details.append('SPF record is missing')
        
        # DKIM scoring (10 points)
        dkim = self.dns_results.get('dkim', {})
        if dkim.get('exists'):
            score += 10
            details.append('DKIM record(s) found')
        else:
            details.append('DKIM record not found (may require specific selector)')
        
        # DMARC scoring (15 points)
        dmarc = self.dns_results.get('dmarc', {})
        if dmarc.get('exists'):
            policy = dmarc.get('policy')
            if policy == 'reject':
                score += 15
                details.append('DMARC policy set to reject (best practice)')
            elif policy == 'quarantine':
                score += 12
                details.append('DMARC policy set to quarantine (good)')
            else:
                score += 8
                details.append('DMARC policy set to none (needs strengthening)')
        else:
            details.append('DMARC record is missing')
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 1),
            'details': details
        }
    
    def calculate_domain_health_score(self) -> Dict[str, Any]:
        """
        Calculate domain health score.
        Max score: 20 points
        """
        score = 0
        max_score = 20
        details = []
        
        # Check if all authentication methods are present
        spf_exists = self.dns_results.get('spf', {}).get('exists', False)
        dkim_exists = self.dns_results.get('dkim', {}).get('exists', False)
        dmarc_exists = self.dns_results.get('dmarc', {}).get('exists', False)
        
        if spf_exists and dkim_exists and dmarc_exists:
            score += 15
            details.append('All authentication methods configured')
        elif spf_exists and dmarc_exists:
            score += 10
            details.append('SPF and DMARC configured')
        elif spf_exists or dmarc_exists:
            score += 5
            details.append('Partial authentication setup')
        else:
            details.append('Minimal authentication configuration')
        
        # Additional points for strong DMARC
        dmarc = self.dns_results.get('dmarc', {})
        if dmarc.get('policy') in ['quarantine', 'reject']:
            score += 5
            details.append('Strong DMARC policy in place')
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 1),
            'details': details
        }
    
    def calculate_sending_setup_score(self) -> Dict[str, Any]:
        """
        Calculate sending setup score based on MX records.
        Max score: 20 points
        """
        score = 0
        max_score = 20
        details = []
        
        mx = self.dns_results.get('mx', {})
        if mx.get('exists'):
            mx_count = mx.get('count', 0)
            if mx_count >= 2:
                score += 15
                details.append(f'Multiple MX records configured ({mx_count} servers)')
            elif mx_count == 1:
                score += 10
                details.append('Single MX record configured')
            
            # Bonus points for having records
            score += 5
            details.append('MX records properly configured')
        else:
            details.append('No MX records found - cannot receive email')
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 1),
            'details': details
        }
    
    def calculate_content_risk_score(self) -> Dict[str, Any]:
        """
        Calculate content risk score based on headers and body analysis.
        Max score: 20 points
        """
        score = 20  # Start with full score, deduct for issues
        max_score = 20
        details = []
        risk_factors = []
        
        if self.headers:
            # Check for authentication results in headers
            headers_lower = self.headers.lower()
            
            # Check for SPF pass
            if 'spf=pass' in headers_lower:
                details.append('SPF authentication passed in headers')
            elif 'spf=' in headers_lower and 'spf=pass' not in headers_lower:
                score -= 5
                risk_factors.append('SPF authentication issues in headers')
            
            # Check for DKIM pass
            if 'dkim=pass' in headers_lower:
                details.append('DKIM authentication passed in headers')
            elif 'dkim=' in headers_lower and 'dkim=pass' not in headers_lower:
                score -= 5
                risk_factors.append('DKIM authentication issues in headers')
            
            # Check for DMARC pass
            if 'dmarc=pass' in headers_lower:
                details.append('DMARC authentication passed in headers')
            elif 'dmarc=' in headers_lower and 'dmarc=pass' not in headers_lower:
                score -= 5
                risk_factors.append('DMARC authentication issues in headers')
        
        if self.body:
            body_lower = self.body.lower()
            
            # Check for spam indicators using configured keywords
            spam_words = settings.SPAM_KEYWORDS
            found_spam = [word for word in spam_words if word in body_lower]
            
            if found_spam:
                # Cap spam keyword penalty to max 10 points per email to prevent excessive penalties
                deduction = min(len(found_spam) * 2, 10)
                score -= deduction
                risk_factors.append(f'Potential spam keywords detected: {len(found_spam)}')
        
        if not self.headers and not self.body:
            details.append('No email content provided for analysis')
        
        if not risk_factors:
            details.append('No content risk factors detected')
        
        score = max(0, score)  # Ensure score doesn't go negative
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 1),
            'details': details,
            'risk_factors': risk_factors
        }
    
    def calculate_overall_score(self) -> Dict[str, Any]:
        """Calculate overall trust score (0-100)."""
        auth_score = self.calculate_authentication_score()
        domain_score = self.calculate_domain_health_score()
        sending_score = self.calculate_sending_setup_score()
        content_score = self.calculate_content_risk_score()
        
        total_score = (
            auth_score['score'] +
            domain_score['score'] +
            sending_score['score'] +
            content_score['score']
        )
        
        max_total = (
            auth_score['max_score'] +
            domain_score['max_score'] +
            sending_score['max_score'] +
            content_score['max_score']
        )
        
        return {
            'total_score': total_score,
            'max_score': max_total,
            'trust_percentage': round((total_score / max_total) * 100, 1),
            'authentication': auth_score,
            'domain_health': domain_score,
            'sending_setup': sending_score,
            'content_risk': content_score
        }
