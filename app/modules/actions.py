"""
Actions module for generating actionable fix suggestions.
"""
from typing import List, Dict, Any


class ActionGenerator:
    """Generates prioritized fix suggestions based on scan results."""
    
    def __init__(self, dns_results: Dict[str, Any], scores: Dict[str, Any]):
        self.dns_results = dns_results
        self.scores = scores
        self.suggestions = []
    
    def generate_suggestions(self) -> List[Dict[str, Any]]:
        """Generate prioritized list of fix suggestions."""
        self.suggestions = []
        
        # Check SPF
        self._check_spf_suggestions()
        
        # Check DKIM
        self._check_dkim_suggestions()
        
        # Check DMARC
        self._check_dmarc_suggestions()
        
        # Check MX
        self._check_mx_suggestions()
        
        # Check content issues
        self._check_content_suggestions()
        
        # Sort by priority (critical, high, medium, low)
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.suggestions.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return self.suggestions
    
    def _check_spf_suggestions(self):
        """Generate SPF-related suggestions."""
        spf = self.dns_results.get('spf', {})
        
        if not spf.get('exists'):
            self.suggestions.append({
                'priority': 'critical',
                'category': 'SPF',
                'issue': 'No SPF record found',
                'action': 'Add an SPF record to your domain DNS settings',
                'details': 'SPF (Sender Policy Framework) helps prevent email spoofing. Add a TXT record like: "v=spf1 include:_spf.google.com ~all"',
                'impact': 'High - Missing SPF significantly reduces email deliverability'
            })
        elif not spf.get('valid'):
            self.suggestions.append({
                'priority': 'high',
                'category': 'SPF',
                'issue': 'SPF record exists but may be improperly configured',
                'action': 'Review and update your SPF record',
                'details': f'Current SPF: {spf.get("record")}. Ensure it ends with -all or ~all and includes all sending sources.',
                'impact': 'Medium - Improper SPF configuration may cause delivery issues'
            })
    
    def _check_dkim_suggestions(self):
        """Generate DKIM-related suggestions."""
        dkim = self.dns_results.get('dkim', {})
        
        if not dkim.get('exists'):
            self.suggestions.append({
                'priority': 'high',
                'category': 'DKIM',
                'issue': 'No DKIM records found',
                'action': 'Set up DKIM signing for your domain',
                'details': 'DKIM adds a digital signature to your emails. Configure DKIM through your email service provider (e.g., Google Workspace, Microsoft 365).',
                'impact': 'High - DKIM is essential for email authentication'
            })
    
    def _check_dmarc_suggestions(self):
        """Generate DMARC-related suggestions."""
        dmarc = self.dns_results.get('dmarc', {})
        
        if not dmarc.get('exists'):
            self.suggestions.append({
                'priority': 'critical',
                'category': 'DMARC',
                'issue': 'No DMARC record found',
                'action': 'Add a DMARC record to your domain',
                'details': 'DMARC tells receiving servers what to do with emails that fail SPF/DKIM. Add a TXT record at _dmarc.yourdomain.com like: "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
                'impact': 'Critical - DMARC is required by major email providers'
            })
        elif dmarc.get('policy') == 'none':
            self.suggestions.append({
                'priority': 'medium',
                'category': 'DMARC',
                'issue': 'DMARC policy set to "none"',
                'action': 'Strengthen DMARC policy to "quarantine" or "reject"',
                'details': f'Current DMARC: {dmarc.get("record")}. Change p=none to p=quarantine or p=reject for better protection.',
                'impact': 'Medium - Weak DMARC policy provides minimal protection'
            })
    
    def _check_mx_suggestions(self):
        """Generate MX-related suggestions."""
        mx = self.dns_results.get('mx', {})
        
        if not mx.get('exists'):
            self.suggestions.append({
                'priority': 'critical',
                'category': 'MX Records',
                'issue': 'No MX records found',
                'action': 'Add MX records to receive emails',
                'details': 'MX records tell other mail servers where to deliver emails for your domain. Configure MX records through your DNS provider.',
                'impact': 'Critical - Cannot receive emails without MX records'
            })
        elif mx.get('count', 0) == 1:
            self.suggestions.append({
                'priority': 'low',
                'category': 'MX Records',
                'issue': 'Only one MX record configured',
                'action': 'Consider adding backup MX records',
                'details': 'Multiple MX records provide redundancy. Add a secondary MX server with higher priority number.',
                'impact': 'Low - Improves reliability but not critical'
            })
    
    def _check_content_suggestions(self):
        """Generate content-related suggestions."""
        content_score = self.scores.get('content_risk', {})
        risk_factors = content_score.get('risk_factors', [])
        
        if risk_factors:
            self.suggestions.append({
                'priority': 'medium',
                'category': 'Email Content',
                'issue': 'Potential content issues detected',
                'action': 'Review email content for spam indicators',
                'details': f'Issues found: {", ".join(risk_factors)}. Avoid spam trigger words and ensure proper authentication.',
                'impact': 'Medium - Content issues can trigger spam filters'
            })
    
    def get_top_suggestions(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top N prioritized suggestions."""
        if not self.suggestions:
            self.generate_suggestions()
        return self.suggestions[:limit]
