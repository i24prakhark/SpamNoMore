"""
DNS lookup module for checking SPF, DKIM, DMARC, and MX records.
"""
import dns.resolver
import dns.exception
from typing import Optional, Dict, List, Any


class DNSChecker:
    """Handles DNS lookups for email authentication records."""
    
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def check_spf(self) -> Dict[str, Any]:
        """Check SPF record for the domain."""
        try:
            txt_records = self.resolver.resolve(self.domain, 'TXT')
            spf_record = None
            
            for record in txt_records:
                txt_value = record.to_text().strip('"')
                if txt_value.startswith('v=spf1'):
                    spf_record = txt_value
                    break
            
            if spf_record:
                return {
                    'exists': True,
                    'record': spf_record,
                    'valid': self._validate_spf(spf_record)
                }
            else:
                return {
                    'exists': False,
                    'record': None,
                    'valid': False
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {
                'exists': False,
                'record': None,
                'valid': False
            }
    
    def check_dmarc(self) -> Dict[str, Any]:
        """Check DMARC record for the domain."""
        dmarc_domain = f'_dmarc.{self.domain}'
        try:
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_record = None
            
            for record in txt_records:
                txt_value = record.to_text().strip('"')
                if txt_value.startswith('v=DMARC1'):
                    dmarc_record = txt_value
                    break
            
            if dmarc_record:
                policy = self._extract_dmarc_policy(dmarc_record)
                return {
                    'exists': True,
                    'record': dmarc_record,
                    'policy': policy,
                    'valid': policy in ['quarantine', 'reject']
                }
            else:
                return {
                    'exists': False,
                    'record': None,
                    'policy': None,
                    'valid': False
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {
                'exists': False,
                'record': None,
                'policy': None,
                'valid': False
            }
    
    def check_dkim(self, selector: str = 'default') -> Dict[str, Any]:
        """
        Check DKIM record for the domain.
        Note: DKIM requires a selector which varies per organization.
        We'll check common selectors and indicate if setup is needed.
        """
        common_selectors = [selector, 'default', 'google', 'k1', 'selector1', 'selector2']
        found_records = []
        
        for sel in common_selectors:
            dkim_domain = f'{sel}._domainkey.{self.domain}'
            try:
                txt_records = self.resolver.resolve(dkim_domain, 'TXT')
                for record in txt_records:
                    txt_value = record.to_text().strip('"')
                    if 'p=' in txt_value:
                        found_records.append({
                            'selector': sel,
                            'record': txt_value
                        })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
        
        if found_records:
            return {
                'exists': True,
                'records': found_records,
                'valid': True
            }
        else:
            return {
                'exists': False,
                'records': [],
                'valid': False
            }
    
    def check_mx(self) -> Dict[str, Any]:
        """Check MX records for the domain."""
        try:
            mx_records = self.resolver.resolve(self.domain, 'MX')
            mx_list = []
            
            for mx in mx_records:
                mx_list.append({
                    'priority': mx.preference,
                    'server': str(mx.exchange).rstrip('.')
                })
            
            # Sort by priority
            mx_list.sort(key=lambda x: x['priority'])
            
            return {
                'exists': True,
                'records': mx_list,
                'count': len(mx_list),
                'valid': len(mx_list) > 0
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {
                'exists': False,
                'records': [],
                'count': 0,
                'valid': False
            }
    
    def _validate_spf(self, spf_record: str) -> bool:
        """Basic SPF validation."""
        required_elements = ['v=spf1']
        has_all_modifier = any(m in spf_record for m in ['~all', '-all', '+all', '?all'])
        return all(elem in spf_record for elem in required_elements) and has_all_modifier
    
    def _extract_dmarc_policy(self, dmarc_record: str) -> Optional[str]:
        """Extract policy from DMARC record."""
        for part in dmarc_record.split(';'):
            part = part.strip()
            if part.startswith('p='):
                return part.split('=')[1].strip()
        return None
    
    def check_all(self) -> Dict[str, Any]:
        """Perform all DNS checks."""
        return {
            'spf': self.check_spf(),
            'dmarc': self.check_dmarc(),
            'dkim': self.check_dkim(),
            'mx': self.check_mx()
        }
