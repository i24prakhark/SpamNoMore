"""
Actions module for generating intelligent, contextual suggestions.
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

        # High-level domain maturity detection
        enterprise_like = self._is_enterprise_like()

        # SPF
        self._check_spf_suggestions()

        # DKIM
        self._check_dkim_suggestions(enterprise_like)

        # DMARC
        self._check_dmarc_suggestions(enterprise_like)

        # MX
        self._check_mx_suggestions()

        # Content
        self._check_content_suggestions()

        # Sort suggestions by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.suggestions.sort(key=lambda x: priority_order.get(x['priority'], 99))

        return self.suggestions

    # ---------------- INTELLIGENCE ----------------

    def _is_enterprise_like(self) -> bool:
        """Detect if domain behaves like an enterprise-scale provider"""
        mx = self.dns_results.get("mx", {})
        dmarc = self.dns_results.get("dmarc", {})
        dkim = self.dns_results.get("dkim", {})

        mx_count = mx.get("count", 0)
        dmarc_mode = dmarc.get("mode")
        dkim_ok = dkim.get("valid")

        # Enterprise = large infra + DKIM + policy nuance
        return mx_count >= 4 and dkim_ok and dmarc_mode in ["partial-enforcement", "enforcing", "strict"]

    # ---------------- SPF ----------------

    def _check_spf_suggestions(self):
        spf = self.dns_results.get("spf", {})

        if not spf.get("exists"):
            self.suggestions.append({
                "priority": "critical",
                "category": "SPF",
                "issue": "No SPF record found",
                "action": "Add an SPF record to your domain",
                "details": "SPF prevents senders from spoofing your domain. Add a DNS TXT record like: v=spf1 include:_spf.google.com ~all",
                "impact": "High — Missing SPF reduces inbox trust"
            })

        elif not spf.get("valid"):
            self.suggestions.append({
                "priority": "high",
                "category": "SPF",
                "issue": "SPF is configured incorrectly",
                "action": "Fix your SPF configuration",
                "details": f"Current record: {spf.get('record')}. Ensure redirect, includes and terminal policy are valid.",
                "impact": "Medium — Broken SPF causes authentication failures"
            })

    # ---------------- DKIM ----------------

    def _check_dkim_suggestions(self, enterprise: bool):
        dkim = self.dns_results.get("dkim", {})

        if not dkim.get("exists"):

            if enterprise:
                self.suggestions.append({
                    "priority": "info",
                    "category": "DKIM",
                    "issue": "DKIM not publicly discoverable",
                    "action": "No action needed",
                    "details": "Enterprise providers may hide selectors intentionally. Authentication is managed internally.",
                    "impact": "None"
                })
            else:
                self.suggestions.append({
                    "priority": "high",
                    "category": "DKIM",
                    "issue": "No DKIM records found",
                    "action": "Enable DKIM signing",
                    "details": "Configure DKIM inside your email provider (Google Workspace, Outlook, etc.)",
                    "impact": "High — Missing DKIM hurts sender identity "
                })

    # ---------------- DMARC ----------------

    def _check_dmarc_suggestions(self, enterprise: bool):
        dmarc = self.dns_results.get("dmarc", {})
        policy = dmarc.get("policy")
        mode = dmarc.get("mode")

        if not dmarc.get("exists"):
            self.suggestions.append({
                "priority": "critical",
                "category": "DMARC",
                "issue": "No DMARC policy found",
                "action": "Add DMARC record",
                "details": "DMARC protects your domain from spoofing. Recommended: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
                "impact": "Critical — Missing DMARC breaks protection"
            })

        elif policy == "none":

            if enterprise and mode == "partial-enforcement":
                self.suggestions.append({
                    "priority": "info",
                    "category": "DMARC",
                    "issue": "DMARC in monitoring mode",
                    "action": "No change recommended",
                    "details": "This configuration is common in enterprise environments for observability and staged enforcement.",
                    "impact": "None"
                })
            else:
                self.suggestions.append({
                    "priority": "medium",
                    "category": "DMARC",
                    "issue": "DMARC policy not enforcing",
                    "action": "Move to quarantine or reject",
                    "details": f"Current DMARC: {dmarc.get('record')}. Enforcing policy improves security and trust.",
                    "impact": "Medium — Enables domain-level protection"
                })

        elif policy in ["quarantine", "reject"] and enterprise:
            self.suggestions.append({
                "priority": "info",
                "category": "DMARC",
                "issue": "DMARC policy enforced",
                "action": "No action needed",
                "details": "This policy provides strong domain protection.",
                "impact": "None"
            })

    # ---------------- MX ----------------

    def _check_mx_suggestions(self):
        mx = self.dns_results.get("mx", {})
        count = mx.get("count", 0)

        if not mx.get("exists"):
            self.suggestions.append({
                "priority": "critical",
                "category": "MX",
                "issue": "No MX records found",
                "action": "Set MX records",
                "details": "MX records enable incoming email delivery.",
                "impact": "Critical — Cannot receive email"
            })

        elif count == 1:
            self.suggestions.append({
                "priority": "low",
                "category": "MX",
                "issue": "Single MX server",
                "action": "Add backup MX",
                "details": "Adding redundancy improves reliability.",
                "impact": "Low"
            })

    # ---------------- CONTENT ----------------

    def _check_content_suggestions(self):
        content = self.scores.get("content_risk", {})
        risks = content.get("risk_factors", [])

        if risks:
            self.suggestions.append({
                "priority": "medium",
                "category": "Email Content",
                "issue": "Content risk signals detected",
                "action": "Review email wording and links",
                "details": ", ".join(risks),
                "impact": "Medium — Content impacts inbox placement"
            })

    # ---------------- OUTPUT ----------------

    def get_top_suggestions(self, limit: int = 5) -> List[Dict[str, Any]]:
        if not self.suggestions:
            self.generate_suggestions()
        return self.suggestions[:limit]
