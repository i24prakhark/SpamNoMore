"""
Scoring module for calculating trust scores based on DNS checks and email analysis.
This version emphasizes protocol correctness and realistic weighting.
"""

from typing import Dict, Any, Optional
from app.config import settings


class TrustScorer:
    """Calculates trust scores for email deliverability based on DNS and content analysis."""

    def __init__(self, dns_results: Dict[str, Any], headers: Optional[str] = None, body: Optional[str] = None):
        self.dns_results = dns_results
        self.headers = headers
        self.body = body

    # ---------------- AUTHENTICATION ------------------

    def calculate_authentication_score(self) -> Dict[str, Any]:
        """
        Authentication quality (SPF, DKIM, DMARC)
        Max: 40
        """
        score = 0
        details = []
        max_score = 40

        spf = self.dns_results.get("spf", {})
        dkim = self.dns_results.get("dkim", {})
        dmarc = self.dns_results.get("dmarc", {})

        # SPF (15)
        if spf.get("exists"):
            if spf.get("valid"):
                score += 15
                details.append("SPF correctly configured")
            else:
                score += 8
                details.append("SPF exists but may be malformed")
        else:
            details.append("SPF missing")

        # DKIM (10)
        if dkim.get("exists") and dkim.get("valid"):
            score += 10
            details.append("DKIM signing detected")
        else:
            details.append("DKIM not detected")

        # DMARC (15)
        if dmarc.get("exists"):
            mode = dmarc.get("mode")
            policy = dmarc.get("policy")

            if policy == "reject":
                score += 15
                details.append("DMARC enforcing (reject)")
            elif policy == "quarantine":
                score += 12
                details.append("DMARC enforcing (quarantine)")
            elif mode == "partial-enforcement":
                score += 10
                details.append("DMARC partial enforcement (subdomains protected)")
            elif policy == "none":
                score += 7
                details.append("DMARC monitoring only")
            else:
                score += 4
                details.append("Weak DMARC configuration")
        else:
            details.append("DMARC missing")

        return {
            "score": score,
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 1),
            "details": details
        }

    # ---------------- DOMAIN HEALTH ------------------

    def calculate_domain_health_score(self) -> Dict[str, Any]:
        """
        Structural trust maturity
        Max: 20
        """
        score = 0
        details = []
        max_score = 20

        spf = self.dns_results.get("spf", {}).get("exists")
        dkim = self.dns_results.get("dkim", {}).get("exists")
        dmarc = self.dns_results.get("dmarc", {}).get("exists")
        dmarc_mode = self.dns_results.get("dmarc", {}).get("mode")
        dmarc_policy = self.dns_results.get("dmarc", {}).get("policy")

        complete = all([spf, dkim, dmarc])
        partial = sum([spf, dkim, dmarc])

        # Structural strength
        if complete:
            score += 18   # WAS 15 — now rewards full maturity
            details.append("All authentication layers present (full stack)")
        elif partial == 2:
            score += 12
            details.append("Two authentication layers present")
        elif partial == 1:
            score += 6
            details.append("Single authentication mechanism present")
        else:
            details.append("No authentication detected")

        # DMARC policy strength bonus
        if dmarc_policy in ["reject", "quarantine"]:
            score += 5
            details.append("DMARC fully enforced")
        elif dmarc_mode == "partial-enforcement":
            score += 3
            details.append("DMARC partially enforced (subdomain coverage)")

        # Cap max score explicitly
        score = min(score, max_score)

        return {
            "score": score,
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 1),
            "details": details
        }

    # ---------------- SENDING SETUP ------------------

    def calculate_sending_setup_score(self) -> Dict[str, Any]:
        """
        Infrastructure depth (MX)
        Max: 20
        """
        score = 0
        details = []
        max_score = 20

        mx = self.dns_results.get("mx", {})
        count = mx.get("count", 0)

        if count >= 5:
            score += 20
            details.append(f"Large-scale MX infrastructure detected ({count} servers)")
        elif count >= 2:
            score += 15
            details.append(f"Redundant MX setup ({count} servers)")
        elif count == 1:
            score += 10
            details.append("Single MX server")
        else:
            details.append("No MX records detected")

        return {
            "score": score,
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 1),
            "details": details
        }

    # ---------------- CONTENT RISK ------------------

    def calculate_content_risk_score(self) -> Dict[str, Any]:
        """
        Header / content trust
        Max: 20
        (Weakest pillar intentionally)
        """
        score = 20
        deductions = []
        details = []
        max_score = 20

        # Header inspection
        if self.headers:
            hdr = self.headers.lower()

            def penalize(label, n=4):
                nonlocal score
                score -= n
                deductions.append(label)

            if "spf=fail" in hdr:
                penalize("SPF failed in headers")
            if "dkim=fail" in hdr:
                penalize("DKIM failed in headers")
            if "dmarc=fail" in hdr:
                penalize("DMARC failed in headers")

        # Body inspection
        if self.body:
            body = self.body.lower()
            spam_words = settings.SPAM_KEYWORDS
            matches = [w for w in spam_words if w in body]

            if matches:
                penalty = min(8, len(matches) * 2)
                score -= penalty
                deductions.append(f"{len(matches)} spam indicators")

        if not self.headers and not self.body:
            details.append("No email sample provided")

        if deductions:
            details.append("Content risk factors present")
        else:
            details.append("No content issues detected")

        return {
            "score": max(0, score),
            "max_score": max_score,
            "percentage": round((max(0, score) / max_score) * 100, 1),
            "details": details,
            "risk_factors": deductions
        }

    # ---------------- OVERALL ------------------

    def calculate_overall_score(self) -> Dict[str, Any]:
        """Final trust score (0–100)."""

        auth = self.calculate_authentication_score()
        domain = self.calculate_domain_health_score()
        send = self.calculate_sending_setup_score()
        content = self.calculate_content_risk_score()

        total = auth["score"] + domain["score"] + send["score"] + content["score"]
        max_total = auth["max_score"] + domain["max_score"] + send["max_score"] + content["max_score"]

        return {
            "total_score": total,
            "max_score": max_total,
            "trust_percentage": round((total / max_total) * 100, 1),
            "authentication": auth,
            "domain_health": domain,
            "sending_setup": send,
            "content_risk": content
        }
