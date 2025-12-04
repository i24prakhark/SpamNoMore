"""
DNS lookup module for checking SPF, DKIM, DMARC, and MX records.
"""
import dns.resolver
import dns.exception
from typing import Optional, Dict, List, Any

from app.config import settings


# Domains we NEVER treat like small businesses
ENTERPRISE_DOMAINS = [
    "gmail.com", "google.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"
]

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "mail", "dkim", "email", "smtp", "mx"
]


class DNSChecker:
    """Handles DNS lookups for email authentication records."""

    def __init__(self, domain: str, timeout: Optional[int] = None, lifetime: Optional[int] = None):
        self.domain = domain.lower().strip()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout if timeout is not None else settings.DNS_TIMEOUT
        self.resolver.lifetime = lifetime if lifetime is not None else settings.DNS_LIFETIME

    def is_enterprise_domain(self) -> bool:
        return any(self.domain.endswith(ent) for ent in ENTERPRISE_DOMAINS)

    # ---------------- SPF ------------------

    def check_spf(self) -> Dict[str, Any]:
        """Check SPF record."""

        try:
            txt_records = self.resolver.resolve(self.domain, 'TXT')
            spf_record = None

            for record in txt_records:
                txt_value = record.to_text().strip('"')
                if txt_value.lower().startswith('v=spf1'):
                    spf_record = txt_value
                    break

            if not spf_record:
                return {"exists": False, "record": None, "valid": False, "notes": ["No SPF record found"]}

            return self._evaluate_spf(spf_record)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {"exists": False, "record": None, "valid": False, "notes": ["DNS error while fetching SPF"]}

    def _evaluate_spf(self, record: str) -> Dict[str, Any]:
        result = {"exists": True, "record": record, "valid": True, "notes": []}

        r = record.lower()

        # Must start correctly
        if not r.startswith("v=spf1"):
            result["valid"] = False
            result["notes"].append("Invalid SPF version")
            return result

        # Redirect-based SPF is VALID
        if "redirect=" in r:
            result["notes"].append("Redirect-based SPF detected (valid)")
            return result

        # If no redirect, check terminal policy
        if not any(x in r for x in ["-all", "~all", "?all", "+all"]):
            result["valid"] = False
            result["notes"].append("Missing terminal qualifier (-all, ~all, etc.)")

        return result

    # ---------------- DMARC ------------------

    def check_dmarc(self) -> Dict[str, Any]:
        """Check DMARC record."""

        dmarc_domain = f"_dmarc.{self.domain}"

        try:
            txt_records = self.resolver.resolve(dmarc_domain, "TXT")
            dmarc_record = None

            for record in txt_records:
                txt = record.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                return {"exists": False, "record": None, "policy": None, "mode": "missing", "valid": False}

            return self._interpret_dmarc(dmarc_record)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {"exists": False, "record": None, "policy": None, "mode": "error", "valid": False}

    def _interpret_dmarc(self, record: str) -> Dict[str, Any]:
        r = record.lower()

        result = {
            "exists": True,
            "record": record,
            "policy": None,
            "mode": "unknown",
            "valid": True,
            "notes": []
        }

        def extract(key: str):
            for part in r.split(";"):
                if part.strip().startswith(key + "="):
                    return part.split("=")[1].strip()
            return None

        p = extract("p")
        sp = extract("sp")
        rua = extract("rua")

        result["policy"] = p

        if p == "reject":
            result["mode"] = "strict"
        elif p == "quarantine":
            result["mode"] = "enforcing"
        elif p == "none":
            result["mode"] = "monitoring"
            if rua:
                result["notes"].append("Aggregate reporting enabled")

            if sp in ["reject", "quarantine"]:
                result["mode"] = "partial-enforcement"
                result["notes"].append("Subdomain policy enforced")

        else:
            result["valid"] = False
            result["notes"].append("Invalid DMARC policy")

        return result

    # ---------------- DKIM ------------------

    def check_dkim(self) -> Dict[str, Any]:
        """Check DKIM records"""

        if self.is_enterprise_domain():
            return {
                "exists": True,
                "records": ["Enterprise provider — DKIM is managed automatically"],
                "valid": True,
                "notes": ["Known enterprise provider"]
            }

        found = []

        for selector in COMMON_DKIM_SELECTORS:
            domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = self.resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if "v=dkim1" in txt.lower():
                        found.append({"selector": selector, "record": txt})
            except:
                continue

        if found:
            return {"exists": True, "records": found, "valid": True}
        return {"exists": False, "records": [], "valid": False, "notes": ["No DKIM selectors found"]}

    # ---------------- MX ------------------

    def check_mx(self) -> Dict[str, Any]:
        """Check MX records accurately for inbound mail capability"""

        try:
            answers = self.resolver.resolve(self.domain, 'MX')
            records = []

            # Exact outbound-only MX hosts (not inbound receivers)
            blocked_hosts = {
                "smtp.google.com",
                "smtp.office365.com",
                "smtp.mailgun.org",
                "smtp.sendgrid.net",
                "email-smtp.amazonaws.com"
            }

            for mx in answers:
                server = str(mx.exchange).rstrip(".").lower()

                # Drop ONLY known outbound relay addresses
                if server in blocked_hosts:
                    continue

                records.append({
                    "priority": mx.preference,
                    "server": server
                })

            records.sort(key=lambda x: x["priority"])

            return {
                "exists": len(records) > 0,
                "records": records,
                "count": len(records),
                "valid": len(records) > 0
            }

        except:
            return {"exists": False, "records": [], "count": 0, "valid": False}



    # ---------------- ALL ------------------

    def check_all(self) -> Dict[str, Any]:
        """Run all DNS checks"""

        return {
            "spf": self.check_spf(),
            "dmarc": self.check_dmarc(),
            "dkim": self.check_dkim(),
            "mx": self.check_mx()
        }
