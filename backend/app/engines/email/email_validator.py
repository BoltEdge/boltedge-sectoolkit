"""
BoltEdge SecToolkit â€” Email Validator Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_email

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "dispostable.com", "trashmail.com", "mailnesia.com", "maildrop.cc",
    "discard.email", "temp-mail.org", "fakeinbox.com", "mailcatch.com",
    "10minutemail.com", "tempail.com", "harakirimail.com", "getairmail.com",
}
_ROLE_ACCOUNTS = {
    "admin", "administrator", "postmaster", "webmaster", "hostmaster",
    "info", "support", "help", "sales", "billing", "contact",
    "abuse", "noc", "security", "no-reply", "noreply", "mailer-daemon",
    "root", "ftp", "www", "mail", "office", "hr", "jobs",
}
_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com",
    "gmx.com", "gmx.net", "live.com", "msn.com", "me.com",
}

class EmailValidatorEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def validate(self, email: str) -> dict:
        try:
            email = validate_email(email)
            local, domain = email.split("@", 1)
            mx_valid = self._check_mx(domain)
            is_disposable = domain.lower() in _DISPOSABLE_DOMAINS
            is_role = local.lower() in _ROLE_ACCOUNTS
            is_free = domain.lower() in _FREE_PROVIDERS
            issues = []
            if is_disposable: issues.append("Disposable/temporary email domain")
            if not mx_valid["has_mx"]: issues.append("Domain has no MX records")
            if is_role: issues.append("Role-based email account (not personal)")
            score = 100
            if not mx_valid["has_mx"]: score -= 50
            if is_disposable: score -= 40
            if is_role: score -= 10
            return {"email": email, "local_part": local, "domain": domain,
                    "format_valid": True, "mx_valid": mx_valid["has_mx"],
                    "mx_records": mx_valid.get("records", []), "is_disposable": is_disposable,
                    "is_role_account": is_role, "is_free_provider": is_free,
                    "score": max(score, 0), "deliverable": mx_valid["has_mx"] and not is_disposable,
                    "issues": issues}
        except Exception as e: raise EngineError(f"Email validation failed: {str(e)}")

    def _check_mx(self, domain):
        try:
            mx = self.dns.resolve(domain, "MX")
            return {"has_mx": len(mx) > 0, "records": mx}
        except (EngineError, EngineTimeoutError): return {"has_mx": False, "records": []}
