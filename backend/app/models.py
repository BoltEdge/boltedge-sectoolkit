"""
SecToolkit 101 — Database Models

All SQLAlchemy models for threat feeds, WHOIS history,
breach data, CVEs, and exploits.
"""
from datetime import datetime, timezone
from app import db


# ============================================================
# Threat Feed Models
# ============================================================

class ThreatIP(db.Model):
    """IP addresses from threat intelligence feeds."""
    __tablename__ = "threat_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    confidence = db.Column(db.Integer, nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("ip", "source", name="uq_threat_ip_source"),
        db.Index("ix_threat_ip_source", "ip", "source"),
    )

    def __repr__(self):
        return f"<ThreatIP {self.ip} [{self.source}]>"


class ThreatDomain(db.Model):
    """Domains from threat intelligence feeds."""
    __tablename__ = "threat_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(253), nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("domain", "source", name="uq_threat_domain_source"),
        db.Index("ix_threat_domain_source", "domain", "source"),
    )

    def __repr__(self):
        return f"<ThreatDomain {self.domain} [{self.source}]>"


class ThreatHash(db.Model):
    """Malware hashes from threat intelligence feeds."""
    __tablename__ = "threat_hashes"

    id = db.Column(db.Integer, primary_key=True)
    hash_value = db.Column(db.String(128), nullable=False, index=True)
    hash_type = db.Column(db.String(10), nullable=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True)
    malware_name = db.Column(db.String(255), nullable=True)
    malware_family = db.Column(db.String(100), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("hash_value", "source", name="uq_threat_hash_source"),
        db.Index("ix_threat_hash_source", "hash_value", "source"),
    )

    def __repr__(self):
        return f"<ThreatHash {self.hash_value[:16]}... [{self.source}]>"


class ThreatURL(db.Model):
    """Malicious URLs from threat intelligence feeds."""
    __tablename__ = "threat_urls"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_threat_url_source", "source"),
    )

    def __repr__(self):
        return f"<ThreatURL {self.url[:50]}... [{self.source}]>"


# ============================================================
# WHOIS History
# ============================================================

class WhoisHistory(db.Model):
    """Historical WHOIS snapshots for domains."""
    __tablename__ = "whois_history"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(253), nullable=False, index=True)
    registrar = db.Column(db.String(255), nullable=True)
    nameservers = db.Column(db.Text, nullable=True)
    status = db.Column(db.Text, nullable=True)
    registrant_org = db.Column(db.String(255), nullable=True)
    registrant_country = db.Column(db.String(5), nullable=True)
    creation_date = db.Column(db.DateTime, nullable=True)
    expiration_date = db.Column(db.DateTime, nullable=True)
    updated_date = db.Column(db.DateTime, nullable=True)
    checked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        db.Index("ix_whois_domain_checked", "domain", "checked_at"),
    )

    def __repr__(self):
        return f"<WhoisHistory {self.domain} @ {self.checked_at}>"


# ============================================================
# Breach Data (k-anonymity model)
# ============================================================

class BreachedHash(db.Model):
    """Breached password hash prefixes/suffixes for k-anonymity lookups."""
    __tablename__ = "breached_hashes"

    id = db.Column(db.Integer, primary_key=True)
    prefix = db.Column(db.String(5), nullable=False, index=True)
    suffix = db.Column(db.String(35), nullable=False)
    count = db.Column(db.Integer, default=1)

    __table_args__ = (
        db.UniqueConstraint("prefix", "suffix", name="uq_breach_prefix_suffix"),
        db.Index("ix_breach_prefix", "prefix"),
    )

    def __repr__(self):
        return f"<BreachedHash {self.prefix}...{self.suffix[:8]} count={self.count}>"


# ============================================================
# CVE Database
# ============================================================

class CVE(db.Model):
    """Common Vulnerabilities and Exposures."""
    __tablename__ = "cves"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(100), nullable=True)
    cwe_id = db.Column(db.String(20), nullable=True)
    affected_vendor = db.Column(db.String(255), nullable=True)
    affected_product = db.Column(db.String(255), nullable=True)
    published = db.Column(db.DateTime, nullable=True)
    modified = db.Column(db.DateTime, nullable=True)
    references = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_cve_severity", "severity"),
        db.Index("ix_cve_vendor_product", "affected_vendor", "affected_product"),
    )

    def __repr__(self):
        return f"<CVE {self.cve_id} [{self.severity}]>"


# ============================================================
# Exploit Database
# ============================================================

class Exploit(db.Model):
    """Known exploits from public databases."""
    __tablename__ = "exploits"

    id = db.Column(db.Integer, primary_key=True)
    exploit_id = db.Column(db.String(20), nullable=True, index=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    platform = db.Column(db.String(50), nullable=True)
    exploit_type = db.Column(db.String(50), nullable=True)
    cve_id = db.Column(db.String(20), nullable=True, index=True)
    author = db.Column(db.String(255), nullable=True)
    published = db.Column(db.DateTime, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    source_url = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_exploit_platform", "platform"),
        db.Index("ix_exploit_type", "exploit_type"),
    )

    def __repr__(self):
        return f"<Exploit {self.exploit_id or self.id} - {self.title[:50]}>"


# ============================================================
# Feed Metadata (tracks feed freshness)
# ============================================================

class FeedMetadata(db.Model):
    """Tracks when each threat feed was last updated."""
    __tablename__ = "feed_metadata"

    id = db.Column(db.Integer, primary_key=True)
    feed_name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    feed_type = db.Column(db.String(20), nullable=True)
    last_updated = db.Column(db.DateTime, nullable=True)
    entries_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="pending")
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<FeedMetadata {self.feed_name} [{self.status}]>"