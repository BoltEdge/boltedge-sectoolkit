"""
BoltEdge SecToolkit - Enrichment Service

Orchestrates multiple external API calls for each target type.
Returns combined results from all available APIs.
Gracefully handles missing API keys and errors.
"""
from datetime import datetime, timezone
from app.services.api_clients import get_client
from app.utils.validators import validate_ip, validate_domain, validate_hash, validate_url, validate_cve


def _safe_call(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as e:
        source_name = "unknown"
        if hasattr(func, '__self__'):
            source_name = func.__self__.__class__.__name__
        return {"error": str(e), "source": source_name}


def enrich_ip(ip):
    ip = validate_ip(ip)
    sources = {}

    vt = get_client("virustotal")
    if vt.available:
        sources["virustotal"] = _safe_call(vt.check_ip, ip)

    abuse = get_client("abuseipdb")
    if abuse.available:
        sources["abuseipdb"] = _safe_call(abuse.check_ip, ip)

    shodan = get_client("shodan")
    if shodan.available:
        sources["shodan"] = _safe_call(shodan.check_ip, ip)

    gn = get_client("greynoise")
    if gn.available:
        sources["greynoise"] = _safe_call(gn.check_ip, ip)

    risk_score = _aggregate_ip_risk(sources)

    return {
        "ip": ip,
        "enriched": True,
        "sources_queried": len(sources),
        "sources_available": list(sources.keys()),
        "aggregate_risk": risk_score,
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_domain(domain):
    domain = validate_domain(domain)
    sources = {}

    vt = get_client("virustotal")
    if vt.available:
        sources["virustotal"] = _safe_call(vt.check_domain, domain)

    return {
        "domain": domain,
        "enriched": True,
        "sources_queried": len(sources),
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_hash(file_hash):
    file_hash = validate_hash(file_hash)
    sources = {}

    vt = get_client("virustotal")
    if vt.available:
        sources["virustotal"] = _safe_call(vt.check_hash, file_hash)

    return {
        "hash": file_hash,
        "enriched": True,
        "sources_queried": len(sources),
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_url(url):
    url = validate_url(url)
    sources = {}

    vt = get_client("virustotal")
    if vt.available:
        sources["virustotal"] = _safe_call(vt.check_url, url)

    return {
        "url": url,
        "enriched": True,
        "sources_queried": len(sources),
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_cve(cve_id):
    cve_id = validate_cve(cve_id)
    sources = {}

    nvd = get_client("nvd")
    if nvd.available:
        sources["nvd"] = _safe_call(nvd.lookup_cve, cve_id)

    return {
        "cve_id": cve_id,
        "enriched": True,
        "sources_queried": len(sources),
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def enrich_password(password):
    sources = {}

    hibp = get_client("hibp")
    if hibp.available:
        sources["hibp"] = _safe_call(hibp.check_password, password)

    return {
        "enriched": True,
        "sources_queried": len(sources),
        "results": sources,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def _aggregate_ip_risk(sources):
    signals = []

    vt = sources.get("virustotal", {})
    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        total = vt.get("total_engines", 1)
        vt_score = min(100, int((malicious / max(total, 1)) * 100)) if malicious else 0
        signals.append({"source": "virustotal", "score": vt_score, "weight": 0.3})

    abuse = sources.get("abuseipdb", {})
    if abuse and not abuse.get("error"):
        abuse_score = abuse.get("abuse_confidence_score", 0)
        signals.append({"source": "abuseipdb", "score": abuse_score, "weight": 0.3})

    shodan_data = sources.get("shodan", {})
    if shodan_data and not shodan_data.get("error"):
        vuln_count = shodan_data.get("vuln_count", 0)
        shodan_score = min(100, vuln_count * 15)
        signals.append({"source": "shodan", "score": shodan_score, "weight": 0.2})

    gn = sources.get("greynoise", {})
    if gn and not gn.get("error"):
        classification = gn.get("classification", "unknown")
        gn_map = {"malicious": 100, "unknown": 30, "benign": 0}
        gn_score = gn_map.get(classification, 30)
        signals.append({"source": "greynoise", "score": gn_score, "weight": 0.2})

    if signals:
        total_weight = sum(s["weight"] for s in signals)
        score = round(sum(s["score"] * s["weight"] for s in signals) / total_weight)
    else:
        score = 0

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "clean"

    return {"score": score, "level": level, "signals": signals}