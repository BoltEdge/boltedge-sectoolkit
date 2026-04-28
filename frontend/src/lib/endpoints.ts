/**
 * SecToolkit 101 — Endpoint Mapping
 *
 * Maps category + tool ID to Flask backend endpoint.
 * Used by ToolContent.tsx to make real API calls.
 */

const ENDPOINTS: Record<string, Record<string, string>> = {
  ip: {
    "geolocation":       "/ip/geolocation",
    "reputation":        "/ip/reputation",
    "whois":             "/ip/whois",
    "reverse-dns":       "/ip/reverse-dns",
    "asn-lookup":        "/ip/asn",
    "subnet-calculator": "/ip/subnet-calculator",
    "cidr-calculator":   "/ip/cidr-calculator",
    "ip-range-generator":"/ip/range-generator",
    "ptr-lookup":        "/ip/ptr",
    "blacklist-check":   "/ip/blacklist",
    "ip-history":        "/ip/history",
    "port-scanner":      "/ip/port-scan",
    "ping":              "/ip/ping",
    "traceroute":        "/ip/traceroute",
    "vpn-detection":     "/ip/vpn-detection",
  },
  domain: {
    "dns-lookup":        "/domain/dns-lookup",
    "domain-whois":      "/domain/whois",
    "subdomain-finder":  "/domain/subdomains",
    "dns-propagation":   "/domain/propagation",
    "mx-records":        "/domain/mx",
    "ns-records":        "/domain/ns",
    "txt-records":       "/domain/txt",
    "domain-age":        "/domain/age",
    "reverse-ip":        "/domain/reverse-ip",
    "dnssec":            "/domain/dnssec",
    "zone-transfer":     "/domain/zone-transfer",
    "domain-reputation": "/domain/reputation",
  },
  ssl: {
    "certificate-checker": "/ssl/certificate",
    "ssl-grade":           "/ssl/grade",
    "ct-search":           "/ssl/ct",
    "certificate-decoder": "/ssl/decode",
    "certificate-chain":   "/ssl/chain",
    "csr-decoder":         "/ssl/csr",
    "tls-check":           "/ssl/tls-versions",
    "expiry-monitor":      "/ssl/expiry",
  },
  url: {
    "url-scanner":       "/url/scan",
    "screenshot":        "/url/screenshot",
    "tech-stack":        "/url/techstack",
    "redirect-tracer":   "/url/redirects",
    "http-headers":      "/url/headers",
    "robots-txt":        "/url/parse",
    "security-headers":  "/url/headers",
    "link-extractor":    "/url/links",
    "open-redirect":     "/url/redirects",
    "url-unshortener":   "/url/redirects",
  },
  email: {
    "header-analyser":    "/email/headers",
    "spf-check":          "/email/spf",
    "dmarc-check":        "/email/dmarc",
    "dkim-check":         "/email/dkim",
    "email-verification": "/email/validate",
    "email-reputation":   "/email/blacklist",
    "mx-check":           "/email/mx-check",
    "spoofability":       "/email/spoofability",
    "bimi-check":         "/email/bimi",
  },
  hash: {
    "hash-generator":    "/hash/generate",
    "file-hash":         "/hash/generate",
    "hash-compare":      "/hash/compare",
    "md5-lookup":        "/hash/lookup",
    "hash-analyser":     "/hash/identify",
    "hmac-generator":    "/hash/hmac",
    "malware-hash":      "/hash/lookup",
    "threatfox":         "/threat/ioc",
    "urlhaus":           "/threat/ioc",
    "virustotal":        "/external/enrich/hash",
    "threat-feed":       "/threat/ioc",
    "reputation-scorer": "/threat/reputation",
    "ioc-checker":       "/threat/ioc",
  },
  encode: {
    "base64":            "/encode/base64/encode",
    "url-encode":        "/encode/url/encode",
    "html-entities":     "/encode/html/encode",
    "hex-converter":     "/encode/hex/encode",
    "ascii-converter":   "/encode/ascii/to-codes",
    "unicode":           "/encode/unicode/encode",
    "jwt-decoder":       "/encode/jwt/decode",
    "timestamp":         "/encode/string",
    "regex-tester":      "/encode/regex",
    "defang-refang":     "/encode/string",
    "rot13":             "/encode/rot13",
    "case-converter":    "/encode/string",
    "ioc-extractor":     "/encode/regex",
    "string-tools":      "/encode/string",
  },
  network: {
    "bandwidth-calculator": "/network/bandwidth",
    "mac-lookup":           "/network/mac",
    "http2-check":          "/network/http2",
    "performance":          "/network/status",
    "cors-tester":          "/network/status",
    "sitemap-viewer":       "/network/status",
    "whois-server":         "/network/whois-history",
    "status-checker":       "/network/status",
  },
  threat: {
    "ioc-checker":          "/threat/ioc",
    "cve-lookup":           "/threat/cve",
    "mitre-attack":         "/threat/exploit",
    "malware-hash-lookup":  "/threat/ioc",
    "threat-feed-checker":  "/threat/feeds",
    "reputation-scorer":    "/threat/reputation",
    "greynoise":            "/external/enrich/ip",
  },
  password: {
    "password-generator":   "/password/generate",
    "password-strength":    "/password/strength",
    "passphrase-generator": "/password/passphrase",
    "password-hash":        "/hash/bcrypt",
    "breach-check":         "/password/breach",
  },
};


/**
 * Get the Flask API endpoint for a given category + tool ID.
 * Returns the endpoint path (e.g. "/ip/geolocation").
 */
export function getEndpoint(categoryId: string, toolId: string): string {
  const category = ENDPOINTS[categoryId];
  if (!category) {
    console.warn("No endpoints for category:", categoryId);
    return "/health";
  }
  const endpoint = category[toolId];
  if (!endpoint) {
    console.warn("No endpoint for tool:", categoryId, toolId);
    return "/health";
  }
  return endpoint;
}