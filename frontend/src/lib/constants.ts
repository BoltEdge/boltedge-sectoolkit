export interface Tool {
  id: string;
  name: string;
  description: string;
  inputType: "ip" | "domain" | "url" | "email" | "hash" | "text" | "file" | "none";
  inputLabel?: string;
  inputPlaceholder?: string;
}

export interface ToolCategory {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  tools: Tool[];
}

export const categories: ToolCategory[] = [
  {
    id: "ip", name: "IP", description: "IP address analysis, geolocation, reputation, and scanning",
    icon: "Globe", color: "#d97706",
    tools: [
      { id: "geolocation", name: "IP Geolocation", description: "Locate IP addresses with detailed geographic information", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "reputation", name: "IP Reputation", description: "Check IP reputation across threat feeds", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "whois", name: "IP WHOIS", description: "Query IP registration and ownership details", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "reverse-dns", name: "Reverse DNS", description: "Perform reverse DNS lookup on IP addresses", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "asn-lookup", name: "ASN Lookup", description: "Lookup autonomous system information", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter asn lookup target..." },
      { id: "subnet-calculator", name: "Subnet Calculator", description: "Calculate IP subnets and network ranges", inputType: "text", inputLabel: "CIDR / Subnet", inputPlaceholder: "Enter CIDR notation (e.g. 192.168.1.0/24)..." },
      { id: "cidr-calculator", name: "CIDR Calculator", description: "Convert between CIDR and subnet masks", inputType: "text", inputLabel: "CIDR / Mask", inputPlaceholder: "Enter CIDR or subnet mask..." },
      { id: "ip-range-generator", name: "IP Range Generator", description: "Generate IP address ranges from CIDR", inputType: "text", inputLabel: "CIDR", inputPlaceholder: "Enter CIDR notation..." },
      { id: "ptr-lookup", name: "PTR Lookup", description: "Query PTR records for IP addresses", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "blacklist-check", name: "Blacklist Check", description: "Check if IP is on email blacklists", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "ip-history", name: "IP History", description: "View historical DNS records for IP", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "port-scanner", name: "Port Scanner", description: "Scan common ports on target IP", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "ping", name: "Ping Test", description: "Test network connectivity to IP address", inputType: "ip", inputLabel: "Target", inputPlaceholder: "Enter IP address or hostname..." },
      { id: "traceroute", name: "Traceroute", description: "Trace network path to destination", inputType: "ip", inputLabel: "Target", inputPlaceholder: "Enter IP address or hostname..." },
      { id: "vpn-detection", name: "VPN Detection", description: "Detect VPN, proxy, and Tor usage", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
    ],
  },
  {
    id: "domain", name: "Domain", description: "DNS lookups, WHOIS, subdomain discovery, and domain analysis",
    icon: "Globe2", color: "#06b6d4",
    tools: [
      { id: "dns-lookup", name: "DNS Lookup", description: "Query DNS records for any domain", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "domain-whois", name: "Domain WHOIS", description: "Query domain registration details", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "subdomain-finder", name: "Subdomain Finder", description: "Discover subdomains for a domain", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "dns-propagation", name: "DNS Propagation", description: "Check DNS propagation across global resolvers", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "mx-records", name: "MX Records", description: "Look up mail exchange records", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "ns-records", name: "NS Records", description: "Look up nameserver records", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "txt-records", name: "TXT Records", description: "Look up TXT records", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "domain-age", name: "Domain Age", description: "Check when a domain was registered", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "reverse-ip", name: "Reverse IP", description: "Find domains hosted on the same IP", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
      { id: "dnssec", name: "DNSSEC Validator", description: "Validate DNSSEC configuration", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "zone-transfer", name: "Zone Transfer", description: "Test for DNS zone transfer vulnerability", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "domain-reputation", name: "Domain Reputation", description: "Check domain against threat intel feeds", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
    ],
  },
  {
    id: "ssl", name: "SSL", description: "SSL/TLS certificate inspection, grading, and monitoring",
    icon: "Lock", color: "#22c55e",
    tools: [
      { id: "certificate-checker", name: "SSL Certificate Checker", description: "Inspect SSL/TLS certificate details", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "ssl-grade", name: "SSL Labs Test", description: "Grade SSL/TLS configuration", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "ct-search", name: "Certificate Transparency", description: "Search certificate transparency logs", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "certificate-decoder", name: "Certificate Decoder", description: "Decode and display certificate contents", inputType: "text", inputLabel: "Certificate (PEM)", inputPlaceholder: "Paste PEM certificate..." },
      { id: "certificate-chain", name: "Certificate Chain", description: "Validate the full certificate chain", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "csr-decoder", name: "CSR Decoder", description: "Decode certificate signing request", inputType: "text", inputLabel: "CSR (PEM)", inputPlaceholder: "Paste CSR..." },
      { id: "tls-check", name: "TLS Version Check", description: "Check supported TLS versions and ciphers", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "expiry-monitor", name: "Expiry Monitor", description: "Check certificate expiry date", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
    ],
  },
  {
    id: "url", name: "URL", description: "URL analysis, screenshots, tech detection, and security scanning",
    icon: "Link", color: "#a855f7",
    tools: [
      { id: "url-scanner", name: "URL Scanner", description: "Scan URL for threats and reputation", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "screenshot", name: "Website Screenshot", description: "Capture screenshot of any website", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "tech-stack", name: "Tech Stack Detector", description: "Identify technologies used by a website", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "redirect-tracer", name: "Redirect Tracer", description: "Follow and trace URL redirects", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "http-headers", name: "HTTP Headers", description: "Inspect HTTP response headers", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "robots-txt", name: "Robots.txt Viewer", description: "Fetch and display robots.txt", inputType: "url", inputLabel: "Domain / URL", inputPlaceholder: "Enter domain or URL..." },
      { id: "security-headers", name: "Security Headers", description: "Grade security header configuration", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "link-extractor", name: "Link Extractor", description: "Extract all links from a webpage", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "open-redirect", name: "Open Redirect Check", description: "Test for open redirect vulnerability", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "url-unshortener", name: "URL Unshortener", description: "Expand shortened URLs", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter shortened URL..." },
    ],
  },
  {
    id: "email", name: "Email", description: "Email authentication, header analysis, and spoofability testing",
    icon: "Mail", color: "#d97706",
    tools: [
      { id: "header-analyser", name: "Email Header Analyzer", description: "Parse and analyse email headers", inputType: "text", inputLabel: "Email Headers", inputPlaceholder: "Paste email headers..." },
      { id: "spf-check", name: "SPF Checker", description: "Validate SPF record configuration", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "dmarc-check", name: "DMARC Checker", description: "Validate DMARC record and policy", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "dkim-check", name: "DKIM Validator", description: "Validate DKIM record configuration", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "email-verification", name: "Email Verification", description: "Verify email address deliverability", inputType: "email", inputLabel: "Email Address", inputPlaceholder: "Enter email address..." },
      { id: "email-reputation", name: "Email Reputation", description: "Check email domain reputation", inputType: "email", inputLabel: "Email Address", inputPlaceholder: "Enter email address..." },
      { id: "mx-check", name: "MX Check", description: "Verify MX record and mail server connectivity", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "spoofability", name: "Spoofability Test", description: "Score how spoofable a domain's email is", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "bimi-check", name: "BIMI Check", description: "Validate BIMI record configuration", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
    ],
  },
  {
    id: "hash", name: "Hash", description: "Hash generation, comparison, analysis, and malware lookups",
    icon: "Hash", color: "#ef4444",
    tools: [
      { id: "hash-generator", name: "Hash Generator", description: "Generate MD5, SHA-1, SHA-256 hashes", inputType: "text", inputLabel: "Input Text", inputPlaceholder: "Enter text to hash..." },
      { id: "file-hash", name: "File Hash", description: "Calculate hash of uploaded file", inputType: "file", inputLabel: "File" },
      { id: "hash-compare", name: "Hash Compare", description: "Compare two hash values", inputType: "text", inputLabel: "Hash 1", inputPlaceholder: "Enter first hash..." },
      { id: "md5-lookup", name: "MD5 Lookup", description: "Look up MD5 hash in threat databases", inputType: "hash", inputLabel: "MD5 Hash", inputPlaceholder: "Enter MD5 hash..." },
      { id: "hash-analyser", name: "Hash Analyzer", description: "Identify hash type and properties", inputType: "hash", inputLabel: "Hash", inputPlaceholder: "Enter hash value..." },
      { id: "hmac-generator", name: "HMAC Generator", description: "Generate HMAC with various algorithms", inputType: "text", inputLabel: "Message", inputPlaceholder: "Enter message..." },
      { id: "malware-hash", name: "Malware Hash Lookup", description: "Check hash against malware databases", inputType: "hash", inputLabel: "Hash", inputPlaceholder: "Enter file hash..." },
      { id: "threatfox", name: "ThreatFox Lookup", description: "Search ThreatFox IOC database", inputType: "text", inputLabel: "IOC", inputPlaceholder: "Enter IOC..." },
      { id: "urlhaus", name: "URLhaus Check", description: "Check URL against URLhaus database", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "virustotal", name: "VirusTotal Lookup", description: "Query VirusTotal for file/URL analysis", inputType: "hash", inputLabel: "Target", inputPlaceholder: "Enter hash, URL, or domain..." },
      { id: "threat-feed", name: "Threat Feed Checker", description: "Check against aggregated threat feeds", inputType: "text", inputLabel: "IOC", inputPlaceholder: "Enter IP, domain, or hash..." },
      { id: "reputation-scorer", name: "Reputation Scorer", description: "Calculate reputation score from multiple sources", inputType: "text", inputLabel: "Target", inputPlaceholder: "Enter IP, domain, or hash..." },
      { id: "ioc-checker", name: "IOC Checker", description: "Bulk check indicators of compromise", inputType: "text", inputLabel: "IOCs", inputPlaceholder: "Enter IOCs (one per line)..." },
    ],
  },
  {
    id: "encode", name: "Encode", description: "Encoding, decoding, conversion, and text transformation tools",
    icon: "Code", color: "#3b82f6",
    tools: [
      { id: "base64", name: "Base64", description: "Encode and decode Base64 strings", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text to encode/decode..." },
      { id: "url-encode", name: "URL Encode", description: "Encode and decode URL components", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "html-entities", name: "HTML Entities", description: "Encode and decode HTML entities", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "hex-converter", name: "Hex Converter", description: "Convert between hex, ASCII, and binary", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter value..." },
      { id: "ascii-converter", name: "ASCII Converter", description: "Convert between ASCII and character codes", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "unicode", name: "Unicode Converter", description: "Encode and decode Unicode escape sequences", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "jwt-decoder", name: "JWT Decoder", description: "Decode and inspect JSON Web Tokens", inputType: "text", inputLabel: "JWT Token", inputPlaceholder: "Paste JWT token..." },
      { id: "timestamp", name: "Timestamp Converter", description: "Convert Unix timestamps to human dates", inputType: "text", inputLabel: "Timestamp", inputPlaceholder: "Enter Unix timestamp..." },
      { id: "regex-tester", name: "Regex Tester", description: "Test regular expressions with live matching", inputType: "text", inputLabel: "Pattern", inputPlaceholder: "Enter regex pattern..." },
      { id: "defang-refang", name: "Defang/Refang", description: "Defang and refang IOC indicators", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter IOCs..." },
      { id: "rot13", name: "ROT13", description: "Apply ROT13 cipher transformation", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "case-converter", name: "Case Converter", description: "Convert text between cases", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
      { id: "ioc-extractor", name: "IOC Extractor", description: "Extract IPs, domains, hashes from text", inputType: "text", inputLabel: "Input Text", inputPlaceholder: "Paste text containing IOCs..." },
      { id: "string-tools", name: "String Tools", description: "Reverse, count, and transform strings", inputType: "text", inputLabel: "Input", inputPlaceholder: "Enter text..." },
    ],
  },
  {
    id: "network", name: "Network", description: "Network utilities, calculators, and connectivity testing",
    icon: "Wifi", color: "#ec4899",
    tools: [
      { id: "bandwidth-calculator", name: "Bandwidth Calculator", description: "Calculate bandwidth and transfer times", inputType: "text", inputLabel: "File Size", inputPlaceholder: "Enter file size..." },
      { id: "mac-lookup", name: "MAC Lookup", description: "Identify vendor from MAC address", inputType: "text", inputLabel: "MAC Address", inputPlaceholder: "Enter MAC address..." },
      { id: "http2-check", name: "HTTP/2 Check", description: "Test HTTP/2 protocol support", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "performance", name: "Performance Test", description: "Measure DNS, TLS, and TTFB timing", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "cors-tester", name: "CORS Tester", description: "Test CORS policy configuration", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
      { id: "sitemap-viewer", name: "Sitemap Viewer", description: "Fetch and parse sitemap.xml", inputType: "domain", inputLabel: "Domain", inputPlaceholder: "Enter domain name..." },
      { id: "whois-server", name: "WHOIS Server", description: "Direct WHOIS server query", inputType: "text", inputLabel: "Target", inputPlaceholder: "Enter domain or IP..." },
      { id: "status-checker", name: "Status Checker", description: "Check if a website is up or down", inputType: "url", inputLabel: "URL", inputPlaceholder: "Enter URL..." },
    ],
  },
  {
    id: "threat", name: "Threat", description: "Threat intelligence, CVE lookups, and MITRE ATT&CK mapping",
    icon: "Shield", color: "#f97316",
    tools: [
      { id: "ioc-checker", name: "IOC Checker", description: "Check indicators against threat feeds", inputType: "text", inputLabel: "IOC", inputPlaceholder: "Enter IP, domain, or hash..." },
      { id: "cve-lookup", name: "CVE Lookup", description: "Search the CVE vulnerability database", inputType: "text", inputLabel: "CVE ID", inputPlaceholder: "Enter CVE ID (e.g. CVE-2024-1234)..." },
      { id: "mitre-attack", name: "MITRE ATT&CK", description: "Search MITRE ATT&CK techniques", inputType: "text", inputLabel: "Search", inputPlaceholder: "Enter technique ID or keyword..." },
      { id: "malware-hash-lookup", name: "Malware Hash Lookup", description: "Check hash against malware databases", inputType: "hash", inputLabel: "Hash", inputPlaceholder: "Enter file hash..." },
      { id: "threat-feed-checker", name: "Threat Feed Checker", description: "Check against aggregated threat feeds", inputType: "text", inputLabel: "Target", inputPlaceholder: "Enter IP, domain, or hash..." },
      { id: "reputation-scorer", name: "Reputation Scorer", description: "Multi-source reputation score", inputType: "text", inputLabel: "Target", inputPlaceholder: "Enter target..." },
      { id: "greynoise", name: "GreyNoise Check", description: "Check IP against GreyNoise", inputType: "ip", inputLabel: "IP Address", inputPlaceholder: "Enter IP address..." },
    ],
  },
  {
    id: "password", name: "Password", description: "Password generation, strength testing, and hash utilities",
    icon: "KeyRound", color: "#8b5cf6",
    tools: [
      { id: "password-generator", name: "Password Generator", description: "Generate secure random passwords", inputType: "none" },
      { id: "password-strength", name: "Password Strength", description: "Analyse password strength and entropy", inputType: "text", inputLabel: "Password", inputPlaceholder: "Enter password to test..." },
      { id: "passphrase-generator", name: "Passphrase Generator", description: "Generate memorable passphrases", inputType: "none" },
      { id: "password-hash", name: "Password Hash", description: "Generate bcrypt, argon2, or SHA hashes", inputType: "text", inputLabel: "Password", inputPlaceholder: "Enter password..." },
      { id: "breach-check", name: "Password Breach Check", description: "Check if password appears in breaches", inputType: "text", inputLabel: "Password", inputPlaceholder: "Enter password..." },
    ],
  },
];

export function getCategoryById(id: string) { return categories.find(c => c.id === id); }
export function getToolById(categoryId: string, toolId: string) { return getCategoryById(categoryId)?.tools.find(t => t.id === toolId); }
export function getTotalToolCount() { return categories.reduce((s, c) => s + c.tools.length, 0); }
