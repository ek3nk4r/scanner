# Bug Bounty Hunting Plan: clearme.com

> **⚠️ IMPORTANT**: Only execute this plan if you have explicit authorization through an official bug bounty program. Unauthorized security testing is illegal.

## Target Overview

**Target**: clearme.com  
**Industry**: Identity verification / Airport security clearance  
**Known Program**: Clearme.com has had bug bounty programs in the past - verify current status on:
- HackerOne
- Bugcrowd
- Intigriti
- Their security.txt file at `https://clearme.com/.well-known/security.txt`

---

## Phase 1: Reconnaissance & Information Gathering

### 1.1 Program Verification
```bash
# Check for security.txt
curl -s https://clearme.com/.well-known/security.txt

# Check for bug bounty program listings
# Visit: hackerone.com, bugcrowd.com, intigriti.com
```

### 1.2 Subdomain Enumeration
```bash
# Using multiple tools for comprehensive coverage
subfinder -d clearme.com -silent -o subdomains.txt
assetfinder --subs-only clearme.com >> subdomains.txt
amass enum -passive -d clearme.com >> subdomains.txt

# Remove duplicates
sort -u subdomains.txt -o subdomains.txt
```

### 1.3 Live Host Detection
```bash
# Check which subdomains are alive
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o live_hosts.txt
```

### 1.4 Technology Fingerprinting
```bash
# Identify technologies in use
wappalyzer -u https://clearme.com
whatweb https://clearme.com
```

---

## Phase 2: Content Discovery

### 2.1 URL Collection with HaxShadow
```bash
# Use the existing HaxShadow tool
./HaxShadow.sh -f https://clearme.com
```

This will:
- Fetch URLs from gau (AlienVault, CommonCrawl, Wayback)
- Filter URLs with query parameters
- Validate live endpoints with httpx

### 2.2 Directory/Endpoint Discovery
```bash
# Directory bruteforcing on main domain
ffuf -u https://clearme.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,403

# Recursive directory discovery
feroxbuster -u https://clearme.com -x html,php,asp,aspx,jsp
```

### 2.3 JavaScript Analysis
```bash
# Extract and analyze JavaScript files
cat live_hosts.txt | gospider -o js_output
# Look for:
# - API endpoints
# - Hidden parameters
# - Secrets/keys
# - Debug endpoints
```

---

## Phase 3: Vulnerability Scanning

### 3.1 XSS Testing with HaxShadow
```bash
# XSS scanning mode
./HaxShadow.sh -x https://clearme.com

# Or fast mode for quick results
./HaxShadow.sh -s https://clearme.com
```

Tools used:
- XSStrike (advanced XSS fuzzer)
- Dalfox (context-aware XSS scanner)

### 3.2 Nuclei Comprehensive Scan
```bash
# Full nuclei scan with HaxShadow
./HaxShadow.sh -n https://clearme.com

# Or standalone nuclei with custom templates
nuclei -u https://clearme.com -t /path/to/templates -severity critical,high,medium
```

### 3.3 Additional Vulnerability Checks

#### SQL Injection
```bash
# Using sqlmap on parameterized URLs
sqlmap -m filtered_urls.txt --batch --random-agent
```

#### SSRF Testing
```bash
# Look for URL parameters that might be vulnerable
gf ssrf filtered_urls.txt | qsreplace "http://your-server.com" | httpx
```

#### Open Redirect
```bash
# Test for open redirects
gf redirect filtered_urls.txt | qsreplace "https://evil.com" | httpx
```

#### IDOR Testing
```bash
# Manual testing required - look for:
# - Numeric IDs in parameters
# - User IDs in API calls
# - Document/file references
```

---

## Phase 4: Manual Testing Focus Areas

### 4.1 Authentication & Authorization
- [ ] Login flow analysis
- [ ] Password reset functionality
- [ ] Session management
- [ ] OAuth implementation
- [ ] Multi-factor authentication bypass
- [ ] Account takeover vectors

### 4.2 API Security
- [ ] API endpoint discovery
- [ ] Rate limiting
- [ ] Authentication bypass
- [ ] IDOR on API endpoints
- [ ] Mass assignment
- [ ] GraphQL introspection

### 4.3 Business Logic
- [ ] Clear airport security bypass
- [ ] Identity verification bypass
- [ ] Payment flow manipulation
- [ ] Membership tier escalation
- [ ] Booking manipulation

### 4.4 Sensitive Data Exposure
- [ ] PII in responses
- [ ] Debug information leakage
- [ ] Source code exposure
- [ ] Backup files
- [ ] Configuration files

---

## Phase 5: Exploitation & PoC Development

### 5.1 Vulnerability Validation
For each finding:
1. Confirm the vulnerability is real
2. Determine impact and severity
3. Create a safe PoC
4. Document reproduction steps

### 5.2 Report Template
```markdown
# Vulnerability Title

## Summary
Brief description of the vulnerability

## Impact
- What can an attacker achieve?
- What data is at risk?
- Business impact

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Proof of Concept
Include screenshots, videos, or code

## Remediation
Suggested fix for the vulnerability
```

---

## Execution Checklist

### Pre-Engagement
- [ ] Verify bug bounty program exists
- [ ] Read and understand program rules
- [ ] Note scope and out-of-scope items
- [ ] Set up testing environment
- [ ] Configure Burp Suite / proxy

### Active Testing
- [ ] Phase 1: Reconnaissance complete
- [ ] Phase 2: Content discovery complete
- [ ] Phase 3: Vulnerability scanning complete
- [ ] Phase 4: Manual testing complete
- [ ] Phase 5: PoC development complete

### Post-Engagement
- [ ] Document all findings
- [ ] Write detailed reports
- [ ] Submit through proper channels
- [ ] Maintain ethical disclosure timeline

---

## Tools Reference

| Tool | Purpose | Installation |
|------|---------|--------------|
| HaxShadow | DAST scanning | Already in workspace |
| subfinder | Subdomain enum | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | Vulnerability scanner | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ffuf | Fuzzing | `go install -v github.com/ffuf/ffuf/v2@latest` |
| gau | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| Dalfox | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| XSStrike | XSS fuzzer | `pip install xsstrike` |

---

## Output Files

When running HaxShadow, expect these output files:
- `filtered_urls.txt` - Live URLs with query parameters
- `nuclei_results.txt` - Nuclei vulnerability findings
- `xsstrike_results.txt` - XSStrike XSS findings
- `dalfox_results.txt` - Dalfox XSS findings

---

## Notes

- Clearme.com is an identity verification service used for airport security
- High-value targets include:
  - Identity verification bypass
  - User data exposure
  - Authentication flaws
  - API vulnerabilities
- Always test within scope and follow responsible disclosure practices
