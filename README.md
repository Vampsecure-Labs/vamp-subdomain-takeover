<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.1-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp%20%2B%20dnspython-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-subdomain-takeover/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-subdomain-takeover</h1>
<p align="center"><em>Subdomain Takeover Vulnerability Scanner — VampSecure Labs</em></p>

---

## Overview

**vamp-subdomain-takeover** detects subdomain takeover vulnerabilities by performing full CNAME chain resolution and comparing dangling DNS records against a fingerprint database of 30+ cloud services and hosting platforms.

A subdomain takeover occurs when a subdomain's DNS CNAME points to a cloud resource (GitHub Pages, AWS S3, Heroku, Netlify, etc.) that no longer exists, allowing an attacker to register that resource and serve content under the victim's domain. This vulnerability class directly enables phishing, session hijacking, and content injection.

The scanner classifies each result into three states: **VULNERABLE** (fingerprint confirmed in HTTP response body), **POTENTIAL** (orphaned CNAME detected, HTTP confirmation not possible), or **SAFE**.

---

## Features

- Asynchronous CNAME chain resolution via `dns.asyncresolver` — handles multi-hop delegation
- 30+ service fingerprint signatures covering major cloud platforms
- Dual-stage validation: DNS orphan detection followed by HTTP body fingerprint confirmation
- CVSS scores embedded per service (GitHub Pages 8.1, AWS S3 9.3, Heroku 8.8, Netlify 8.8, Vercel 8.8, Azure 8.5, and more)
- Scope-aware: scan all subdomains for a domain, or supply a custom subdomain list
- Filter output to vulnerable hosts only with `--only-vulnerable`
- Configurable concurrency for large-scale scans

---

## Requirements

```
Python 3.11+
aiohttp >= 3.9.0
dnspython >= 2.4.0
rich >= 13.7.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation


```bash
pip install vamp-subdomain-takeover
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-subdomain-takeover
```

```bash
git clone https://github.com/belky-me/vamp-subdomain-takeover.git
cd vamp-subdomain-takeover
pip install -r requirements.txt
```

---

## Usage

```
python vamp_subdomain_takeover.py -d DOMAIN [OPTIONS]

Required:
  -d, --domain DOMAIN            Apex domain to check (drives auto-enumeration if no list given)

Input:
  -f, --from-file FILE           File with subdomains to check (one per line)
      --subdomains SUB1,SUB2     Comma-separated subdomain list

Output:
  -o, --output FILE              Write findings to JSON
      --html FILE                Generate standalone HTML report
      --only-vulnerable          Output only VULNERABLE results (suppress POTENTIAL/SAFE)

Performance:
      --concurrency N            Concurrent DNS + HTTP workers (default: 30)
      --http-timeout N           HTTP response timeout in seconds (default: 12)
```

---

## Examples

Check all subdomains of a target domain discovered via passive recon:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt
```

Check a domain and write only confirmed vulnerable findings to JSON:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt \
  --only-vulnerable -o takeover_findings.json
```

Generate an HTML report for client delivery:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt --html report.html
```

Check specific subdomains with reduced concurrency for rate-limited resolvers:

```bash
python vamp_subdomain_takeover.py -d example.com \
  --subdomains staging,dev,old,mail,legacy \
  --concurrency 10 -o findings.json
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with subdomain, CNAME chain, service, status, and CVSS |
| JSON | `-o FILE` | Full structured output: DNS chain, service, status, evidence |
| HTML | `--html FILE` | Standalone dark-theme report for client delivery or archival |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | All subdomains safe — no takeover risk detected | Pass gate |
| `1` | POTENTIAL findings — orphaned CNAMEs without HTTP confirmation | Review recommended |
| `2` | VULNERABLE — confirmed takeover opportunity detected | Fail gate — remediate immediately |

---

## Status Levels

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Fingerprint string found in HTTP response body — takeover confirmed |
| `POTENTIAL` | CNAME points to unclaimed resource but HTTP probe inconclusive |
| `SAFE` | CNAME target is registered and responds normally |
| `ERROR` | DNS resolution failed or host unreachable |

---

## Sample Output

```
$ python vamp_subdomain_takeover.py -d example.com -f subdomains.txt
vamp-subdomain-takeover v1.1 — VampSecure Labs
──────────────────────────────────────────────────────────────────────
[*] Checking 48 subdomains for example.com with concurrency 30...

┌─────────────────────┬────────────────────────────────────┬────────────┬───────────┬──────┐
│ Subdomain           │ CNAME Chain                        │ Service    │ Status    │ CVSS │
├─────────────────────┼────────────────────────────────────┼────────────┼───────────┼──────┤
│ shop.example.com    │ → shop.example.myshopify.com       │ Shopify    │ SAFE      │ —    │
│ blog.example.com    │ → example.github.io (DANGLING)     │ GitHub Pgs │ VULNERABLE│ 8.1  │
│ cdn.example.com     │ → example.s3.amazonaws.com (NXDOM) │ AWS S3     │ VULNERABLE│ 9.3  │
│ staging.example.com │ → example-app.herokuapp.com        │ Heroku     │ POTENTIAL │ 8.8  │
│ mail.example.com    │ (no CNAME)                         │ —          │ SAFE      │ —    │
└─────────────────────┴────────────────────────────────────┴────────────┴───────────┴──────┘

Summary: 48 subdomains · 2 VULNERABLE · 1 POTENTIAL · 45 SAFE
Exit code: 2 — immediate remediation required

VULNERABLE — blog.example.com (GitHub Pages, CVSS 8.1)
  CNAME: blog.example.com → example.github.io
  HTTP body: "There isn't a GitHub Pages site here."
  Remediation: create repo at github.com/example OR remove DNS record

VULNERABLE — cdn.example.com (AWS S3, CVSS 9.3)
  CNAME: cdn.example.com → example.s3.amazonaws.com
  DNS: NXDOMAIN — bucket does not exist
  Remediation: create S3 bucket "example" OR remove DNS record
```

## Why vamp-subdomain-takeover vs. subjack · nuclei (takeover templates) · can-i-take-over-xyz

| Capability | vamp-subdomain-takeover | subjack | nuclei (takeover) | can-i-take-over-xyz |
|------------|------------------------|---------|-------------------|---------------------|
| Async CNAME chain resolution (multi-hop) | ✅ `dns.asyncresolver` | ✅ | ✅ | ❌ Reference only |
| HTTP body fingerprint confirmation | ✅ Dual-stage validation | ✅ | ✅ | ❌ |
| CVSS score per service | ✅ Embedded per finding | ❌ | ❌ | ❌ |
| MX / NS record checks | ✅ | ❌ | ❌ | ❌ |
| Continuous monitoring mode | ✅ | ❌ | ❌ via cron | ❌ |
| Standalone HTML report for client delivery | ✅ `--html` | ❌ | ✅ SARIF | ❌ |
| JSON structured output | ✅ | ✅ | ✅ | ❌ |
| Configurable concurrency | ✅ `--concurrency N` | ✅ | ✅ | ❌ |
| Python importable package | ✅ | ❌ Go | ❌ Go | ❌ |
| Self-hosted / no cloud dependency | ✅ | ✅ | ✅ | ❌ Web app |

- **CVSS scores per service** — each fingerprint carries a published CVSS base score (GitHub Pages 8.1, AWS S3 9.3, Azure CDN 8.5), giving clients an immediate risk priority without extra research.
- **Dual-stage validation** — DNS orphan detection alone produces false positives; the HTTP body fingerprint confirmation step verifies whether the unclaimed resource is actually exploitable.
- **MX and NS coverage** — email subdomain takeovers (via orphaned MX records) and DNS delegation hijacks (via abandoned NS records) are checked alongside CNAME takeovers.
- **Client-ready output** — `--html` produces a standalone dark-theme report with CVSS-sorted findings, ready to hand to a client without post-processing.

## Check Coverage

| Check | Service / Attack Vector | CVSS | Standard |
|-------|------------------------|------|----------|
| GitHub Pages CNAME orphan | `github.io` NXDOMAIN / "There isn't a GitHub Pages site here." | 8.1 | OWASP OTG-CONFIG-002 |
| AWS S3 bucket CNAME orphan | `s3.amazonaws.com` NXDOMAIN | 9.3 | MITRE ATT&CK T1584.001 |
| Heroku CNAME orphan | `herokuapp.com` "No such app" fingerprint | 8.8 | OWASP OTG-CONFIG-002 |
| Netlify CNAME orphan | `netlify.app` "Not Found" body fingerprint | 8.8 | OWASP OTG-CONFIG-002 |
| Vercel CNAME orphan | `vercel.app` "The deployment could not be found" | 8.8 | OWASP OTG-CONFIG-002 |
| Azure CDN / Blob orphan | `azurewebsites.net` / `blob.core.windows.net` NXDOMAIN | 8.5 | MITRE ATT&CK T1584.001 |
| Fastly CNAME orphan | `fastly.net` "Fastly error: unknown domain" | 7.5 | OWASP OTG-CONFIG-002 |
| Shopify CNAME orphan | `myshopify.com` "Sorry, this shop is currently unavailable" | 7.5 | OWASP OTG-CONFIG-002 |
| Tumblr CNAME orphan | `tumblr.com` "There's nothing here" body fingerprint | 7.2 | OWASP OTG-CONFIG-002 |
| Ghost / HelpScout / Zendesk orphan | Various SaaS "page not found" fingerprints | 7.0–7.5 | OWASP OTG-CONFIG-002 |
| Orphaned NS delegation (DNS hijack) | NS record pointing to unregistered domain | 9.0 | MITRE ATT&CK T1584.002 |
| Orphaned MX record (email takeover) | MX pointing to unclaimed mail host | 8.0 | MITRE ATT&CK T1584.001 |

---

## Part of VampSecure Labs Toolkit

`vamp-subdomain-takeover` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---

## Versión
v1.1 — VampSecure Labs Security Research Division
