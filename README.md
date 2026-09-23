<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.1-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp%20%2B%20dnspython-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
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
