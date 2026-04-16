# Owusu DomainProbe

**Operator-focused DNS, web, mail, and registrar diagnostics.**  
Built for support triage, incident reports, and fast domain analysis.

Homepage: [owusuboateng.me](https://owusuboateng.me) · License: MIT

---

## What It Does

DomainProbe is a terminal toolkit that puts every domain diagnostic you need in one place. It has a menu-driven interactive mode and a full non-interactive CLI for scripting and CI use.

### Feature Overview

| Category | Features |
|---|---|
| **DNS Core** | Record lookup (15 types), propagation check (9 resolvers), NS consistency & SOA validation, zone delegation check, CNAME conflict & TTL analysis, wildcard detection, subdomain enumeration |
| **Domain Lifecycle** | WHOIS, RDAP, EPP / IANA status decoder (24 codes), expiry calendar (portfolio view) |
| **Email Deliverability** | SPF recursive analyzer (include chain + lookup count), DMARC inspector, DKIM selector prober (28 selectors), MX validator + port check, RBL / blacklist checker (18 DNSBLs) |
| **Security** | SSL/TLS inspector (chain, SANs, ciphers, expiry), DNSSEC validator, DNS-over-HTTPS probe (4 providers), CAA analyzer, **zone transfer test (AXFR)** |
| **Web / Network** | Redirect chain follower, port scan (10 ports), ping, traceroute, **ASN / BGP lookup** |
| **CDN Detection** | Fingerprints via NS, CNAME, and HTTP headers (Cloudflare, Fastly, CloudFront, Akamai, Vercel, Netlify, Azure) |
| **Reporting** | DNS health score (A–F grade, 17-point weighted audit), ticket-ready summary, diff mode, bulk domain lookup, live propagation watcher, session export (JSON / CSV) |
| **Diagnosis Workflows** | Flagship domain / website / email diagnosis flows with severity-ranked findings and actionable advice |

---

## Install

```bash
git clone https://github.com/PushDream/domainprobe.git
cd domainprobe
pip install -r requirements.txt
```

Or install as a package (adds a `domainprobe` command to your PATH):

```bash
pip install .
```

### Requirements

- Python 3.9+
- `dnspython >= 2.4.0`
- `python-whois >= 0.9.0`
- `requests >= 2.31.0`
- `rich >= 13.0.0`

---

## Quick Start

**Interactive mode** (menu-driven):

```bash
python3 domainprobe.py
# or after pip install:
domainprobe
```

**CLI mode** (non-interactive, scriptable):

```bash
# Domain health diagnosis
python3 domainprobe.py diagnose-domain example.com

# Website diagnosis — redirects, SSL, CDN, HTTP headers
python3 domainprobe.py diagnose-website example.com

# Email deliverability — SPF, DKIM, DMARC, MX, RBL
python3 domainprobe.py diagnose-email example.com

# Full actionable audit
python3 domainprobe.py audit example.com

# JSON output
python3 domainprobe.py diagnose-domain example.com --format json

# Save report to file
python3 domainprobe.py audit example.com --output audit.txt

# Exit non-zero if a critical or high finding is present (for CI)
python3 domainprobe.py diagnose-email example.com --fail-on high

# Version
python3 domainprobe.py --version
```

---

## CLI Reference

### `diagnose-domain <domain>`
Full domain resolution diagnosis: DNS records, propagation status, WHOIS, DNSSEC, TTL anomalies, NS consistency.

### `diagnose-website <domain>`
Website diagnosis: redirect chain, SSL/TLS, CDN detection, HTTP security headers, response time.

### `diagnose-email <domain>`
Email deliverability: SPF (recursive), DMARC, DKIM (28 selectors), MX reachability, RBL checks.

### `audit <domain>`
Actionable audit across all dimensions with severity-ranked findings and fix recommendations.

**Common flags** (all four commands):

| Flag | Values | Default | Description |
|---|---|---|---|
| `--format` | `text`, `json` | `text` | Output format |
| `--output FILE` | path | — | Write report to file |
| `--fail-on` | `never`, `critical`, `high`, `medium`, `low` | `never` | Exit code 2 if finding at or above severity |

---

## Syntax Check

```bash
python3 -m py_compile domainprobe.py modules/*.py
```

## Tests

```bash
# Unit tests (no network required)
python3 -m unittest tests/test_spf.py -v

# Smoke tests (requires network)
python3 -m unittest tests/smoke_test.py -v
```

---

## Project Layout

```
domainprobe/
├── domainprobe.py          # Entry point — CLI + interactive menu
├── requirements.txt
├── pyproject.toml
├── LICENSE
├── README.md
├── modules/
│   ├── audit_engine.py     # Actionable audit with severity scoring
│   ├── connectivity.py     # Ping, port scan, traceroute, ASN/BGP lookup
│   ├── diagnose.py         # Flagship diagnosis workflows + CDN detection
│   ├── diagnostics.py      # Health score, redirect chain, transfer eligibility
│   ├── display.py          # Rich console helpers, section/subsection headers
│   ├── dns_core.py         # DNS lookup, propagation, NS consistency, subdomain enum
│   ├── email_suite.py      # SPF, DMARC, DKIM, MX, RBL
│   ├── meta.py             # Version, app metadata
│   ├── reporter.py         # Ticket summary, diff mode, live watcher
│   ├── security.py         # SSL/TLS, DNSSEC, DoH, CAA, zone transfer
│   ├── session.py          # In-session result storage + JSON/CSV export
│   └── whois_rdap.py       # WHOIS, RDAP, EPP decoder
└── tests/
    ├── test_spf.py         # Unit tests — SPF, DMARC, grading, CLI args
    └── smoke_test.py       # Integration tests — real DNS/network
```

---

## Notes

- Keep generated reports and session exports out of git (covered by `.gitignore`)
- The tool never modifies DNS records — it is read-only
- Zone transfer tests and subdomain enumeration are scoped to the domain you enter; use only on domains you own or have authorisation to test
