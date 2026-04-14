# DomainProbe v2.0
**Advanced DNS & Domain Intelligence Platform**

Tier 2 DNS / Domain Technical Support Tool — built for fast, accurate, parallel diagnostics.

---

## Quick Start

```bash
# Install dependencies
python -m pip install -r requirements.txt

# Run
python domainprobe.py
```

---

## Features (26 options)

### DNS Core
| # | Feature | What it does |
|---|---------|-------------|
| 1 | DNS Record Lookup | All 15 record types, custom resolver support |
| 2 | NS Consistency & SOA | Queries each NS directly, compares SOA serials, zone delegation mismatch |
| 3 | Propagation Check | Parallel query across 9 resolvers (Google, Cloudflare, Quad9, OpenDNS…) |
| 4 | CNAME / TTL Analyzer | RFC conflict detection, TTL anomaly flagging, wildcard DNS check |

### Domain Lifecycle
| # | Feature | What it does |
|---|---------|-------------|
| 5 | WHOIS Lookup | Full WHOIS with deduplicated dates and expiry warnings |
| 6 | RDAP Lookup | JSON RDAP via rdap.org, all events and entities |
| 7 | EPP Decoder | 24 ICANN status codes — meaning, action, DNS impact |
| 8 | Transfer Eligibility | Full 8-condition ICANN transfer check |

### Email Deliverability
| # | Feature | What it does |
|---|---------|-------------|
| 9 | SPF Analyzer | Recursive include resolution, lookup count (RFC 7208), IP list, +all detection |
| 10 | DMARC Inspector | All tags decoded: p, sp, pct, rua, ruf, adkim, aspf, fo |
| 11 | DKIM Prober | 28 common selectors, key type & length detection |
| 12 | MX Validator | Priority check, port 25/587, reverse DNS, reachability |
| 13 | RBL Checker | 18 DNSBLs in parallel — Spamhaus, Barracuda, Spamcop… |

### Security
| # | Feature | What it does |
|---|---------|-------------|
| 14 | SSL Inspector | Cert chain, SANs, expiry, TLS version, cipher, hostname match |
| 15 | DNSSEC Validator | DS, DNSKEY, RRSIG, enforcement test via Cloudflare |
| 16 | DoH Probe | Cloudflare, Google, Quad9, NextDNS — cross-provider consistency |
| 17 | CAA Analyzer | Issuance restrictions, iodef, wildcard policy |

### Diagnostics & Reports
| # | Feature | What it does |
|---|---------|-------------|
| **18** | **DNS Health Score** | **17-check weighted audit, A–F grade, ranked issue list** |
| **19** | **Ticket Summary** | **Full scan → formatted plaintext report, save to file** |
| 20 | Redirect Chain | Follows HTTP redirects, detects loops & HTTPS downgrades |
| 21 | Live Watcher | Polls a record every N seconds, alerts on change (Ctrl+C to stop) |
| 22 | Expiry Calendar | Portfolio of domains, sorted by expiry urgency |
| 23 | Connectivity | Ping, 10-port scan, traceroute (Windows & Linux) |

### Session
| # | Feature | What it does |
|---|---------|-------------|
| 24 | Bulk Lookup | Many domains at once, any record type, parallel |
| 25 | Diff Mode | Before/after DNS snapshot comparison |
| 26 | Export | Session results to JSON or CSV |

---

## DNS Health Score — Check List

| Check | Points |
|-------|--------|
| NS Records (≥2) | 8 |
| SOA Record | 5 |
| A / AAAA Records | 8 |
| MX Records | 6 |
| MX Reachability (port 25) | 5 |
| SPF Record | 8 |
| SPF Strictness (-all) | 5 |
| DMARC Policy | 8 |
| DMARC Enforcement | 5 |
| DKIM (any selector) | 7 |
| CAA Records | 5 |
| DNSSEC (DS record) | 8 |
| www Subdomain | 4 |
| TTL Sanity | 4 |
| No CNAME Conflicts | 4 |
| SSL Certificate Valid | 6 |
| Not on Spamhaus | 4 |
| **Total** | **102** |

Grades: A ≥90% · B ≥75% · C ≥60% · D ≥45% · F <45%

---

## Architecture

```
domainprobe_v2/
├── domainprobe.py          ← Main entry point / menu
├── requirements.txt
├── README.md
└── modules/
    ├── display.py          ← Rich console, helpers, Spinner
    ├── session.py          ← Result storage, snapshots, export
    ├── dns_core.py         ← DNS lookup, propagation, NS/SOA, CNAME/TTL
    ├── whois_rdap.py       ← WHOIS, RDAP, EPP decoder
    ├── email_suite.py      ← SPF, DMARC, DKIM, MX, RBL
    ├── security.py         ← SSL/TLS, DNSSEC, DoH, CAA
    ├── diagnostics.py      ← Health score, redirect, transfer, expiry
    ├── connectivity.py     ← Ping, port scan, traceroute
    └── reporter.py         ← Ticket summary, diff, live watcher
```

All parallel operations use `concurrent.futures.ThreadPoolExecutor` for speed.
All DNS queries go through `resolve_safe()` — never raises, always returns `(values, ttl, status)`.

---

## Requirements
- Python 3.9+
- dnspython, python-whois, requests, rich
