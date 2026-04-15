# Owusu DomainProbe

Operator-focused DNS, web, mail, and registrar diagnostics for support triage and domain incident work.

## What It Does

Owusu DomainProbe is a terminal toolkit for:

- DNS record inspection and propagation checks
- WHOIS and RDAP lookups
- SPF, DKIM, DMARC, MX, and blacklist checks
- TLS, DNSSEC, DoH, and CAA validation
- Website, domain, and email diagnosis workflows
- Audit reports, session exports, diff snapshots, and ticket-ready summaries

## Quick Start

```bash
python3 -m pip install -r requirements.txt
python3 domainprobe.py
```

CLI mode is also available:

```bash
python3 domainprobe.py diagnose-domain example.com --format json
python3 domainprobe.py diagnose-website example.com
python3 domainprobe.py diagnose-email example.com --fail-on high
python3 domainprobe.py audit example.com --output audit.txt
```

## Project Layout

```text
domainprobe/
├── domainprobe.py
├── requirements.txt
├── README.md
└── modules/
    ├── audit_engine.py
    ├── connectivity.py
    ├── diagnose.py
    ├── diagnostics.py
    ├── display.py
    ├── dns_core.py
    ├── email_suite.py
    ├── meta.py
    ├── reporter.py
    ├── session.py
    └── whois_rdap.py
```

## Development Notes

- Keep generated files out of git.
- Use `python3 -m py_compile domainprobe.py modules/*.py` for a fast syntax check.
- Install dependencies from `requirements.txt` before running feature checks.
