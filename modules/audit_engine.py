"""Structured actionable audit engine for headless and interactive use."""

import concurrent.futures
import datetime
import json
import re
import socket
import ssl
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from . import session
from .display import console, get_domain, info, ok, section, Spinner, warn
from .dns_core import resolve_safe
from .email_suite import DKIM_SELECTORS, _spf_recurse

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_PENALTY = {"critical": 30, "high": 18, "medium": 10, "low": 4}
FAIL_LEVELS = {"never": None, "critical": 0, "high": 1, "medium": 2, "low": 3}
CORE_TYPES = ["A", "AAAA", "NS", "SOA", "MX", "TXT", "CAA", "DS", "CNAME"]
DMARC_RE = re.compile(r"\bp=([a-zA-Z]+)")
PCT_RE = re.compile(r"\bpct=(\d+)")


def _timestamp():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_values(values):
    return [v.strip() for v in values if str(v).strip()]


def _collect_core_records(domain):
    def fetch(rtype):
        values, ttl, status = resolve_safe(domain, rtype)
        return rtype, {"values": _clean_values(values), "ttl": ttl, "status": status}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(CORE_TYPES)) as ex:
        raw = list(ex.map(fetch, CORE_TYPES))
    return {rtype: result for rtype, result in raw}


def _parse_spf_record(values):
    return next(
        (
            value.strip('"').strip("'")
            for value in values
            if value.strip('"').strip("'").startswith("v=spf1")
        ),
        None,
    )


def _parse_dmarc_record(domain):
    values, ttl, status = resolve_safe(f"_dmarc.{domain}", "TXT")
    record = next((value.strip('"') for value in values if "v=DMARC1" in value.strip('"')), None)
    return {
        "record": record,
        "ttl": ttl,
        "status": status,
        "policy": DMARC_RE.search(record).group(1).lower() if record and DMARC_RE.search(record) else None,
        "pct": int(PCT_RE.search(record).group(1)) if record and PCT_RE.search(record) else 100,
    }


def _probe_dkim(domain, selectors=None):
    selectors = selectors or DKIM_SELECTORS[:8]

    def query(selector):
        values, _, status = resolve_safe(f"{selector}._domainkey.{domain}", "TXT", timeout=4)
        record = next((value.strip('"') for value in values if "p=" in value), None)
        return selector, record, status

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(selectors), 8)) as ex:
        raw = list(ex.map(query, selectors))

    found = [
        {"selector": selector, "record": record}
        for selector, record, status in raw
        if status == "ok" and record
    ]
    return {"selectors_checked": selectors, "found": found}


def _detect_wildcard(domain):
    probe = f"domainprobe-wildcard-check.{domain}"
    values, _, status = resolve_safe(probe, "A", timeout=4)
    return {"active": status == "ok" and bool(values), "answers": _clean_values(values), "status": status}


def _probe_ssl(domain):
    result = {"checked": False, "valid": False, "days_remaining": None, "version": None, "issuer": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                expires_at = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(item[0] for item in cert.get("issuer", []))
                result.update(
                    {
                        "checked": True,
                        "valid": expires_at > datetime.datetime.utcnow(),
                        "days_remaining": (expires_at - datetime.datetime.utcnow()).days,
                        "version": tls_sock.version(),
                        "issuer": issuer.get("commonName", "Unknown"),
                    }
                )
    except Exception as exc:
        result.update({"checked": True, "error": str(exc)})
    return result


def _sorted_findings(findings):
    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["title"]))


def _severity_counts(findings):
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def _top_recommendations(findings):
    seen = set()
    items = []
    for finding in findings:
        rec = finding["recommendation"]
        if rec not in seen:
            items.append(rec)
            seen.add(rec)
    return items[:8]


def run_actionable_audit(domain):
    domain = domain.strip().lower()
    findings = []
    positives = []
    records = _collect_core_records(domain)
    domain_exists = records["NS"]["status"] != "NXDOMAIN"

    def add_finding(severity, category, code, title, evidence, recommendation):
        findings.append(
            {
                "severity": severity,
                "category": category,
                "code": code,
                "title": title,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    ns_status = records["NS"]["status"]
    if ns_status == "NXDOMAIN":
        add_finding(
            "critical",
            "dns",
            "nxdomain",
            "Domain does not exist in DNS",
            f"NS lookup returned NXDOMAIN for {domain}.",
            "Verify the domain spelling and ensure the zone exists at the registrar and DNS provider.",
        )
    else:
        ns_count = len(records["NS"]["values"])
        if ns_count >= 2:
            positives.append(f"Delegation looks healthy with {ns_count} nameservers.")
        else:
            add_finding(
                "high",
                "dns",
                "ns-count",
                "Too few authoritative nameservers",
                f"Only {ns_count} NS record(s) were found.",
                "Publish at least two authoritative nameservers to avoid a single point of failure.",
            )

        if records["SOA"]["status"] == "ok" and records["SOA"]["values"]:
            positives.append("SOA record is present.")
        else:
            add_finding(
                "high",
                "dns",
                "missing-soa",
                "SOA record missing or unreadable",
                f"SOA lookup status: {records['SOA']['status']}.",
                "Confirm the zone is correctly hosted and the authoritative nameservers serve an SOA record.",
            )

    apex_addresses = sorted(set(records["A"]["values"] + records["AAAA"]["values"]))
    wildcard = {"active": False, "answers": [], "status": "SKIPPED"}
    spf_record = None
    dmarc = {"record": None, "ttl": 0, "status": "SKIPPED", "policy": None, "pct": 100}
    dkim = {"selectors_checked": DKIM_SELECTORS[:8], "found": []}
    email_enabled = False

    if domain_exists:
        if apex_addresses:
            positives.append(f"Apex resolves to {', '.join(apex_addresses[:4])}.")
        else:
            add_finding(
                "low",
                "dns",
                "no-apex-address",
                "No apex A or AAAA records detected",
                "Neither A nor AAAA records were returned for the zone apex.",
                "Add apex address records if the domain should serve web or API traffic directly.",
            )

        if records["CNAME"]["status"] == "ok" and records["CNAME"]["values"]:
            conflict_types = []
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                if records[rtype]["status"] == "ok" and records[rtype]["values"]:
                    conflict_types.append(rtype)
            add_finding(
                "critical",
                "dns",
                "apex-cname",
                "Apex CNAME conflicts with other record sets",
                f"CNAME values: {', '.join(records['CNAME']['values'])}; conflicting sets: {', '.join(conflict_types) or 'none'}.",
                "Remove the apex CNAME and use A/AAAA or provider-specific flattening instead.",
            )

        wildcard = _detect_wildcard(domain)
        if wildcard["active"]:
            add_finding(
                "medium",
                "dns",
                "wildcard-dns",
                "Wildcard DNS is active",
                f"Random hostnames resolved to {', '.join(wildcard['answers'])}.",
                "Confirm the wildcard is intentional; otherwise remove it to avoid masking bad subdomain configurations.",
            )

        spf_record = _parse_spf_record(records["TXT"]["values"])
        dmarc = _parse_dmarc_record(domain)
        dkim = _probe_dkim(domain)
        email_enabled = bool(records["MX"]["values"] or spf_record or dmarc["record"] or dkim["found"])

    if domain_exists and email_enabled:
        if records["MX"]["values"]:
            positives.append(f"MX records are present ({len(records['MX']['values'])} host(s)).")

        if not spf_record:
            add_finding(
                "high",
                "email",
                "missing-spf",
                "No SPF record found",
                "Email-related DNS records were detected, but no TXT record starting with v=spf1 was found.",
                "Publish an SPF record that lists authorized senders and ends with -all once validated.",
            )
        else:
            positives.append("SPF record is present.")
            _, lookup_count, _, spf_warnings = _spf_recurse(domain)
            if "+all" in spf_record or re.search(r"(^|\s)all($|\s)", spf_record):
                add_finding(
                    "critical",
                    "email",
                    "spf-pass-all",
                    "SPF record allows any sender",
                    f"SPF record: {spf_record}",
                    "Replace +all or bare all with -all after enumerating authorized mail sources.",
                )
            elif "-all" in spf_record:
                positives.append("SPF enforcement is strict (-all).")
            elif "~all" in spf_record:
                add_finding(
                    "low",
                    "email",
                    "spf-softfail",
                    "SPF policy is softfail",
                    f"SPF record ends with ~all: {spf_record}",
                    "Move to -all once your sender inventory is complete.",
                )
            else:
                add_finding(
                    "medium",
                    "email",
                    "spf-no-all",
                    "SPF policy has no terminating all mechanism",
                    f"SPF record: {spf_record}",
                    "Add -all or at minimum ~all so receivers have a clear enforcement instruction.",
                )

            if lookup_count > 10:
                add_finding(
                    "high",
                    "email",
                    "spf-lookup-limit",
                    "SPF exceeds the RFC lookup limit",
                    f"Recursive SPF analysis counted {lookup_count} DNS-triggering mechanisms.",
                    "Flatten or simplify the SPF tree to stay at 10 lookups or fewer.",
                )
            elif lookup_count >= 8:
                add_finding(
                    "medium",
                    "email",
                    "spf-near-limit",
                    "SPF is close to the RFC lookup limit",
                    f"Recursive SPF analysis counted {lookup_count} DNS-triggering mechanisms.",
                    "Reduce includes and indirections before the record starts failing on stricter receivers.",
                )

            for warning_text in sorted(set(spf_warnings)):
                add_finding(
                    "low",
                    "email",
                    "spf-warning",
                    "SPF recursion produced a warning",
                    warning_text,
                    "Review the SPF include chain and remove unnecessary redirects or recursion.",
                )

        if not dmarc["record"]:
            add_finding(
                "high",
                "email",
                "missing-dmarc",
                "No DMARC policy found",
                f"_dmarc.{domain} did not return a DMARC TXT record.",
                "Publish a DMARC record and start with monitoring only if you need a safe rollout path.",
            )
        else:
            positives.append(f"DMARC is present with policy {dmarc['policy'] or 'unknown'}.")
            if dmarc["policy"] == "none":
                add_finding(
                    "medium",
                    "email",
                    "dmarc-monitor-only",
                    "DMARC is in monitor-only mode",
                    f"DMARC record: {dmarc['record']}",
                    "Move to p=quarantine or p=reject after reviewing aggregate reports.",
                )
            elif dmarc["policy"] in ("quarantine", "reject"):
                positives.append(f"DMARC enforcement is active ({dmarc['policy']}).")

            if dmarc["pct"] < 100:
                add_finding(
                    "low",
                    "email",
                    "dmarc-partial",
                    "DMARC only applies to part of traffic",
                    f"DMARC pct={dmarc['pct']}.",
                    "Raise pct to 100 when you are ready for full policy coverage.",
                )

        if dkim["found"]:
            found_selectors = ", ".join(item["selector"] for item in dkim["found"][:4])
            positives.append(f"DKIM selectors found: {found_selectors}.")
        else:
            add_finding(
                "low",
                "email",
                "dkim-not-detected",
                "No common DKIM selector was detected",
                f"Checked selectors: {', '.join(dkim['selectors_checked'])}.",
                "Verify the exact selector used by your mail provider and publish or rotate the DKIM key as needed.",
            )

    if domain_exists:
        if records["CAA"]["status"] == "ok" and records["CAA"]["values"]:
            positives.append(f"CAA records are present ({len(records['CAA']['values'])}).")
        else:
            add_finding(
                "low",
                "security",
                "missing-caa",
                "CAA records are not configured",
                "CAA lookup returned no records.",
                "Add CAA records to restrict which certificate authorities may issue for the domain.",
            )

        if records["DS"]["status"] == "ok" and records["DS"]["values"]:
            positives.append("DNSSEC DS record is present.")
        else:
            add_finding(
                "low",
                "security",
                "missing-dnssec",
                "DNSSEC is not enabled at the parent zone",
                "DS lookup returned no records.",
                "Enable DNSSEC at the DNS provider and publish the DS record through the registrar.",
            )

    ssl_result = None
    if domain_exists and apex_addresses:
        ssl_result = _probe_ssl(domain)
        if ssl_result["valid"]:
            positives.append(
                f"TLS endpoint is valid over {ssl_result['version'] or 'unknown TLS'} and expires in {ssl_result['days_remaining']} day(s)."
            )
            if ssl_result["days_remaining"] is not None and ssl_result["days_remaining"] < 30:
                add_finding(
                    "medium",
                    "security",
                    "ssl-expiring-soon",
                    "TLS certificate expires soon",
                    f"Certificate expires in {ssl_result['days_remaining']} day(s).",
                    "Renew the certificate before expiry and confirm automated renewal is working.",
                )
        elif ssl_result["error"]:
            add_finding(
                "medium",
                "security",
                "ssl-unavailable",
                "TLS handshake failed on port 443",
                ssl_result["error"],
                "Verify the HTTPS listener, certificate chain, and firewall on port 443.",
            )

    findings = _sorted_findings(findings)
    counts = _severity_counts(findings)
    score = max(0, 100 - sum(SEVERITY_PENALTY[item["severity"]] for item in findings))

    audit = {
        "domain": domain,
        "generated_at": _timestamp(),
        "score": score,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": counts,
            "top_recommendations": _top_recommendations(findings),
        },
        "findings": findings,
        "positives": positives,
        "snapshot": {
            "records": records,
            "wildcard": wildcard,
            "email": {
                "spf": spf_record,
                "dmarc": dmarc,
                "dkim": dkim,
                "email_enabled": email_enabled,
            },
            "ssl": ssl_result,
        },
    }
    return audit


def render_audit_text(audit):
    counts = audit["summary"]["severity_counts"]
    lines = [
        "DOMAINPROBE ACTIONABLE AUDIT",
        f"Domain: {audit['domain']}",
        f"Generated: {audit['generated_at']}",
        f"Risk Score: {audit['score']}/100",
        (
            "Findings: "
            f"{audit['summary']['finding_count']} "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']})"
        ),
        "",
    ]

    if audit["findings"]:
        lines.append("Findings")
        for index, finding in enumerate(audit["findings"], 1):
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"   Evidence: {finding['evidence']}")
            lines.append(f"   Action: {finding['recommendation']}")
        lines.append("")
    else:
        lines.append("Findings")
        lines.append("0. No high-confidence issues detected by the audit.")
        lines.append("")

    if audit["positives"]:
        lines.append("Positive Signals")
        for item in audit["positives"]:
            lines.append(f"- {item}")
        lines.append("")

    recommendations = audit["summary"]["top_recommendations"]
    if recommendations:
        lines.append("Priority Actions")
        for item in recommendations:
            lines.append(f"- {item}")

    return "\n".join(lines).strip()


def save_audit_report(audit, filename, output_format):
    output_path = Path(filename)
    if output_format == "json":
        output_path.write_text(json.dumps(audit, indent=2, default=str), encoding="utf-8")
    else:
        output_path.write_text(render_audit_text(audit) + "\n", encoding="utf-8")
    return output_path


def should_fail(findings, level):
    threshold = FAIL_LEVELS[level]
    if threshold is None:
        return False
    return any(SEVERITY_ORDER[item["severity"]] <= threshold for item in findings)


def actionable_audit(domain=None):
    if domain is None:
        domain = get_domain()

    section(f"Actionable Audit Report — {domain}")
    info("Running DNS, email, and TLS checks to produce ranked findings.")
    with Spinner(f"Auditing {domain}"):
        audit = run_actionable_audit(domain)

    text_report = render_audit_text(audit)
    border_style = "green" if not audit["findings"] else "yellow"
    if audit["summary"]["severity_counts"]["critical"]:
        border_style = "red"
    console.print(Panel(text_report, border_style=border_style, padding=(0, 1)))

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if Confirm.ask("\n  [cyan]Save audit report to file?[/cyan]", default=True):
        output_format = Prompt.ask("  [cyan]Format[/cyan]", choices=["txt", "json"], default="txt")
        default_name = f"audit_{domain}_{timestamp}.{output_format}"
        filename = Prompt.ask("  [cyan]Filename[/cyan]", default=default_name)
        save_audit_report(audit, filename, "text" if output_format == "txt" else "json")
        ok(f"Saved → [bold]{filename}[/bold]")

    if audit["summary"]["finding_count"] == 0:
        ok("No actionable findings detected.")
    else:
        warn(f"{audit['summary']['finding_count']} actionable finding(s) detected.")

    session.store("actionable_audit", domain, audit)
    return audit
