"""Flagship domain and website diagnosis workflows."""

import concurrent.futures
import datetime
import json
import socket
import ssl
from pathlib import Path

import requests
import whois
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from . import session
from .display import console, get_domain, info, ok, section, Spinner, warn
from .dns_core import RESOLVERS, resolve_safe

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BASE_TYPES = ["NS", "SOA", "A", "AAAA", "CNAME", "DS"]
DEFAULT_RESOLVER_SAMPLE = list(RESOLVERS.items())[:6]


def _timestamp():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_values(values):
    return [value.strip() for value in values if str(value).strip()]


def _sort_findings(findings):
    return sorted(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])


def _top_finding(findings):
    return findings[0] if findings else None


def _save_report(report, filename, output_format, renderer):
    path = Path(filename)
    if output_format == "json":
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    else:
        path.write_text(renderer(report) + "\n", encoding="utf-8")
    return path


def save_diagnosis_report(report, filename, output_format, renderer):
    return _save_report(report, filename, output_format, renderer)


def _collect_base_records(domain):
    def fetch(rtype):
        values, ttl, status = resolve_safe(domain, rtype)
        return rtype, {"values": _clean_values(values), "ttl": ttl, "status": status}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(BASE_TYPES)) as ex:
        raw = list(ex.map(fetch, BASE_TYPES))
    return {rtype: result for rtype, result in raw}


def _collect_auth_ns(domain, nameservers):
    def query(ns_host):
        host = ns_host.rstrip(".")
        try:
            ip = socket.gethostbyname(host)
        except OSError as exc:
            return {
                "host": host,
                "ip": None,
                "reachable": False,
                "authoritative": False,
                "status": f"UNRESOLVABLE:{exc}",
                "serial": None,
                "auth_ns": [],
            }

        soa_values, _, soa_status = resolve_safe(domain, "SOA", ip, timeout=4)
        auth_values, _, auth_status = resolve_safe(domain, "NS", ip, timeout=4)
        serial = None
        if soa_status == "ok" and soa_values:
            parts = soa_values[0].split()
            if len(parts) >= 3:
                serial = parts[2]

        return {
            "host": host,
            "ip": ip,
            "reachable": soa_status in ("ok", "NOANSWER") or auth_status == "ok",
            "authoritative": bool(auth_values) or soa_status == "ok",
            "status": soa_status if soa_status != "NOANSWER" else auth_status,
            "serial": serial,
            "auth_ns": sorted(item.rstrip(".").lower() for item in auth_values),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(nameservers))) as ex:
        return list(ex.map(query, nameservers))


def _collect_propagation(domain, rtype="A"):
    def query(item):
        name, ip = item
        values, ttl, status = resolve_safe(domain, rtype, ip, timeout=4)
        return {
            "resolver": name.strip(),
            "ip": ip,
            "values": sorted(_clean_values(values)),
            "ttl": ttl,
            "status": status,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DEFAULT_RESOLVER_SAMPLE)) as ex:
        return list(ex.map(query, DEFAULT_RESOLVER_SAMPLE))


def _whois_snapshot(domain):
    result = {"checked": False, "expires": None, "expired": False, "status": []}
    try:
        data = whois.whois(domain)
        expires = data.expiration_date
        statuses = data.status or []
        if isinstance(expires, list):
            expires = expires[0]
        if isinstance(statuses, str):
            statuses = [statuses]
        statuses = [item.split()[0].lower() for item in statuses]
        result["checked"] = True
        result["status"] = statuses
        if isinstance(expires, datetime.datetime):
            expires = expires.replace(tzinfo=None)
            result["expires"] = expires.strftime("%Y-%m-%d")
            result["expired"] = expires < datetime.datetime.utcnow()
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_tls(domain):
    result = {
        "checked": False,
        "ok": False,
        "version": None,
        "issuer": None,
        "days_remaining": None,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                expires_at = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(item[0] for item in cert.get("issuer", []))
                result.update(
                    {
                        "checked": True,
                        "ok": expires_at > datetime.datetime.utcnow(),
                        "version": tls_sock.version(),
                        "issuer": issuer.get("commonName", "Unknown"),
                        "days_remaining": (expires_at - datetime.datetime.utcnow()).days,
                    }
                )
    except Exception as exc:
        result.update({"checked": True, "error": str(exc)})
    return result


def _fetch_url(url):
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": "DomainProbe/2.0"},
        )
        return {
            "url": url,
            "ok": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "history": [{"status_code": item.status_code, "url": item.url} for item in response.history],
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
        }
    except requests.exceptions.TooManyRedirects as exc:
        return {"url": url, "ok": False, "error": f"redirect-loop:{exc}"}
    except requests.exceptions.SSLError as exc:
        return {"url": url, "ok": False, "error": f"ssl:{exc}"}
    except requests.exceptions.RequestException as exc:
        return {"url": url, "ok": False, "error": str(exc)}


def _render_primary(primary):
    if not primary:
        return [
            "Primary Cause: No clear failure isolated",
            "Confidence: medium",
            "Likely Owner: review manually",
            "Evidence: The automated checks did not find a definitive break.",
            "Next Action: Use the advanced tools to inspect the specific symptom in more detail.",
        ]
    return [
        f"Primary Cause: {primary['title']}",
        f"Confidence: {primary['confidence']}",
        f"Likely Owner: {primary['owner']}",
        f"Evidence: {primary['evidence']}",
        f"Next Action: {primary['next_action']}",
    ]


def render_domain_diagnosis_text(report):
    lines = [
        "DOMAIN DIAGNOSIS",
        f"Domain: {report['domain']}",
        f"Generated: {report['generated_at']}",
        f"Status: {report['status']}",
        "",
    ]
    lines.extend(_render_primary(report["primary_cause"]))
    lines.append("")

    if report["secondary_findings"]:
        lines.append("Secondary Findings")
        for index, finding in enumerate(report["secondary_findings"], 1):
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"   Owner: {finding['owner']}")
            lines.append(f"   Evidence: {finding['evidence']}")
            lines.append(f"   Action: {finding['next_action']}")
        lines.append("")

    if report["positives"]:
        lines.append("Positive Signals")
        for item in report["positives"]:
            lines.append(f"- {item}")

    return "\n".join(lines).strip()


def render_website_diagnosis_text(report):
    lines = [
        "WEBSITE DIAGNOSIS",
        f"Domain: {report['domain']}",
        f"Generated: {report['generated_at']}",
        f"Status: {report['status']}",
        "",
    ]
    lines.extend(_render_primary(report["primary_cause"]))
    lines.append("")

    if report["secondary_findings"]:
        lines.append("Secondary Findings")
        for index, finding in enumerate(report["secondary_findings"], 1):
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"   Owner: {finding['owner']}")
            lines.append(f"   Evidence: {finding['evidence']}")
            lines.append(f"   Action: {finding['next_action']}")
        lines.append("")

    if report["positives"]:
        lines.append("Positive Signals")
        for item in report["positives"]:
            lines.append(f"- {item}")

    return "\n".join(lines).strip()


def run_domain_diagnosis(domain):
    domain = domain.strip().lower()
    findings = []
    positives = []
    base = _collect_base_records(domain)
    whois_data = _whois_snapshot(domain)
    nameservers = base["NS"]["values"]
    auth_ns = _collect_auth_ns(domain, nameservers) if nameservers else []
    propagation = _collect_propagation(domain)

    def add_finding(severity, title, owner, evidence, next_action, confidence="high"):
        findings.append(
            {
                "severity": severity,
                "title": title,
                "owner": owner,
                "evidence": evidence,
                "next_action": next_action,
                "confidence": confidence,
            }
        )

    if whois_data.get("expired"):
        add_finding(
            "critical",
            "Domain registration expired",
            "registrar / domain owner",
            f"WHOIS expiration date is {whois_data['expires']}.",
            "Renew the domain first, then re-check delegation and resolution.",
            confidence="high",
        )

    if base["NS"]["status"] == "NXDOMAIN":
        add_finding(
            "critical",
            "Domain does not exist in DNS",
            "registrar / DNS provider",
            f"NS lookup returned NXDOMAIN for {domain}.",
            "Verify the zone exists and the domain is delegated to an active DNS provider.",
            confidence="high",
        )
    elif not nameservers:
        add_finding(
            "high",
            "No nameserver delegation returned",
            "registrar / DNS provider",
            f"NS lookup status was {base['NS']['status']} with no returned nameservers.",
            "Check registrar delegation and confirm the zone has authoritative nameservers assigned.",
            confidence="high",
        )
    else:
        positives.append(f"Recursive lookup returned {len(nameservers)} nameserver(s).")

    reachable_auth = [item for item in auth_ns if item["reachable"]]
    if nameservers and not reachable_auth:
        add_finding(
            "critical",
            "Authoritative nameservers are unreachable",
            "DNS provider / hosting provider",
            "Direct SOA/NS queries to all delegated nameservers failed.",
            "Restore DNS service on the authoritative nameservers or correct the delegation.",
            confidence="high",
        )
    elif nameservers and len(reachable_auth) < len(nameservers):
        failed_hosts = ", ".join(item["host"] for item in auth_ns if not item["reachable"])
        add_finding(
            "medium",
            "Some authoritative nameservers are unreachable",
            "DNS provider",
            f"Direct queries failed for: {failed_hosts}.",
            "Fix the failed nameservers or remove them from delegation to avoid intermittent failures.",
            confidence="medium",
        )

    if reachable_auth:
        serials = sorted({item["serial"] for item in reachable_auth if item["serial"]})
        auth_sets = [set(item["auth_ns"]) for item in reachable_auth if item["auth_ns"]]
        if serials and len(serials) == 1:
            positives.append(f"Authoritative SOA serial is consistent at {serials[0]}.")
        elif len(serials) > 1:
            add_finding(
                "medium",
                "Authoritative nameservers disagree on SOA serial",
                "DNS provider",
                f"Observed SOA serials: {', '.join(serials)}.",
                "Wait for secondary sync if this is a recent change, otherwise repair zone replication.",
                confidence="medium",
            )

        if auth_sets:
            auth_union = sorted(set.union(*auth_sets))
            recursive_ns = sorted(item.rstrip(".").lower() for item in nameservers)
            if sorted(auth_union) and auth_union != recursive_ns:
                add_finding(
                    "high",
                    "Delegation mismatch between recursive and authoritative data",
                    "registrar / DNS provider",
                    f"Recursive NS set: {', '.join(recursive_ns)}; authoritative NS set: {', '.join(auth_union)}.",
                    "Make the registrar delegation match the active authoritative zone.",
                    confidence="high",
                )
            elif auth_union:
                positives.append("Recursive and authoritative nameserver sets agree.")

        lame_hosts = [item["host"] for item in auth_ns if item["reachable"] and not item["authoritative"]]
        if lame_hosts:
            add_finding(
                "medium",
                "Lame delegation detected",
                "DNS provider",
                f"These delegated nameservers did not act authoritative: {', '.join(lame_hosts)}.",
                "Remove or fix the lame nameservers so all delegated hosts serve the zone authoritatively.",
                confidence="medium",
            )

    if base["SOA"]["status"] != "ok" or not base["SOA"]["values"]:
        add_finding(
            "high",
            "SOA record missing or unreadable",
            "DNS provider",
            f"SOA lookup status was {base['SOA']['status']}.",
            "Confirm the zone is loaded and being served by the authoritative DNS provider.",
            confidence="high",
        )
    else:
        positives.append("SOA record is present in recursive lookup.")

    addresses = sorted(set(base["A"]["values"] + base["AAAA"]["values"]))
    if addresses:
        positives.append(f"Apex resolves to {', '.join(addresses[:4])}.")
    else:
        cname_values = base["CNAME"]["values"]
        if cname_values:
            add_finding(
                "high",
                "Apex relies on a CNAME instead of address records",
                "DNS provider",
                f"CNAME values: {', '.join(cname_values)} and no A/AAAA records were found.",
                "Use apex flattening or publish A/AAAA records for the root domain.",
                confidence="high",
            )
        else:
            add_finding(
                "high",
                "No apex A or AAAA records found",
                "DNS provider / hosting provider",
                "The root domain returned no address records.",
                "Publish the correct origin or edge IP addresses for the root domain.",
                confidence="high",
            )

    if base["CNAME"]["status"] == "ok" and base["CNAME"]["values"] and addresses:
        add_finding(
            "critical",
            "Apex CNAME conflicts with address records",
            "DNS provider",
            f"CNAME values: {', '.join(base['CNAME']['values'])}; A/AAAA values: {', '.join(addresses)}.",
            "Remove the conflicting apex CNAME and keep only the supported record set.",
            confidence="high",
        )

    successful_answers = [tuple(item["values"]) for item in propagation if item["status"] == "ok" and item["values"]]
    unique_answers = sorted(set(successful_answers))
    if len(unique_answers) > 1:
        add_finding(
            "medium",
            "Propagation is incomplete across public resolvers",
            "DNS provider / resolver cache",
            f"Observed {len(unique_answers)} different answer sets across sampled resolvers.",
            "Wait for TTL expiry if the change was recent, otherwise verify every authoritative server serves the same answer.",
            confidence="medium",
        )
    elif unique_answers:
        positives.append("Sampled public resolvers agree on the apex answer.")

    bad_resolver_statuses = [item for item in propagation if item["status"] not in ("ok", "NOANSWER")]
    if bad_resolver_statuses and base["DS"]["values"] and not addresses:
        failing = ", ".join(f"{item['resolver']}={item['status']}" for item in bad_resolver_statuses[:4])
        add_finding(
            "high",
            "Possible DNSSEC or authoritative validation failure",
            "DNS provider / registrar",
            f"DS record exists but resolver sampling returned failures: {failing}.",
            "Verify the DNSKEY/DS chain or temporarily remove the bad DS record until signing is fixed.",
            confidence="medium",
        )
    elif base["DS"]["values"]:
        positives.append("DS records are present at the parent zone.")

    findings = _sort_findings(findings)
    primary = _top_finding(findings)
    report = {
        "domain": domain,
        "generated_at": _timestamp(),
        "status": "healthy" if not primary else "issues-found",
        "primary_cause": primary,
        "secondary_findings": findings[1:],
        "positives": positives,
        "findings": findings,
        "snapshot": {
            "dns": base,
            "whois": whois_data,
            "authoritative": auth_ns,
            "propagation": propagation,
        },
    }
    return report


def run_website_diagnosis(domain):
    domain_report = run_domain_diagnosis(domain)
    domain = domain_report["domain"]
    findings = list(domain_report["findings"])
    positives = list(domain_report["positives"])
    addresses = domain_report["snapshot"]["dns"]["A"]["values"] + domain_report["snapshot"]["dns"]["AAAA"]["values"]

    port_state = {"80": False, "443": False}
    tls = None
    http_result = None
    https_result = None

    if addresses:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            port_80_future = ex.submit(_check_port, domain, 80)
            port_443_future = ex.submit(_check_port, domain, 443)
            port_state["80"] = port_80_future.result()
            port_state["443"] = port_443_future.result()

        if port_state["80"]:
            positives.append("Port 80 is reachable.")
        if port_state["443"]:
            positives.append("Port 443 is reachable.")

        if port_state["443"]:
            tls = _probe_tls(domain)
            if tls["ok"]:
                positives.append(
                    f"TLS handshake succeeds over {tls['version'] or 'unknown TLS'} and expires in {tls['days_remaining']} day(s)."
                )
                if tls["days_remaining"] is not None and tls["days_remaining"] < 30:
                    findings.append(
                        {
                            "severity": "medium",
                            "title": "TLS certificate expires soon",
                            "owner": "hosting provider / certificate automation",
                            "evidence": f"The active certificate expires in {tls['days_remaining']} day(s).",
                            "next_action": "Renew the certificate and confirm automated renewal is working.",
                            "confidence": "medium",
                        }
                    )
            elif tls["error"]:
                findings.append(
                    {
                        "severity": "high",
                        "title": "TLS handshake failed on port 443",
                        "owner": "hosting provider / CDN / certificate automation",
                        "evidence": tls["error"],
                        "next_action": "Fix the certificate chain, hostname coverage, or HTTPS listener configuration.",
                        "confidence": "high",
                    }
                )

        if port_state["80"]:
            http_result = _fetch_url(f"http://{domain}")
        if port_state["443"]:
            https_result = _fetch_url(f"https://{domain}")

        if not port_state["80"] and not port_state["443"]:
            findings.append(
                {
                    "severity": "high",
                    "title": "Web service ports are unreachable",
                    "owner": "hosting provider / firewall / CDN",
                    "evidence": "Both port 80 and port 443 refused or timed out.",
                    "next_action": "Check edge/origin reachability, firewall rules, and whether the service is listening.",
                    "confidence": "high",
                }
            )
        elif port_state["80"] and not port_state["443"]:
            findings.append(
                {
                    "severity": "medium",
                    "title": "HTTP is reachable but HTTPS is not",
                    "owner": "hosting provider / CDN / firewall",
                    "evidence": "Port 80 is open while port 443 is closed or unreachable.",
                    "next_action": "Restore the HTTPS listener and verify certificate termination on port 443.",
                    "confidence": "high",
                }
            )

        for result in (http_result, https_result):
            if not result:
                continue
            if not result["ok"]:
                error_text = result["error"]
                if error_text.startswith("redirect-loop"):
                    findings.append(
                        {
                            "severity": "high",
                            "title": "HTTP redirect loop detected",
                            "owner": "web platform / CDN / application config",
                            "evidence": f"{result['url']} triggered too many redirects.",
                            "next_action": "Review redirect rules between HTTP, HTTPS, CDN, and origin.",
                            "confidence": "high",
                        }
                    )
                elif error_text.startswith("ssl:"):
                    findings.append(
                        {
                            "severity": "high",
                            "title": "HTTPS request failed during SSL negotiation",
                            "owner": "hosting provider / CDN",
                            "evidence": error_text,
                            "next_action": "Repair the certificate or TLS configuration on the HTTPS endpoint.",
                            "confidence": "high",
                        }
                    )
                else:
                    findings.append(
                        {
                            "severity": "medium",
                            "title": f"{result['url']} request failed",
                            "owner": "hosting provider / network",
                            "evidence": error_text,
                            "next_action": "Check origin reachability, upstream health, and any proxy or CDN edge logs.",
                            "confidence": "medium",
                        }
                    )
                continue

            code = result["status_code"]
            if code >= 500:
                findings.append(
                    {
                        "severity": "high",
                        "title": "Website returns server errors",
                        "owner": "application / origin infrastructure",
                        "evidence": f"{result['url']} returned HTTP {code} with final URL {result['final_url']}.",
                        "next_action": "Inspect origin or application logs and fix the upstream failure.",
                        "confidence": "high",
                    }
                )
            elif code in (403, 404):
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Website responds but serves the wrong application state",
                        "owner": "application / virtual host configuration",
                        "evidence": f"{result['url']} returned HTTP {code} with final URL {result['final_url']}.",
                        "next_action": "Verify vhost routing, document root, and application deployment for this hostname.",
                        "confidence": "medium",
                    }
                )
            elif result["elapsed_ms"] > 2500:
                findings.append(
                    {
                        "severity": "low",
                        "title": "Website is slow after connection",
                        "owner": "application / origin / CDN",
                        "evidence": f"{result['url']} completed in {result['elapsed_ms']} ms.",
                        "next_action": "Profile origin latency, CDN cache status, and upstream dependency response times.",
                        "confidence": "medium",
                    }
                )
            else:
                positives.append(f"{result['url']} returned HTTP {code} in {result['elapsed_ms']} ms.")

    findings = _sort_findings(findings)
    primary = _top_finding(findings)
    report = {
        "domain": domain,
        "generated_at": _timestamp(),
        "status": "healthy" if not primary else "issues-found",
        "primary_cause": primary,
        "secondary_findings": findings[1:],
        "positives": positives,
        "findings": findings,
        "snapshot": {
            "domain_diagnosis": domain_report,
            "ports": port_state,
            "tls": tls,
            "http": http_result,
            "https": https_result,
        },
    }
    return report


def _interactive_report(domain, runner, renderer, session_key, title, filename_prefix):
    if domain is None:
        domain = get_domain()

    section(f"{title} — {domain}")
    info("Running focused diagnostics and isolating the most likely culprit.")
    with Spinner(f"Diagnosing {domain}"):
        report = runner(domain)

    border = "green" if report["status"] == "healthy" else "yellow"
    if report["primary_cause"] and report["primary_cause"]["severity"] == "critical":
        border = "red"
    console.print(Panel(renderer(report), border_style=border, padding=(0, 1)))

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if Confirm.ask("\n  [cyan]Save diagnosis report to file?[/cyan]", default=True):
        output_format = Prompt.ask("  [cyan]Format[/cyan]", choices=["txt", "json"], default="txt")
        default_name = f"{filename_prefix}_{domain}_{timestamp}.{output_format}"
        filename = Prompt.ask("  [cyan]Filename[/cyan]", default=default_name)
        _save_report(report, filename, "text" if output_format == "txt" else "json", renderer)
        ok(f"Saved → [bold]{filename}[/bold]")

    if report["status"] == "healthy":
        ok("No obvious break detected by the flagship diagnosis flow.")
    else:
        warn(f"{1 + len(report['secondary_findings'])} finding(s) detected.")

    session.store(session_key, domain, report)
    return report


def diagnose_domain(domain=None):
    return _interactive_report(
        domain,
        run_domain_diagnosis,
        render_domain_diagnosis_text,
        "diagnose_domain",
        "Diagnose Domain",
        "diagnose_domain",
    )


def diagnose_website(domain=None):
    return _interactive_report(
        domain,
        run_website_diagnosis,
        render_website_diagnosis_text,
        "diagnose_website",
        "Diagnose Website",
        "diagnose_website",
    )
