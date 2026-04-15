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
from .email_suite import collect_mx, collect_spf, collect_dmarc, collect_dkim, collect_rbl
from .meta import APP_USER_AGENT

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE_LABEL = {"high": "Confirmed", "medium": "Likely", "unknown": "Insufficient Evidence"}
BASE_TYPES = ["NS", "SOA", "A", "AAAA", "CNAME", "DS"]
DEFAULT_RESOLVER_SAMPLE = list(RESOLVERS.items())[:6]

# CDN / proxy detection fingerprints
_CDN_BY_NS = {
    "Cloudflare":  ["cloudflare.com"],
    "AWS Route 53":["awsdns"],
    "Vercel":      ["vercel-dns.com"],
    "Netlify":     ["nsone.net", "netlify.com"],
    "Azure":       ["azure-dns.com", "azure-dns.net", "azure-dns.org"],
}
_CDN_BY_CNAME = {
    "Cloudflare":      ["cloudflare.net", "cloudflare.com"],
    "Fastly":          ["fastly.net", "fastlylb.net"],
    "AWS CloudFront":  ["cloudfront.net"],
    "Akamai":          ["akamaiedge.net", "akamaized.net", "akadns.net"],
    "Vercel":          ["vercel-dns.com", "vercel.app"],
    "Netlify":         ["netlify.app", "netlify.com"],
    "Azure CDN":       ["azurefd.net", "azureedge.net"],
}
_CDN_BY_HEADER = {
    "Cloudflare":      ["cf-ray", "cf-cache-status"],
    "Fastly":          ["x-served-by", "fastly-restarts"],
    "AWS CloudFront":  ["x-amz-cf-id", "x-amz-cf-pop"],
    "Akamai":          ["x-akamai-transformed", "akamai-cache-status"],
    "Vercel":          ["x-vercel-id", "x-vercel-cache"],
    "Netlify":         ["x-nf-request-id"],
    "Azure CDN":       ["x-azure-ref"],
}


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
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _detect_cdn(ns_values, cname_values, http_headers=None):
    """Return the first CDN/proxy provider detected from NS records, CNAMEs, or HTTP headers."""
    for provider, patterns in _CDN_BY_NS.items():
        for ns in ns_values:
            if any(p in ns.lower() for p in patterns):
                return {"detected": True, "provider": provider, "method": "nameserver"}
    for provider, patterns in _CDN_BY_CNAME.items():
        for cn in cname_values:
            if any(p in cn.lower() for p in patterns):
                return {"detected": True, "provider": provider, "method": "cname"}
    if http_headers:
        headers_lower = {k.lower() for k in http_headers}
        for provider, header_list in _CDN_BY_HEADER.items():
            if any(h in headers_lower for h in header_list):
                return {"detected": True, "provider": provider, "method": "http-headers"}
    return {"detected": False, "provider": None, "method": None}


def _rdap_expiry(domain):
    """Fetch expiry date and status flags from rdap.org as a fallback to WHOIS."""
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=8,
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code != 200:
            return None, []
        data = resp.json()
        statuses = [s.lower().replace("-", "") for s in data.get("status", [])]
        expiry = None
        for evt in data.get("events", []):
            if evt.get("eventAction") == "expiration":
                try:
                    expiry = datetime.datetime.fromisoformat(
                        evt["eventDate"].replace("Z", "+00:00")
                    ).replace(tzinfo=None)
                except Exception:
                    pass
        return expiry, statuses
    except Exception:
        return None, []


def _whois_snapshot(domain):
    result = {"checked": False, "expires": None, "expired": False, "status": [], "source": None}
    try:
        data = whois.whois(domain)
        expires = data.expiration_date
        statuses = data.status or []
        if isinstance(expires, list):
            expires = expires[0]
        if isinstance(statuses, str):
            statuses = [statuses]
        statuses = [item.split()[0].lower() for item in statuses]
        result.update({"checked": True, "status": statuses, "source": "whois"})
        if isinstance(expires, datetime.datetime):
            expires = expires.replace(tzinfo=None)
            result["expires"] = expires.strftime("%Y-%m-%d")
            result["expired"] = expires < datetime.datetime.utcnow()
            return result
    except Exception as exc:
        result["error"] = str(exc)

    # WHOIS failed or returned no expiry — try RDAP
    expiry, statuses = _rdap_expiry(domain)
    if expiry is not None:
        result.update({
            "checked": True,
            "source": "rdap",
            "expires": expiry.strftime("%Y-%m-%d"),
            "expired": expiry < datetime.datetime.utcnow(),
        })
        if statuses:
            result["status"] = statuses
    return result


def _check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _check_port_by_ip(ip, port, timeout=3):
    """Test a specific IP address (supports both IPv4 and IPv6)."""
    af = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except OSError:
        return False


def _is_waf_blocked(response):
    """Return the WAF/CDN provider name if the response looks like a bot-block, else None."""
    if response.status_code not in (403, 503):
        return None
    headers_lower = {k.lower() for k in response.headers}
    for provider, header_list in _CDN_BY_HEADER.items():
        if any(h in headers_lower for h in header_list):
            return provider
    body = response.text[:400].lower()
    if any(phrase in body for phrase in ("blocked", "access denied", "bot protection", "checking your browser")):
        return "WAF / bot protection"
    return None


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
            headers={"User-Agent": APP_USER_AGENT},
        )
        return {
            "url": url,
            "ok": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": dict(response.headers),
            "history": [{"status_code": item.status_code, "url": item.url} for item in response.history],
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "_response": response,
        }
    except requests.exceptions.TooManyRedirects as exc:
        return {"url": url, "ok": False, "error": f"redirect-loop:{exc}"}
    except requests.exceptions.SSLError as exc:
        return {"url": url, "ok": False, "error": f"ssl:{exc}"}
    except requests.exceptions.ConnectionError as exc:
        # Retry once — catches transient connection resets
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=10,
                headers={"User-Agent": APP_USER_AGENT},
            )
            return {
                "url": url,
                "ok": True,
                "status_code": response.status_code,
                "final_url": response.url,
                "headers": dict(response.headers),
                "history": [{"status_code": item.status_code, "url": item.url} for item in response.history],
                "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
                "_response": response,
            }
        except requests.exceptions.RequestException:
            return {"url": url, "ok": False, "error": str(exc)}
    except requests.exceptions.RequestException as exc:
        return {"url": url, "ok": False, "error": str(exc)}


def _render_primary(primary):
    if not primary:
        return [
            "Primary Cause: No clear failure isolated",
            "Confidence: Insufficient Evidence",
            "Likely Owner: review manually",
            "Evidence: The automated checks did not find a definitive break.",
            "Next Action: Use the advanced tools to inspect the specific symptom in more detail.",
        ]
    label = CONFIDENCE_LABEL.get(primary["confidence"], primary["confidence"].capitalize())
    return [
        f"Primary Cause: {primary['title']}",
        f"Confidence: {label}",
        f"Likely Owner: {primary['owner']}",
        f"Evidence: {primary['evidence']}",
        f"Next Action: {primary['next_action']}",
    ]


def _make_summary(findings, status, context="domain"):
    """Return a single plain-English sentence summarising the diagnosis outcome."""
    if status == "healthy":
        labels = {"domain": "resolves normally", "website": "is loading normally", "email": "delivery looks healthy"}
        return f"No issues detected — the {context} {labels.get(context, 'looks healthy')}."
    critical = [f for f in findings if f["severity"] == "critical"]
    high     = [f for f in findings if f["severity"] == "high"]
    total    = len(findings)
    if critical:
        return f"{total} issue(s) found — {critical[0]['title'].lower()}."
    if high:
        return f"{total} issue(s) found — {high[0]['title'].lower()}."
    return f"{total} issue(s) found — review the findings below."


def render_domain_diagnosis_text(report):
    lines = [
        "DOMAIN DIAGNOSIS",
        f"Domain: {report['domain']}",
        f"Generated: {report['generated_at']}",
        f"Status: {report['status']}",
        f"Summary: {report.get('summary', '')}",
        "",
    ]
    lines.extend(_render_primary(report["primary_cause"]))
    lines.append("")

    if report["secondary_findings"]:
        lines.append("Secondary Findings")
        for index, finding in enumerate(report["secondary_findings"], 1):
            conf_label = CONFIDENCE_LABEL.get(finding["confidence"], finding["confidence"].capitalize())
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']} ({conf_label})")
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
        f"Summary: {report.get('summary', '')}",
        "",
    ]
    lines.extend(_render_primary(report["primary_cause"]))
    lines.append("")

    if report["secondary_findings"]:
        lines.append("Secondary Findings")
        for index, finding in enumerate(report["secondary_findings"], 1):
            conf_label = CONFIDENCE_LABEL.get(finding["confidence"], finding["confidence"].capitalize())
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']} ({conf_label})")
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
            f"Direct queries failed for: {failed_hosts}. Cannot determine from outside whether this is a provider outage or a configuration issue.",
            "Fix the failed nameservers or remove them from delegation to avoid intermittent failures.",
            confidence="unknown",
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
            f"DS record exists but resolver sampling returned failures: {failing}. Cannot determine from outside whether the DS record or the zone signing is at fault.",
            "Verify the DNSKEY/DS chain or temporarily remove the bad DS record until signing is fixed.",
            confidence="unknown",
        )
    elif base["DS"]["values"]:
        positives.append("DS records are present at the parent zone.")

    findings = _sort_findings(findings)
    primary = _top_finding(findings)
    status = "healthy" if not primary else "issues-found"
    report = {
        "domain": domain,
        "generated_at": _timestamp(),
        "status": status,
        "summary": _make_summary(findings, status, context="domain"),
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
    dns_snap = domain_report["snapshot"]["dns"]
    ipv4_addrs = dns_snap["A"]["values"]
    ipv6_addrs = dns_snap["AAAA"]["values"]
    addresses = ipv4_addrs + ipv6_addrs

    # CDN detection — check NS and CNAME from the domain snapshot
    cdn = _detect_cdn(dns_snap["NS"]["values"], dns_snap["CNAME"]["values"])
    if cdn["detected"]:
        positives.append(
            f"Domain appears to be proxied through {cdn['provider']} (detected via {cdn['method']})."
            " Port and HTTP checks reflect edge behaviour, not the origin server."
        )

    port_state = {"80": False, "443": False}
    tls = None
    http_result = None
    https_result = None
    www_result = None

    if addresses:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            port_80_future  = ex.submit(_check_port, domain, 80)
            port_443_future = ex.submit(_check_port, domain, 443)
            www_future      = ex.submit(_fetch_url, f"http://www.{domain}")
            port_state["80"]  = port_80_future.result()
            port_state["443"] = port_443_future.result()
            www_result        = www_future.result()

        if port_state["80"]:
            positives.append("Port 80 is reachable.")
        if port_state["443"]:
            positives.append("Port 443 is reachable.")

        # www subdomain check
        if www_result and www_result.get("ok"):
            final = www_result.get("final_url", "")
            if domain in final:
                positives.append(f"www.{domain} redirects correctly to the apex.")
            else:
                positives.append(f"www.{domain} is reachable (HTTP {www_result['status_code']}).")
        elif www_result and not www_result.get("ok"):
            findings.append({
                "severity": "low",
                "title": f"www.{domain} is unreachable",
                "owner": "DNS provider / hosting provider",
                "evidence": f"www.{domain} returned: {www_result.get('error', 'no response')}.",
                "next_action": "Add a www CNAME or A record pointing to the same origin as the apex.",
                "confidence": "high",
            })

        # IPv4 / IPv6 dual-stack check
        if ipv4_addrs and ipv6_addrs:
            ipv4_ok = any(_check_port_by_ip(ip, 443) for ip in ipv4_addrs[:2])
            ipv6_ok = any(_check_port_by_ip(ip, 443) for ip in ipv6_addrs[:2])
            if ipv4_ok and not ipv6_ok:
                findings.append({
                    "severity": "medium",
                    "title": "IPv6 address(es) unreachable on HTTPS",
                    "owner": "hosting provider / firewall",
                    "evidence": (
                        f"IPv4 ({', '.join(ipv4_addrs[:2])}) answers on port 443 but "
                        f"IPv6 ({', '.join(ipv6_addrs[:2])}) does not."
                    ),
                    "next_action": "Fix the IPv6 listener or firewall rules — dual-stack visitors on IPv6-only networks will fail.",
                    "confidence": "high",
                })
            elif ipv6_ok and not ipv4_ok:
                findings.append({
                    "severity": "medium",
                    "title": "IPv4 address(es) unreachable on HTTPS",
                    "owner": "hosting provider / firewall",
                    "evidence": (
                        f"IPv6 ({', '.join(ipv6_addrs[:2])}) answers on port 443 but "
                        f"IPv4 ({', '.join(ipv4_addrs[:2])}) does not."
                    ),
                    "next_action": "Fix the IPv4 listener or firewall rules.",
                    "confidence": "high",
                })
            elif ipv4_ok and ipv6_ok:
                positives.append("Both IPv4 and IPv6 stacks answer on port 443.")

        if port_state["443"]:
            tls = _probe_tls(domain)
            if tls["ok"]:
                positives.append(
                    f"TLS handshake succeeds over {tls['version'] or 'unknown TLS'} and expires in {tls['days_remaining']} day(s)."
                )
                if tls["days_remaining"] is not None and tls["days_remaining"] < 30:
                    findings.append({
                        "severity": "medium",
                        "title": "TLS certificate expires soon",
                        "owner": "hosting provider / certificate automation",
                        "evidence": f"The active certificate expires in {tls['days_remaining']} day(s).",
                        "next_action": "Renew the certificate and confirm automated renewal is working.",
                        "confidence": "high",
                    })
            elif tls["error"]:
                findings.append({
                    "severity": "high",
                    "title": "TLS handshake failed on port 443",
                    "owner": "hosting provider / CDN / certificate automation",
                    "evidence": tls["error"],
                    "next_action": "Fix the certificate chain, hostname coverage, or HTTPS listener configuration.",
                    "confidence": "high",
                })

        if port_state["80"]:
            http_result = _fetch_url(f"http://{domain}")
        if port_state["443"]:
            https_result = _fetch_url(f"https://{domain}")

        # Update CDN detection with HTTP response headers if not already found
        if not cdn["detected"]:
            for fetch_result in (http_result, https_result):
                if fetch_result and fetch_result.get("headers"):
                    cdn = _detect_cdn([], [], fetch_result["headers"])
                    if cdn["detected"]:
                        positives.append(
                            f"Domain appears to be proxied through {cdn['provider']} (detected via response headers)."
                            " Port and HTTP checks reflect edge behaviour, not the origin server."
                        )
                        break

        if not port_state["80"] and not port_state["443"]:
            owner = f"{cdn['provider']} edge / origin / firewall" if cdn["detected"] else "hosting provider / firewall / CDN"
            findings.append({
                "severity": "high",
                "title": "Web service ports are unreachable",
                "owner": owner,
                "evidence": "Both port 80 and port 443 refused or timed out.",
                "next_action": "Check edge/origin reachability, firewall rules, and whether the service is listening.",
                "confidence": "high",
            })
        elif port_state["80"] and not port_state["443"]:
            findings.append({
                "severity": "medium",
                "title": "HTTP is reachable but HTTPS is not",
                "owner": "hosting provider / CDN / firewall",
                "evidence": "Port 80 is open while port 443 is closed or unreachable.",
                "next_action": "Restore the HTTPS listener and verify certificate termination on port 443.",
                "confidence": "high",
            })

        for result in (http_result, https_result):
            if not result:
                continue
            if not result["ok"]:
                error_text = result["error"]
                if error_text.startswith("redirect-loop"):
                    findings.append({
                        "severity": "high",
                        "title": "HTTP redirect loop detected",
                        "owner": "web platform / CDN / application config",
                        "evidence": f"{result['url']} triggered too many redirects.",
                        "next_action": "Review redirect rules between HTTP, HTTPS, CDN, and origin.",
                        "confidence": "high",
                    })
                elif error_text.startswith("ssl:"):
                    findings.append({
                        "severity": "high",
                        "title": "HTTPS request failed during SSL negotiation",
                        "owner": "hosting provider / CDN",
                        "evidence": error_text,
                        "next_action": "Repair the certificate or TLS configuration on the HTTPS endpoint.",
                        "confidence": "high",
                    })
                else:
                    findings.append({
                        "severity": "medium",
                        "title": f"{result['url']} request failed",
                        "owner": "hosting provider / network",
                        "evidence": f"{error_text}. Cannot determine from outside whether the cause is network, firewall, CDN, or origin.",
                        "next_action": "Check origin reachability, upstream health, and any proxy or CDN edge logs.",
                        "confidence": "unknown",
                    })
                continue

            # WAF / bot-block detection
            resp_obj = result.get("_response")
            waf = _is_waf_blocked(resp_obj) if resp_obj is not None else None
            code = result["status_code"]

            if waf and code in (403, 503):
                findings.append({
                    "severity": "medium",
                    "title": f"Request blocked by {waf}",
                    "owner": "CDN / WAF configuration",
                    "evidence": (
                        f"{result['url']} returned HTTP {code} with a {waf} bot-protection response. "
                        "The site may be intentionally blocking automated probes."
                    ),
                    "next_action": "Verify the site loads in a browser. If so, the WAF is blocking this tool — check WAF rules for overly aggressive bot filtering.",
                    "confidence": "medium",
                })
            elif code >= 500:
                owner = f"application / {cdn['provider']} origin" if cdn["detected"] else "application / origin infrastructure"
                findings.append({
                    "severity": "high",
                    "title": "Website returns server errors",
                    "owner": owner,
                    "evidence": f"{result['url']} returned HTTP {code} with final URL {result['final_url']}.",
                    "next_action": "Inspect origin or application logs and fix the upstream failure.",
                    "confidence": "high",
                })
            elif code in (403, 404):
                findings.append({
                    "severity": "medium",
                    "title": "Website responds but serves the wrong application state",
                    "owner": "application / virtual host configuration",
                    "evidence": f"{result['url']} returned HTTP {code} with final URL {result['final_url']}.",
                    "next_action": "Verify vhost routing, document root, and application deployment for this hostname.",
                    "confidence": "medium",
                })
            elif result["elapsed_ms"] > 2500:
                findings.append({
                    "severity": "low",
                    "title": "Website is slow after connection",
                    "owner": "application / origin / CDN",
                    "evidence": f"{result['url']} completed in {result['elapsed_ms']} ms.",
                    "next_action": "Profile origin latency, CDN cache status, and upstream dependency response times.",
                    "confidence": "medium",
                })
            else:
                positives.append(f"{result['url']} returned HTTP {code} in {result['elapsed_ms']} ms.")

    findings = _sort_findings(findings)
    primary = _top_finding(findings)
    status = "healthy" if not primary else "issues-found"
    # Strip internal _response object before storing
    for r in (http_result, https_result, www_result):
        if r:
            r.pop("_response", None)
    report = {
        "domain": domain,
        "generated_at": _timestamp(),
        "status": status,
        "summary": _make_summary(findings, status, context="website"),
        "primary_cause": primary,
        "secondary_findings": findings[1:],
        "positives": positives,
        "findings": findings,
        "snapshot": {
            "domain_diagnosis": domain_report,
            "cdn": cdn,
            "ports": port_state,
            "tls": tls,
            "http": http_result,
            "https": https_result,
            "www": www_result,
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


def run_email_diagnosis(domain):
    domain = domain.strip().lower()
    findings = []
    positives = []

    def add_finding(severity, title, owner, evidence, next_action, confidence="high"):
        findings.append({
            "severity": severity,
            "title": title,
            "owner": owner,
            "evidence": evidence,
            "next_action": next_action,
            "confidence": confidence,
        })

    # Gather MX, SPF, DMARC, DKIM concurrently; RBL needs MX IPs so runs after.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        mx_future   = ex.submit(collect_mx,    domain)
        spf_future  = ex.submit(collect_spf,   domain)
        dmarc_future= ex.submit(collect_dmarc, domain)
        dkim_future = ex.submit(collect_dkim,  domain)
        mx_data    = mx_future.result()
        spf_data   = spf_future.result()
        dmarc_data = dmarc_future.result()
        dkim_data  = dkim_future.result()

    mx_ips = [r["ip"] for r in mx_data.get("records", []) if r.get("ip")]
    rbl_data = collect_rbl(mx_ips) if mx_ips else {"listed": [], "checked_ips": 0}

    # ── MX ────────────────────────────────────────────────────────────────────
    if not mx_data["has_records"]:
        add_finding(
            "critical",
            "No MX records found",
            "DNS provider",
            f"MX lookup returned {mx_data.get('status', 'no answer')} — inbound mail cannot be delivered.",
            "Publish MX records pointing to your mail provider's servers.",
            confidence="high",
        )
    else:
        records = mx_data["records"]
        unresolvable = [r["host"] for r in records if not r["ip"]]
        port25_closed = [r["host"] for r in records if r["ip"] and not r["port25"]]
        no_rdns = [r["host"] for r in records if r["ip"] and not r["rdns"]]

        if unresolvable:
            add_finding(
                "critical",
                "MX host(s) do not resolve to an IP address",
                "DNS provider / mail provider",
                f"Unresolvable MX hosts: {', '.join(unresolvable)}.",
                "Fix the A record for each MX hostname or update the MX record to a resolvable host.",
                confidence="high",
            )

        if mx_ips and len(port25_closed) == len([r for r in records if r["ip"]]):
            add_finding(
                "critical",
                "Port 25 is closed on all reachable MX servers",
                "mail provider / firewall",
                f"All reachable MX hosts refused port 25 connections: {', '.join(port25_closed)}.",
                "Restore SMTP listener on port 25 or check firewall rules blocking inbound mail.",
                confidence="high",
            )
        elif port25_closed:
            add_finding(
                "medium",
                "Port 25 closed on some MX servers",
                "mail provider / firewall",
                f"Port 25 closed on: {', '.join(port25_closed)}.",
                "Fix the SMTP listener or firewall on the affected servers to avoid delivery failures.",
                confidence="high",
            )
        else:
            positives.append(f"Port 25 reachable on all {len([r for r in records if r['ip']])} MX server(s).")

        if no_rdns:
            add_finding(
                "medium",
                "MX server(s) missing reverse DNS (PTR record)",
                "mail provider / hosting provider",
                f"No PTR record found for: {', '.join(no_rdns)}.",
                "Add a PTR record matching the MX hostname — many receivers use this as a spam signal.",
                confidence="likely",
            )
        else:
            positives.append("All MX servers have reverse DNS.")

        mx_summary = ", ".join(f"{r['host']} (pri {r['priority']})" for r in records[:3])
        positives.append(f"MX records found: {mx_summary}.")

    # ── RBL ───────────────────────────────────────────────────────────────────
    if rbl_data["listed"]:
        for entry in rbl_data["listed"]:
            add_finding(
                "critical",
                f"Mail server IP blacklisted ({entry['ip']})",
                "mail provider / domain owner",
                f"IP {entry['ip']} is listed on: {', '.join(entry['listed_on'][:5])}.",
                "Submit a delist request to each blacklist and investigate the spam source.",
                confidence="high",
            )
    elif mx_ips:
        positives.append(f"MX server IP(s) clean on all checked blacklists ({rbl_data['checked_ips']} IP(s) verified).")

    # ── SPF ───────────────────────────────────────────────────────────────────
    if not spf_data["has_record"]:
        add_finding(
            "high",
            "No SPF record found",
            "DNS provider / domain owner",
            f"No TXT record starting with 'v=spf1' found for {domain}.",
            "Publish an SPF record authorising your sending mail servers.",
            confidence="high",
        )
    else:
        directive = spf_data["all_directive"]
        lookup_count = spf_data["lookup_count"]

        if directive in ("+all", "all"):
            add_finding(
                "critical",
                "SPF allows anyone to send mail as this domain (+all)",
                "domain owner / DNS provider",
                f"SPF record ends with '{directive}' — any server on the internet can pass SPF for this domain.",
                "Replace '+all' with '-all' and restrict the authorised sender list.",
                confidence="high",
            )
        elif directive in ("~all", "?all"):
            add_finding(
                "medium",
                f"SPF uses weak enforcement ({directive})",
                "domain owner",
                f"SPF directive is '{directive}' — failing mail is not rejected, only soft-failed or neutral.",
                "Upgrade to '-all' once you have confirmed all legitimate senders are listed.",
                confidence="high",
            )
        else:
            positives.append(f"SPF uses strict '-all' enforcement.")

        if lookup_count > 10:
            add_finding(
                "high",
                "SPF lookup count exceeds the RFC 7208 limit of 10",
                "domain owner / DNS provider",
                f"Resolving the full include chain required {lookup_count} DNS lookups — receivers will return PERMERROR.",
                "Flatten the SPF record or reduce include chains to stay within 10 lookups.",
                confidence="high",
            )
        elif lookup_count >= 8:
            add_finding(
                "medium",
                "SPF lookup count is approaching the RFC 7208 limit",
                "domain owner",
                f"Current lookup count is {lookup_count}/10 — adding any sender will exceed the limit.",
                "Flatten the SPF record now to avoid future PERMERROR failures.",
                confidence="high",
            )
        else:
            positives.append(f"SPF lookup count is {lookup_count}/10 — within the RFC limit.")

    # ── DMARC ─────────────────────────────────────────────────────────────────
    if not dmarc_data["has_record"]:
        add_finding(
            "high",
            "No DMARC record found",
            "domain owner / DNS provider",
            f"No TXT record found at _dmarc.{domain} — the domain is unprotected against spoofing.",
            f"Publish a DMARC record at _dmarc.{domain}, starting with p=none for monitoring.",
            confidence="high",
        )
    else:
        policy = dmarc_data["policy"]
        pct = dmarc_data["pct"]
        rua = dmarc_data["rua"]

        if policy == "none":
            add_finding(
                "high",
                "DMARC policy is 'none' — monitoring only, no enforcement",
                "domain owner",
                "p=none means receivers take no action on failing mail. Spoofed mail is delivered.",
                "Upgrade to p=quarantine once you have reviewed aggregate reports, then to p=reject.",
                confidence="high",
            )
        elif policy == "quarantine":
            add_finding(
                "low",
                "DMARC policy is 'quarantine' — consider upgrading to 'reject'",
                "domain owner",
                "p=quarantine sends failing mail to spam rather than rejecting it outright.",
                "Upgrade to p=reject for maximum spoofing protection once you are confident in coverage.",
                confidence="high",
            )
        else:
            positives.append("DMARC policy is 'reject' — strongest spoofing protection active.")

        if pct != "100":
            add_finding(
                "medium",
                f"DMARC enforcement is partial (pct={pct})",
                "domain owner",
                f"Only {pct}% of failing messages are subject to the DMARC policy.",
                "Increase pct to 100 once you are confident all legitimate senders pass alignment.",
                confidence="high",
            )
        else:
            positives.append("DMARC pct=100 — policy applies to all messages.")

        if not rua:
            add_finding(
                "low",
                "DMARC has no aggregate report destination (rua)",
                "domain owner",
                "Without rua= you receive no visibility into who is sending mail as your domain.",
                "Add rua=mailto:dmarc@yourdomain.com or a third-party DMARC reporting service.",
                confidence="high",
            )
        else:
            positives.append(f"DMARC aggregate reports configured: {rua}.")

    # ── DKIM ──────────────────────────────────────────────────────────────────
    found_dkim = dkim_data.get("found", [])
    if not found_dkim:
        add_finding(
            "medium",
            "No DKIM records found for any known selector",
            "mail provider / domain owner",
            "Probed 28 common selectors — none returned a valid DKIM public key.",
            "Check your mail provider's setup guide for the correct selector name and publish the DKIM TXT record.",
            confidence="unknown",
        )
    else:
        weak = [r for r in found_dkim if r["weak"]]
        if weak:
            add_finding(
                "medium",
                "Weak DKIM key detected",
                "mail provider / domain owner",
                f"Selector(s) with weak keys: {', '.join(r['selector'] + ' (' + r['key_length'] + ')' for r in weak)}.",
                "Rotate to a 2048-bit RSA or Ed25519 key.",
                confidence="high",
            )
        else:
            positives.append(
                f"DKIM active on {len(found_dkim)} selector(s): {', '.join(r['selector'] for r in found_dkim)}."
            )

    findings = _sort_findings(findings)
    primary = _top_finding(findings)
    status = "healthy" if not primary else "issues-found"
    return {
        "domain": domain,
        "generated_at": _timestamp(),
        "status": status,
        "summary": _make_summary(findings, status, context="email"),
        "primary_cause": primary,
        "secondary_findings": findings[1:],
        "positives": positives,
        "findings": findings,
        "snapshot": {
            "mx": mx_data,
            "spf": spf_data,
            "dmarc": dmarc_data,
            "dkim": dkim_data,
            "rbl": rbl_data,
        },
    }


def render_email_diagnosis_text(report):
    lines = [
        "EMAIL DIAGNOSIS",
        f"Domain: {report['domain']}",
        f"Generated: {report['generated_at']}",
        f"Status: {report['status']}",
        f"Summary: {report.get('summary', '')}",
        "",
    ]
    lines.extend(_render_primary(report["primary_cause"]))
    lines.append("")

    if report["secondary_findings"]:
        lines.append("Secondary Findings")
        for index, finding in enumerate(report["secondary_findings"], 1):
            conf_label = CONFIDENCE_LABEL.get(finding["confidence"], finding["confidence"].capitalize())
            lines.append(f"{index}. [{finding['severity'].upper()}] {finding['title']} ({conf_label})")
            lines.append(f"   Owner: {finding['owner']}")
            lines.append(f"   Evidence: {finding['evidence']}")
            lines.append(f"   Action: {finding['next_action']}")
        lines.append("")

    if report["positives"]:
        lines.append("Positive Signals")
        for item in report["positives"]:
            lines.append(f"- {item}")

    return "\n".join(lines).strip()


def diagnose_email(domain=None):
    return _interactive_report(
        domain,
        run_email_diagnosis,
        render_email_diagnosis_text,
        "diagnose_email",
        "Diagnose Email",
        "diagnose_email",
    )
