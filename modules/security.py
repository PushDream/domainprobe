"""
Security Module
───────────────
• SSL/TLS inspector — cert chain, SANs, expiry, cipher, hostname match
• DNSSEC validator — DS, DNSKEY, RRSIG, validation test
• DNS-over-HTTPS (DoH) probe — Cloudflare, Google, Quad9, NextDNS
• CAA record analyzer
"""

import ssl, socket, datetime, re, concurrent.futures
import requests
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt
from .display import console, section, ok, warn, err, info, get_domain, days_label, Spinner
from .dns_core import resolve_safe
from . import session

# ── SSL / TLS Inspector ───────────────────────────────────────────────────────
def ssl_inspector(domain=None):
    if domain is None: domain = get_domain()
    section(f"SSL/TLS Certificate Inspector — {domain}")
    port = int(Prompt.ask("  [cyan]Port[/cyan]", default="443"))

    cert, cipher, version, verified = None, None, None, True

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(); cipher = ssock.cipher(); version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        err(f"Certificate verification FAILED: {e}")
        verified = False
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(); cipher = ssock.cipher(); version = ssock.version()
        except Exception as e2:
            err(f"Could not retrieve cert: {e2}"); session.store("ssl", domain, {"error": str(e2)}); return None
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        err(f"Could not connect to {domain}:{port} — {e}"); session.store("ssl", domain, {"error": str(e)}); return None
    except Exception as e:
        err(f"SSL error: {e}"); session.store("ssl", domain, {"error": str(e)}); return None

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Field", style="bold yellow", width=22)
    table.add_column("Value", style="white")

    result = {}
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    cn       = subject.get("commonName", "Unknown")
    issuer_cn = issuer.get("commonName", "Unknown")
    issuer_o  = issuer.get("organizationName","")

    table.add_row("Common Name (CN)", cn)
    table.add_row("Issuer", f"{issuer_cn} / {issuer_o}" if issuer_o else issuer_cn)
    result.update({"cn": cn, "issuer": issuer_cn})

    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    san_display = "\n".join(sans[:12]) + (f"\n  (+{len(sans)-12} more)" if len(sans) > 12 else "")
    table.add_row("Subject Alt Names", san_display or "[dim]None[/dim]")
    result["sans"] = sans

    not_before_s = cert.get("notBefore","")
    not_after_s  = cert.get("notAfter","")
    try:
        not_after_dt = datetime.datetime.strptime(not_after_s, "%b %d %H:%M:%S %Y %Z")
        exp_display  = not_after_dt.strftime("%Y-%m-%d") + "  " + days_label(not_after_dt)
        result["expires"] = not_after_dt.strftime("%Y-%m-%d")
    except Exception:
        exp_display = not_after_s
    table.add_row("Valid From",  not_before_s)
    table.add_row("Valid Until", exp_display)
    table.add_row("Protocol",    version or "Unknown")
    if cipher:
        table.add_row("Cipher Suite", cipher[0])
        table.add_row("Key Bits",     str(cipher[2]) if cipher[2] else "?")
    table.add_row("Verified",    "[green]Yes[/green]" if verified else "[red]No — self-signed or mismatched[/red]")

    console.print(table)
    console.print()

    # Hostname match
    wildcard = f"*.{'.'.join(domain.split('.')[1:])}"
    if domain == cn or domain in sans or wildcard in sans:
        ok(f"Hostname match — certificate covers [bold]{domain}[/bold]")
    else:
        err(f"Hostname MISMATCH — cert does not cover {domain}")
        info(f"CN: {cn} | First 3 SANs: {', '.join(sans[:3])}")

    # Protocol security rating
    protocol_scores = {"TLSv1.3":"best","TLSv1.2":"ok","TLSv1.1":"old","TLSv1":"old","SSLv3":"insecure"}
    ps = protocol_scores.get(version, "unknown")
    if   ps == "best": ok(f"TLS 1.3 — best available protocol.")
    elif ps == "ok":   info("TLS 1.2 — acceptable but TLS 1.3 preferred.")
    else:              err(f"Outdated protocol: {version} — upgrade immediately.")

    session.store("ssl", domain, result)
    return result

# ── DNSSEC Validator ──────────────────────────────────────────────────────────
def dnssec_validator(domain=None):
    if domain is None: domain = get_domain()
    section(f"DNSSEC Validator — {domain}")

    results = {}

    # 1. DS at parent zone
    ds_vals, _, ds_status = resolve_safe(domain, "DS", "8.8.8.8")
    if ds_status == "ok" and ds_vals:
        ok(f"DS record present at parent zone ({len(ds_vals)} record(s)).")
        t = Table(box=box.SIMPLE, padding=(0,1))
        t.add_column("DS Record", style="dim")
        for v in ds_vals: t.add_row(v[:80])
        console.print(t)
        results["ds"] = {"found": True, "records": ds_vals}
    else:
        err("No DS record — DNSSEC not configured at registry level.")
        results["ds"] = {"found": False}

    # 2. DNSKEY at authoritative
    console.print()
    dnskey_vals, _, dnskey_status = resolve_safe(domain, "DNSKEY")
    if dnskey_status == "ok" and dnskey_vals:
        ok(f"DNSKEY present ({len(dnskey_vals)} key(s)).")
        for v in dnskey_vals:
            flags = int(v.split()[0]) if v.split() else 0
            key_type = "KSK (Key Signing Key)" if flags == 257 else "ZSK (Zone Signing Key)"
            console.print(f"  [dim]Flags {v.split()[0] if v.split() else '?'}: {key_type}[/dim]")
        results["dnskey"] = {"found": True, "count": len(dnskey_vals)}
    else:
        warn("No DNSKEY records found.")
        results["dnskey"] = {"found": False}

    # 3. RRSIG
    rrsig_vals, _, rrsig_status = resolve_safe(domain, "RRSIG")
    console.print()
    if rrsig_status == "ok" and rrsig_vals:
        ok("RRSIG records present — zone is signed.")
        results["rrsig"] = {"found": True}
    else:
        warn("No RRSIG records found via standard query.")
        results["rrsig"] = {"found": False}

    # 4. Enforcement test via Cloudflare (validates DNSSEC)
    console.print()
    info("Testing DNSSEC enforcement via Cloudflare (1.1.1.1)…")
    broken_vals, _, broken_status = resolve_safe("dnssec-failed.org", "A", "1.1.1.1", timeout=6)
    if broken_status in ("SERVFAIL","NO_NS") or "SERVFAIL" in str(broken_status):
        ok("Resolver enforces DNSSEC validation (broken domain returned SERVFAIL ✓).")
    elif broken_status == "TIMEOUT":
        info("Enforcement test inconclusive (timeout).")
    else:
        info(f"Enforcement test result: {broken_status}")

    # Summary
    console.print()
    if results["ds"]["found"] and results["dnskey"]["found"]:
        ok("[bold]DNSSEC fully configured and active.[/bold]")
    else:
        warn("DNSSEC is NOT configured.")
        info("Enable DNSSEC at your registrar — they submit the DS record to the parent zone.")
        info("Without DNSSEC, the domain is vulnerable to DNS cache poisoning (Kaminsky attack).")

    session.store("dnssec", domain, results)
    return results

# ── DNS-over-HTTPS Probe ──────────────────────────────────────────────────────
def doh_probe(domain=None):
    if domain is None: domain = get_domain()
    section(f"DNS-over-HTTPS (DoH) Probe — {domain}")

    endpoints = {
        "Cloudflare": f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
        "Google":     f"https://dns.google/resolve?name={domain}&type=A",
        "Quad9":      f"https://dns.quad9.net/dns-query?name={domain}&type=A",
        "NextDNS":    f"https://dns.nextdns.io/dns-query?name={domain}&type=A",
    }

    def query(item):
        name, url = item
        try:
            r = requests.get(url, timeout=8, headers={"Accept":"application/dns-json"})
            d = r.json()
            if d.get("Status") == 0:
                return name, sorted(a["data"] for a in d.get("Answer",[]) if a.get("type")==1), "ok"
            elif d.get("Status") == 3:
                return name, [], "NXDOMAIN"
            return name, [], f"Status:{d.get('Status')}"
        except Exception as e:
            return name, [], f"error:{str(e)[:40]}"

    with Spinner("Querying DoH endpoints"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            raw = list(ex.map(query, endpoints.items()))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Provider", style="bold yellow", width=14)
    table.add_column("Answer",   style="white")
    table.add_column("Status",   width=14)

    results, all_answers = {}, []
    for name, answers, status in raw:
        if status == "ok" and answers:
            all_answers.append(tuple(answers))
            table.add_row(name, "\n".join(answers), "[green]✓ Resolved[/green]")
        elif status == "NXDOMAIN":
            all_answers.append(("NXDOMAIN",)); table.add_row(name, "[red]NXDOMAIN[/red]", "[red]NXDOMAIN[/red]")
        else:
            table.add_row(name, f"[dim]{status}[/dim]", "[yellow]– Error[/yellow]")
        results[name] = {"answers": answers, "status": status}

    console.print(table)
    console.print()

    unique = set(all_answers)
    if len(unique) <= 1 and all_answers:
        ok("All DoH providers agree — consistent resolution over HTTPS.")
    elif len(unique) > 1:
        warn("DoH providers return different answers — possible regional filtering or hijacking.")
        info("Compare with standard DNS (option 1) to identify the discrepancy.")

    session.store("doh", domain, results)
    return results

# ── CAA Record Analyzer ───────────────────────────────────────────────────────
def caa_analyzer(domain=None):
    if domain is None: domain = get_domain()
    section(f"CAA Record Analyzer — {domain}")

    vals, ttl, status = resolve_safe(domain, "CAA")
    if status != "ok" or not vals:
        warn("No CAA records found.")
        info("Without CAA, any Certificate Authority can issue certs for your domain.")
        info(f'Recommended: 0 issue "letsencrypt.org"  (or your CA of choice)')
        session.store("caa", domain, {"found": False}); return None

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Flag",  style="bold yellow", width=6)
    table.add_column("Tag",   style="cyan",        width=12)
    table.add_column("Value", style="white")
    table.add_column("Meaning")

    cas = []
    tag_meanings = {
        "issue":     "Authorized CA for standard certificates",
        "issuewild": "Authorized CA for wildcard certificates",
        "iodef":     "Report violations to this address",
        "contactemail": "Security contact email",
    }
    for v in vals:
        parts = v.split(None, 2)
        flag = parts[0] if parts else ""
        tag  = parts[1] if len(parts)>1 else ""
        val  = parts[2].strip('"') if len(parts)>2 else ""
        meaning = tag_meanings.get(tag, "[dim]Custom tag[/dim]")
        table.add_row(flag, tag, val, meaning)
        cas.append({"flag": flag, "tag": tag, "value": val})

    console.print(table)
    console.print()
    ok(f"CAA records configured — {sum(1 for c in cas if c['tag']=='issue')} issuance restriction(s).")

    if not any(c["tag"] == "iodef" for c in cas):
        info("Consider adding an iodef tag to receive CA violation notifications.")
    if not any(c["tag"] == "issuewild" for c in cas):
        info("No issuewild tag — wildcard certs fall under issue policy.")

    session.store("caa", domain, {"found": True, "records": cas})
    return cas
