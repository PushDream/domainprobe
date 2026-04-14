"""
DNS Core
────────
• DNS record lookup (15 types, custom resolver)
• Parallel propagation check (9 resolvers)
• NS consistency & SOA serial validation
• Zone delegation validator (registrar NS vs auth NS)
• CNAME conflict detector + TTL anomaly analyzer
• Wildcard DNS detector
"""

import socket, concurrent.futures
import dns.resolver, dns.exception
from rich.table import Table
from rich import box
from rich.prompt import Prompt
from .display import console, section, ok, warn, err, info, get_domain, Spinner
from . import session

# ── Constants ─────────────────────────────────────────────────────────────────
RESOLVERS = {
    "Google Primary       8.8.8.8":       "8.8.8.8",
    "Google Secondary     8.8.4.4":       "8.8.4.4",
    "Cloudflare Primary   1.1.1.1":       "1.1.1.1",
    "Cloudflare Alt       1.0.0.1":       "1.0.0.1",
    "OpenDNS              208.67.222.222": "208.67.222.222",
    "Quad9                9.9.9.9":        "9.9.9.9",
    "Level3               4.2.2.2":        "4.2.2.2",
    "Comodo Secure        8.26.56.26":     "8.26.56.26",
    "Verisign             64.6.64.6":      "64.6.64.6",
}

ALL_TYPES = ["A","AAAA","MX","NS","TXT","SOA","CNAME","SRV",
             "CAA","PTR","DNSKEY","DS","NAPTR","HINFO","TLSA"]

# ── Core resolver helper ──────────────────────────────────────────────────────
def resolve_safe(domain: str, rtype: str, resolver_ip: str = None, timeout: int = 6):
    """Return (values_list, ttl, status_string).  Never raises."""
    r = dns.resolver.Resolver(configure=False)
    # Always set explicit nameservers — avoids NoResolverConfiguration on Windows/containers
    r.nameservers = [resolver_ip] if resolver_ip else ["8.8.8.8", "8.8.4.4"]
    r.lifetime = timeout
    try:
        ans = r.resolve(domain, rtype)
        return [str(x) for x in ans], ans.rrset.ttl, "ok"
    except dns.resolver.NXDOMAIN:          return [], 0, "NXDOMAIN"
    except dns.resolver.NoAnswer:          return [], 0, "NOANSWER"
    except dns.resolver.NoNameservers:     return [], 0, "NO_NS"
    except dns.exception.Timeout:         return [], 0, "TIMEOUT"
    except Exception as e:                 return [], 0, f"ERROR:{e}"

# ── 1. DNS Record Lookup ──────────────────────────────────────────────────────
def dns_lookup(domain=None, record_types=None, resolver_ip=None, silent=False):
    if domain is None:
        domain = get_domain()
    if record_types is None:
        console.print(f"\n  [dim]Available: {', '.join(ALL_TYPES)}[/dim]")
        raw = Prompt.ask("  [cyan]Record type(s)[/cyan] [dim](comma-separated or ALL)[/dim]",
                         default="A,MX,NS,TXT,SOA")
        record_types = (ALL_TYPES if raw.strip().upper() == "ALL"
                        else [t.strip().upper() for t in raw.split(",")])

    if not silent:
        section(f"DNS Record Lookup — {domain}")
        if resolver_ip:
            info(f"Using resolver: {resolver_ip}")

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Type",  style="bold yellow", width=9)
    table.add_column("Value", style="white")
    table.add_column("TTL",   style="dim",         width=7)

    results = {}
    for rtype in record_types:
        vals, ttl, status = resolve_safe(domain, rtype, resolver_ip)
        if status == "ok" and vals:
            for v in vals:
                table.add_row(rtype, v, str(ttl))
            results[rtype] = {"values": vals, "ttl": ttl}
        elif status == "NXDOMAIN":
            table.add_row(rtype, "[red]NXDOMAIN — domain does not exist[/red]", "–")
            results[rtype] = {"error": "NXDOMAIN"}
        elif status == "NOANSWER":
            table.add_row(rtype, "[dim]No records[/dim]", "–")
            results[rtype] = {"values": []}
        else:
            table.add_row(rtype, f"[red]{status}[/red]", "–")
            results[rtype] = {"error": status}

    console.print(table)
    session.store("dns_lookup", domain, results)
    return results

# ── 2. Propagation Check (parallel) ──────────────────────────────────────────
def _query_resolver(args):
    name, ip, domain, rtype = args
    vals, ttl, status = resolve_safe(domain, rtype, ip, timeout=5)
    return name, ip, sorted(vals), ttl, status

def propagation_check(domain=None, rtype=None, silent=False):
    if domain is None:
        domain = get_domain()
    if rtype is None:
        rtype = Prompt.ask("  [cyan]Record type[/cyan]", default="A").upper()

    if not silent:
        section(f"Propagation Check — {domain}  [{rtype}]")

    with Spinner(f"Querying {len(RESOLVERS)} resolvers in parallel"):
        args = [(n, ip, domain, rtype) for n, ip in RESOLVERS.items()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as ex:
            raw = list(ex.map(_query_resolver, args))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Resolver",  style="bold yellow", width=38)
    table.add_column("Answer",    style="white")
    table.add_column("TTL",       style="dim",        width=7)
    table.add_column("Status",    width=14)

    results, all_answers = {}, []
    for name, ip, vals, ttl, status in raw:
        if status == "ok" and vals:
            all_answers.append(tuple(vals))
            table.add_row(name, "\n".join(vals), str(ttl), "[green]✓ Resolved[/green]")
            results[name] = {"values": vals, "ttl": ttl}
        elif status == "NXDOMAIN":
            all_answers.append(("NXDOMAIN",))
            table.add_row(name, "[red]NXDOMAIN[/red]", "–", "[red]✗ NXDOMAIN[/red]")
            results[name] = {"status": "NXDOMAIN"}
        elif status == "TIMEOUT":
            table.add_row(name, "[red]Timeout[/red]", "–", "[red]✗ Timeout[/red]")
            results[name] = {"status": "timeout"}
        else:
            table.add_row(name, f"[dim]{status}[/dim]", "–", "[yellow]– No answer[/yellow]")
            results[name] = {"status": status}

    console.print(table)

    unique = set(all_answers)
    if len(unique) <= 1:
        ok("Fully propagated — all resolvers agree.")
    else:
        warn(f"Inconsistent — {len(unique)} different answer sets across resolvers.")
        for u in unique:
            console.print(f"    • {', '.join(u)}")
        info("Typical propagation delay: 15 min – 48 h depending on TTL.")

    session.store("propagation", domain, results)
    return results

# ── 3. NS Consistency & SOA Validator ─────────────────────────────────────────
def ns_consistency_check(domain=None):
    if domain is None:
        domain = get_domain()

    section(f"NS Consistency & SOA Validation — {domain}")

    ns_vals, _, ns_status = resolve_safe(domain, "NS")
    if ns_status != "ok" or not ns_vals:
        err(f"Could not retrieve NS records: {ns_status}"); return

    info(f"Found {len(ns_vals)} nameserver(s): {', '.join(ns_vals)}")

    def check_ns(ns):
        ns = ns.rstrip(".")
        try:    ip = socket.gethostbyname(ns)
        except: return ns, None, None, None, False, "unresolvable"

        soa_vals, soa_ttl, soa_status = resolve_safe(domain, "SOA", ip, timeout=6)
        serial, auth = None, False
        if soa_status == "ok" and soa_vals:
            parts = soa_vals[0].split()
            if len(parts) >= 3:
                serial = parts[2]; auth = True
        elif soa_status == "NOANSWER":
            auth = True
        return ns, ip, serial, soa_ttl if soa_status=="ok" else None, auth, soa_status

    with Spinner("Querying each nameserver directly"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            ns_results = list(ex.map(check_ns, ns_vals))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Nameserver",      style="bold yellow")
    table.add_column("IP",              style="white", width=16)
    table.add_column("SOA Serial",      style="cyan",  width=14)
    table.add_column("SOA TTL",         style="dim",   width=9)
    table.add_column("Authoritative",   width=14)
    table.add_column("Status",          width=12)

    serials, results = {}, {}
    for ns, ip, serial, soa_ttl, auth, status in ns_results:
        if serial: serials[ns] = serial
        table.add_row(
            ns,
            ip or "[red]Unresolvable[/red]",
            serial or "[red]–[/red]",
            str(soa_ttl) if soa_ttl else "–",
            "[green]✓ Yes[/green]"  if auth else "[red]✗ Lame[/red]",
            "[green]OK[/green]"     if status == "ok" else f"[red]{status}[/red]",
        )
        results[ns] = {"ip": ip, "serial": serial, "auth": auth, "status": status}

    console.print(table)

    unique_serials = set(serials.values())
    if len(unique_serials) == 1:
        ok(f"SOA serials match across all NS: [bold]{list(unique_serials)[0]}[/bold]")
    elif len(unique_serials) > 1:
        warn(f"SOA serial MISMATCH: {', '.join(unique_serials)}")
        info("Primary→Secondary replication lag. The NS with lower serial hasn't synced yet.")
    else:
        err("Could not retrieve SOA from any nameserver.")

    lame = [ns for ns, _, _, _, auth, _ in ns_results if not auth]
    if lame:
        warn(f"Lame delegation: {', '.join(lame)}")
        info("Listed in NS records but not authoritative for this zone — fix delegation.")

    # Zone delegation check inline
    console.print()
    info("Comparing registrar delegation vs authoritative NS response…")
    registrar_ns = sorted(v.rstrip(".").lower() for v in ns_vals)
    auth_ns = []
    if ns_results and ns_results[0][1]:
        auth_vals, _, _ = resolve_safe(domain, "NS", ns_results[0][1])
        auth_ns = sorted(v.rstrip(".").lower() for v in auth_vals)

    all_ns = sorted(set(registrar_ns + auth_ns))
    mismatch = False
    dt = Table(box=box.SIMPLE, header_style="bold white", padding=(0,1))
    dt.add_column("Nameserver", style="white")
    dt.add_column("Registrar",  width=12)
    dt.add_column("Auth NS",    width=12)
    for ns in all_ns:
        in_r = ns in registrar_ns; in_a = ns in auth_ns
        if not (in_r and in_a): mismatch = True
        dt.add_row(ns,
                   "[green]✓[/green]" if in_r else "[red]✗[/red]",
                   "[green]✓[/green]" if in_a else "[red]✗[/red]")
    console.print(dt)
    if mismatch:
        warn("Zone delegation mismatch — registrar NS ≠ authoritative NS.")
        info("Causes split-brain resolution: some users see old NS, some see new.")
    elif all_ns:
        ok("Zone delegation consistent — registrar and authoritative agree.")

    session.store("ns_consistency", domain, {"ns": results, "serials": serials, "delegation_mismatch": mismatch})
    return results

# ── 4. CNAME Conflict & TTL Anomaly Analyzer ─────────────────────────────────
def cname_ttl_analyzer(domain=None):
    if domain is None:
        domain = get_domain()

    section(f"CNAME Conflict & TTL Anomaly Analyzer — {domain}")
    issues = []

    # ── CNAME conflict check ──
    cname_vals, _, cname_status = resolve_safe(domain, "CNAME")
    if cname_status == "ok" and cname_vals:
        info(f"CNAME found → {cname_vals[0]}")
        conflicts = []
        for rt in ["A", "AAAA", "MX", "NS", "TXT"]:
            v, _, s = resolve_safe(domain, rt)
            if s == "ok" and v: conflicts.append(rt)
        if conflicts:
            err(f"CNAME CONFLICT — coexists with: {', '.join(conflicts)}")
            warn("Violates RFC 1034 §3.6.2 — causes unpredictable resolution. Remove conflicting records.")
            issues.append(f"CNAME conflict with: {', '.join(conflicts)}")
        else:
            ok("No CNAME conflicts.")
    else:
        ok("No CNAME at apex — no conflict risk.")

    # ── TTL analysis ──
    console.print()
    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Record", style="bold yellow", width=8)
    table.add_column("TTL",    style="white",       width=10)
    table.add_column("Assessment")

    ttl_data = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]:
        vals, ttl, status = resolve_safe(domain, rtype)
        if status != "ok" or not vals: continue
        if ttl < 60:
            assessment = f"[bold red]Critically low ({ttl}s) — instability risk[/bold red]"
            issues.append(f"{rtype} TTL critically low: {ttl}s")
        elif ttl < 300:
            assessment = f"[yellow]Low ({ttl}s) — may indicate pending change[/yellow]"
            issues.append(f"{rtype} TTL low: {ttl}s — check if intentional")
        elif ttl > 86400:
            assessment = f"[yellow]Very high ({ttl}s = {ttl//3600}h) — slow propagation after changes[/yellow]"
        else:
            assessment = f"[green]Normal ({ttl}s)[/green]"
        table.add_row(rtype, str(ttl), assessment)
        ttl_data[rtype] = ttl

    console.print(table)

    # ── Wildcard check ──
    console.print()
    probe = f"nxdomaintest-{id(domain)}.{domain}"
    wc_vals, _, wc_status = resolve_safe(probe, "A")
    if wc_status == "ok" and wc_vals:
        warn(f"Wildcard DNS active — *.{domain} resolves. May mask misconfigured subdomains.")
        issues.append("Wildcard DNS active")
    else:
        ok("No wildcard DNS detected.")

    if not issues:
        ok("No configuration anomalies found.")

    session.store("cname_ttl", domain, {"issues": issues, "ttl": ttl_data})
    return {"issues": issues, "ttl": ttl_data}
