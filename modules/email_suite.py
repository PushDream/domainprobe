"""
Email Deliverability Suite
──────────────────────────
• SPF recursive analyzer — resolves include chains, counts lookups, flags +all
• DMARC inspector — policy, alignment, reporting tags
• DKIM selector prober — 28 selectors, key type & length detection
• MX validator — priority, reachability (port 25/587), reverse DNS
• RBL / blacklist checker — 18 DNSBLs in parallel
"""

import re, socket, concurrent.futures
import dns.resolver, dns.exception
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt
from .display import console, section, ok, warn, err, info, get_domain, Spinner
from .dns_core import resolve_safe
from . import session

DKIM_SELECTORS = [
    "default","google","selector1","selector2","mail","k1","dkim","smtp",
    "email","mailjet","sendgrid","mandrill","amazonses","zoho","mailgun",
    "pm","s1","s2","key1","key2","mimecast","mx","protonmail",
    "protonmail2","protonmail3","dkimkey","m1","em1",
]

RBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "pbl.spamhaus.org",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "hostkarma.junkemailfilter.com",
    "dnsbl.spfbl.net",
    "drone.abuse.ch",
    "spamrbl.imp.ch",
    "truncate.gbudb.net",
    "dnsbl.justspam.org",
    "all.spamrats.com",
]

# ── SPF Recursive Analyzer ────────────────────────────────────────────────────
def _spf_recurse(domain, depth=0, lookup_count=None, visited=None):
    if lookup_count is None: lookup_count = [0]
    if visited      is None: visited      = set()
    if depth > 12 or domain in visited:
        return [], lookup_count[0], "redirect-loop", ["Redirect loop or depth > 12 detected"]
    visited.add(domain)

    warnings = []
    vals, _, status = resolve_safe(domain, "TXT")
    if status != "ok":
        return [], lookup_count[0], f"no-spf ({status})", warnings

    spf_record = next((v.strip('"').strip("'") for v in vals
                       if v.strip('"').strip("'").startswith("v=spf1")), None)
    if not spf_record:
        return [], lookup_count[0], "no-spf-record", warnings

    ips = []
    for mech in spf_record.split()[1:]:
        bare = mech.lstrip("+-?~")
        if bare.startswith("include:"):
            lookup_count[0] += 1
            if lookup_count[0] > 10:
                warnings.append("DNS lookup limit (10) exceeded — SPF will PERMERROR on this path")
            sub_ips, _, _, sub_w = _spf_recurse(bare[8:], depth+1, lookup_count, visited)
            ips.extend(sub_ips); warnings.extend(sub_w)
        elif bare.startswith("ip4:"):
            ips.append(("ip4", bare[4:]))
        elif bare.startswith("ip6:"):
            ips.append(("ip6", bare[4:]))
        elif bare.startswith(("a","mx","exists:")):
            lookup_count[0] += 1
            if lookup_count[0] > 10:
                warnings.append("DNS lookup limit exceeded")
        elif bare.startswith("redirect="):
            lookup_count[0] += 1
            return _spf_recurse(bare[9:], depth+1, lookup_count, visited)

    return ips, lookup_count[0], spf_record, warnings

def spf_analyzer(domain=None):
    if domain is None: domain = get_domain()
    section(f"SPF Analyzer — {domain}")

    with Spinner("Recursively resolving SPF include chain"):
        ips, lookup_count, record_or_status, warnings = _spf_recurse(domain)

    if "no-spf" in str(record_or_status):
        err("No SPF record found.")
        info(f'Add TXT record: v=spf1 include:_spf.yourprovider.com -all')
        session.store("spf", domain, {"error": "no_spf"}); return None

    spf = record_or_status
    console.print(f"\n  [bold]SPF Record:[/bold] [dim]{spf}[/dim]\n")

    # All directive
    all_match = re.search(r'([+\-?~]?all)\b', spf)
    all_d = all_match.group(1) if all_match else None
    directives = {
        "-all": ("[bold green]-all[/bold green]", "Hardfail — strict, recommended"),
        "~all": ("[yellow]~all[/yellow]",         "Softfail — mail marked but accepted"),
        "?all": ("[yellow]?all[/yellow]",          "Neutral — SPF has no practical effect"),
        "+all": ("[bold red]+all[/bold red]",      "PASS ALL — anyone can spoof your domain!"),
        "all":  ("[bold red]all[/bold red]",       "PASS ALL — same as +all"),
    }
    if all_d in directives:
        col, desc = directives[all_d]
        lvl = err if all_d in ("+all","all") else (ok if all_d=="-all" else warn)
        lvl(f"All directive: {col} — {desc}")
        if all_d in ("+all","all"):
            warnings.append("CRITICAL: +all allows anyone to send email as your domain")
    else:
        warn("No 'all' directive — SPF record is incomplete")

    # Lookup count
    console.print()
    if lookup_count > 10:
        err(f"DNS lookup count: [bold red]{lookup_count}/10[/bold red] — EXCEEDS RFC 7208 limit!")
        warnings.append(f"Lookup count {lookup_count} > 10 → PERMERROR on strict receivers")
    elif lookup_count >= 8:
        warn(f"DNS lookup count: [yellow]{lookup_count}/10[/yellow] — Approaching limit. Consider flattening.")
    else:
        ok(f"DNS lookup count: [green]{lookup_count}/10[/green] — Within limit.")

    # Authorised IPs
    if ips:
        console.print()
        info(f"Resolved {len(ips)} authorised IP block(s):")
        t = Table(box=box.SIMPLE, header_style="bold white", padding=(0,1))
        t.add_column("Type",  style="yellow", width=5)
        t.add_column("Range / Address", style="white")
        for ip_type, ip_val in ips[:35]:
            t.add_row(ip_type, ip_val)
        if len(ips) > 35:
            t.add_row("...", f"(+{len(ips)-35} more)")
        console.print(t)

    for w in warnings:
        warn(w)

    result = {"record": spf, "lookup_count": lookup_count,
              "all_directive": all_d, "ip_count": len(ips), "warnings": warnings}
    session.store("spf", domain, result)
    return result

# ── DMARC Inspector ───────────────────────────────────────────────────────────
def dmarc_inspector(domain=None):
    if domain is None: domain = get_domain()
    section(f"DMARC Inspector — {domain}")

    vals, _, _ = resolve_safe(f"_dmarc.{domain}", "TXT")
    dmarc = next((v.strip('"') for v in vals if "v=DMARC1" in v.strip('"')), None)

    if not dmarc:
        err("No DMARC record found.")
        info(f'Add TXT at _dmarc.{domain}')
        info(f'Recommended: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}')
        session.store("dmarc", domain, {"error": "no_dmarc"}); return None

    console.print(f"\n  [bold]DMARC Record:[/bold] [dim]{dmarc}[/dim]\n")

    tags = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Tag",        style="bold yellow", width=18)
    table.add_column("Value",      style="white",       width=30)
    table.add_column("Assessment")

    p    = tags.get("p", "none")
    sp   = tags.get("sp", p)
    pct  = tags.get("pct", "100")
    rua  = tags.get("rua", "")
    ruf  = tags.get("ruf", "")
    adkim= tags.get("adkim","r")
    aspf = tags.get("aspf","r")
    fo   = tags.get("fo","0")

    def policy_color(pol):
        return {"none":"[yellow]","quarantine":"[green]","reject":"[bold green]"}.get(pol,"[white]")

    table.add_row("p (domain policy)",    p,   f"{policy_color(p)}{p}[/] — " +
                  {"none":"Monitoring only. No enforcement.","quarantine":"Suspicious mail to spam.","reject":"Maximum protection — reject failing mail."}.get(p,p))
    table.add_row("sp (subdomain policy)",sp,  f"{policy_color(sp)}{sp}[/]")
    table.add_row("pct",                  pct, "[green]Full enforcement[/green]" if pct=="100" else f"[yellow]Partial: {pct}% of messages only[/yellow]")
    table.add_row("rua (aggregate)",      rua or "[dim]Not set[/dim]",
                  "[green]Aggregate reports enabled[/green]" if rua else "[yellow]Not set — you won't receive reports[/yellow]")
    table.add_row("ruf (forensic)",       ruf or "[dim]Not set[/dim]",
                  "[green]Forensic reports enabled[/green]" if ruf else "[dim]Optional[/dim]")
    table.add_row("adkim (DKIM align)",   adkim, "[dim]Relaxed[/dim]" if adkim=="r" else "[green]Strict[/green]")
    table.add_row("aspf (SPF align)",     aspf,  "[dim]Relaxed[/dim]" if aspf=="r"  else "[green]Strict[/green]")
    table.add_row("fo (failure opts)",    fo,    {"0":"Report if both fail","1":"[green]Report if either fails (recommended)[/green]","d":"DKIM failure only","s":"SPF failure only"}.get(fo,fo))

    console.print(table)
    console.print()

    if   p == "reject":     ok("Strong DMARC — reject mode active. Excellent protection.")
    elif p == "quarantine": ok("Good DMARC — quarantine mode. Consider upgrading to reject.")
    else:                   warn("Policy is 'none' — no enforcement. Upgrade to quarantine/reject.")

    result = {"record": dmarc, "policy": p, "subdomain_policy": sp,
              "pct": pct, "rua": rua, "ruf": ruf}
    session.store("dmarc", domain, result)
    return result

# ── DKIM Selector Prober ──────────────────────────────────────────────────────
def dkim_prober(domain=None):
    if domain is None: domain = get_domain()
    section(f"DKIM Selector Prober — {domain}")
    info(f"Probing {len(DKIM_SELECTORS)} selectors in parallel…")

    def check(sel):
        vals, _, status = resolve_safe(f"{sel}._domainkey.{domain}", "TXT", timeout=4)
        if status == "ok" and vals:
            for v in vals:
                c = v.strip('"')
                if "v=DKIM1" in c or "p=" in c:
                    return sel, c, True
        return sel, None, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as ex:
        raw = list(ex.map(check, DKIM_SELECTORS))

    found = [(s, v) for s, v, hit in raw if hit]

    if not found:
        warn("No DKIM records found for any known selector.")
        info("Check your mail provider's docs for the exact selector name.")
        session.store("dkim", domain, {"found": []}); return []

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Selector",        style="bold yellow", width=16)
    table.add_column("Key Type",        style="white",       width=10)
    table.add_column("Key Strength",    style="white",       width=20)
    table.add_column("Status",          width=22)

    found_data = []
    for sel, val in found:
        key_type = "Ed25519" if "k=ed25519" in val else "RSA"
        key_length = "256-bit" if key_type == "Ed25519" else "unknown"
        if key_type == "RSA":
            pm = re.search(r'p=([A-Za-z0-9+/=]+)', val)
            if pm:
                b = len(pm.group(1)) * 3 / 4
                if   b > 400: key_length = "4096-bit"
                elif b > 200: key_length = "2048-bit ✓"
                elif b > 100: key_length = "1024-bit [yellow](weak — upgrade)[/yellow]"
                else:         key_length = "[bold red]< 1024-bit INSECURE[/bold red]"

        weak = "weak" in key_length or "INSECURE" in key_length
        status_str = "[red]⚠ Weak key[/red]" if weak else "[green]✓ Active[/green]"
        table.add_row(sel, key_type, key_length, status_str)
        found_data.append({"selector": sel, "key_type": key_type, "key_length": key_length})

    console.print(table)
    ok(f"Found {len(found)} active DKIM selector(s): {', '.join(s for s,_ in found)}")
    session.store("dkim", domain, {"found": found_data})
    return found_data

# ── MX Validator ──────────────────────────────────────────────────────────────
def mx_validator(domain=None):
    if domain is None: domain = get_domain()
    section(f"MX Validator — {domain}")

    mx_vals, _, mx_status = resolve_safe(domain, "MX")
    if mx_status != "ok" or not mx_vals:
        err(f"No MX records found ({mx_status})")
        session.store("mx", domain, {"error": "no_mx"}); return

    mx_records = sorted(
        [(int(v.split()[0]), v.split()[1].rstrip(".")) for v in mx_vals if len(v.split()) >= 2]
    )

    def check_mx(item):
        priority, host = item
        try:   ip = socket.gethostbyname(host)
        except: return priority, host, None, False, False, None

        def port_open(port):
            try:
                s = socket.socket()
                s.settimeout(4)
                r = s.connect_ex((ip, port))
                s.close()
                return r == 0
            except: return False

        p25  = port_open(25)
        p587 = port_open(587)
        try:   rdns = socket.gethostbyaddr(ip)[0]
        except: rdns = None
        return priority, host, ip, p25, p587, rdns

    with Spinner("Testing MX reachability"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            results_raw = list(ex.map(check_mx, mx_records))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Priority",    style="bold yellow", width=10)
    table.add_column("Mail Server", style="white")
    table.add_column("IP",          style="cyan",        width=16)
    table.add_column("Port 25",     width=10)
    table.add_column("Port 587",    width=10)
    table.add_column("Reverse DNS", style="dim")

    results_data = []
    for priority, host, ip, p25, p587, rdns in results_raw:
        table.add_row(
            str(priority), host,
            ip or "[red]Unresolvable[/red]",
            "[green]● Open[/green]"  if p25  else "[red]● Closed[/red]",
            "[green]● Open[/green]"  if p587 else "[dim]● Closed[/dim]",
            rdns or "[dim]No PTR[/dim]",
        )
        results_data.append({"priority": priority, "host": host, "ip": ip,
                              "port25": p25, "port587": p587, "rdns": rdns})

    console.print(table)

    priorities = [p for p, _ in mx_records]
    if len(set(priorities)) < len(priorities):
        warn("Duplicate MX priorities — each should be unique.")
    else:
        ok("MX priorities are unique.")

    unreachable = [d["host"] for d in results_data if not d["port25"]]
    if unreachable:
        warn(f"Port 25 closed / filtered on: {', '.join(unreachable)}")
    else:
        ok("All MX servers reachable on port 25.")

    no_rdns = [d["host"] for d in results_data if not d["rdns"]]
    if no_rdns:
        warn(f"No reverse DNS (PTR) on: {', '.join(no_rdns)} — may cause spam filtering.")

    session.store("mx", domain, results_data)
    return results_data

# ── RBL / Blacklist Checker ───────────────────────────────────────────────────
def rbl_checker(domain=None):
    if domain is None:
        domain = get_domain("Enter domain or IP to check")
    section(f"Blacklist / RBL Checker — {domain}")

    try:   ip = socket.gethostbyname(domain)
    except: ip = domain

    parts = ip.split(".")
    if len(parts) != 4:
        err(f"Cannot reverse IP: {ip}"); return

    rev = ".".join(reversed(parts))
    info(f"IP: {ip}  |  Checking {len(RBL_ZONES)} blacklists in parallel…")

    def check_rbl(zone):
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["8.8.8.8", "8.8.4.4"]
        r.lifetime = 4
        try:
            r.resolve(f"{rev}.{zone}", "A")
            return zone, "listed"
        except dns.resolver.NXDOMAIN: return zone, "clean"
        except dns.exception.Timeout:  return zone, "timeout"
        except Exception:              return zone, "error"

    with concurrent.futures.ThreadPoolExecutor(max_workers=18) as ex:
        raw = list(ex.map(check_rbl, RBL_ZONES))

    listed  = [(z,s) for z,s in raw if s == "listed"]
    clean   = [(z,s) for z,s in raw if s == "clean"]
    errors  = [(z,s) for z,s in raw if s not in ("listed","clean")]

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Blacklist", style="white")
    table.add_column("Status",    width=18)

    for z,_ in listed: table.add_row(z, "[bold red]⚠  LISTED[/bold red]")
    for z,_ in clean:  table.add_row(z, "[green]✓  Clean[/green]")
    for z,s in errors: table.add_row(z, f"[dim]{s}[/dim]")

    console.print(table)
    console.print()

    if listed:
        err(f"Listed on {len(listed)} blacklist(s): {', '.join(z for z,_ in listed)}")
        info("Visit each blacklist's removal/delist page to submit a delist request.")
        info("Common removal pages: https://www.spamhaus.org/lookup/ | https://www.barracudacentral.org/rbl/removal-request")
    else:
        ok(f"Clean on all {len(clean)} checked blacklists.")

    result = {"ip": ip, "listed": [z for z,_ in listed], "clean": len(clean)}
    session.store("rbl", domain, result)
    return result
