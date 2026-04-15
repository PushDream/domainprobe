"""
Diagnostics
───────────
• DNS Health Score — 17-point weighted audit, A–F grade
• Redirect Chain Follower — follows HTTP redirects, detects loops & downgrades
• Transfer Eligibility Checker — full ICANN condition check
• Domain Expiry Calendar — portfolio expiry overview
"""

import re, socket, ssl, datetime, concurrent.futures
import requests
import whois
from pathlib import Path
from rich.table  import Table
from rich.panel  import Panel
from rich.prompt import Prompt, Confirm
from rich import box
from .display import console, section, ok, warn, err, info, get_domain, days_label, score_to_grade, grade_color, Spinner
from .meta    import APP_USER_AGENT
from .dns_core  import resolve_safe
from . import session

# ── Health Score check definitions ────────────────────────────────────────────
CHECKS = [
    # (id, label,                              max_pts)
    ("ns",           "NS Records (≥ 2)",                8),
    ("soa",          "SOA Record",                       5),
    ("a_aaaa",       "A / AAAA Records",                 8),
    ("mx",           "MX Records",                       6),
    ("mx_reach",     "MX Reachability (port 25)",        5),
    ("spf",          "SPF Record",                       8),
    ("spf_strict",   "SPF Strictness (-all)",            5),
    ("dmarc",        "DMARC Record",                     8),
    ("dmarc_enforce","DMARC Enforcement (≥ quarantine)",  5),
    ("dkim",         "DKIM (any selector found)",        7),
    ("caa",          "CAA Records",                      5),
    ("dnssec",       "DNSSEC (DS record)",               8),
    ("www",          "www Subdomain Resolves",            4),
    ("ttl",          "TTL Sanity (A ≥ 300 s)",           4),
    ("no_cname",     "No CNAME Conflicts",               4),
    ("ssl",          "SSL Certificate Valid",             6),
    ("rbl",          "Not on Spamhaus Blacklist",         4),
]

def _run_checks(domain):
    r = {}

    # NS
    ns_vals, _, s = resolve_safe(domain, "NS")
    r["ns"] = s=="ok" and len(ns_vals) >= 2

    # SOA
    soa, _, s2 = resolve_safe(domain, "SOA")
    r["soa"] = s2=="ok" and bool(soa)

    # A/AAAA
    a, _, sa = resolve_safe(domain, "A")
    aaaa, _, saaaa = resolve_safe(domain, "AAAA")
    r["a_aaaa"] = (sa=="ok" and bool(a)) or (saaaa=="ok" and bool(aaaa))

    # MX
    mx, _, smx = resolve_safe(domain, "MX")
    r["mx"] = smx=="ok" and bool(mx)

    # MX port 25
    r["mx_reach"] = False
    if r["mx"]:
        try:
            host = sorted(mx)[0].split()[-1].rstrip(".")
            ip = socket.gethostbyname(host)
            s = socket.socket(); s.settimeout(4)
            r["mx_reach"] = s.connect_ex((ip, 25)) == 0; s.close()
        except: pass

    # SPF
    txt, _, stxt = resolve_safe(domain, "TXT")
    spf = next((v.strip('"') for v in txt if v.strip('"').startswith("v=spf1")), None)
    r["spf"]        = bool(spf)
    r["spf_strict"] = bool(spf and "-all" in spf)

    # DMARC
    dv, _, _ = resolve_safe(f"_dmarc.{domain}", "TXT")
    dmarc = next((v.strip('"') for v in dv if "v=DMARC1" in v.strip('"')), None)
    r["dmarc"] = bool(dmarc)
    if dmarc:
        pm = re.search(r'p=(\w+)', dmarc)
        r["dmarc_enforce"] = pm and pm.group(1) in ("quarantine","reject")
    else:
        r["dmarc_enforce"] = False

    # DKIM — quick probe 6 selectors
    r["dkim"] = False
    for sel in ["default","google","selector1","selector2","mail","k1"]:
        dv2, _, sd = resolve_safe(f"{sel}._domainkey.{domain}", "TXT", timeout=3)
        if sd=="ok" and any("p=" in v for v in dv2):
            r["dkim"] = True; break

    # CAA
    caa, _, scaa = resolve_safe(domain, "CAA")
    r["caa"] = scaa=="ok" and bool(caa)

    # DNSSEC DS
    ds, _, sds = resolve_safe(domain, "DS", "8.8.8.8")
    r["dnssec"] = sds=="ok" and bool(ds)

    # www
    ww, _, sw = resolve_safe(f"www.{domain}", "A")
    r["www"] = sw=="ok" and bool(ww)

    # TTL sanity
    _, ttl, sttl = resolve_safe(domain, "A")
    r["ttl"] = sttl=="ok" and ttl >= 300

    # No CNAME conflict
    cname, _, sc = resolve_safe(domain, "CNAME")
    if sc=="ok" and cname and bool(a):
        r["no_cname"] = False
    else:
        r["no_cname"] = True

    # SSL
    r["ssl"] = False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                na = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                r["ssl"] = na > datetime.datetime.utcnow()
    except: pass

    # RBL — Spamhaus zen only (quick)
    r["rbl"] = True
    try:
        if a:
            rev = ".".join(reversed(a[0].split(".")))
            _, _, sr = resolve_safe(f"{rev}.zen.spamhaus.org", "A", timeout=4)
            r["rbl"] = sr == "NXDOMAIN"
    except: pass

    return r

def dns_health_score(domain=None):
    if domain is None: domain = get_domain()
    section(f"DNS Health Score — Full Audit — {domain}")
    info("Running 17 checks concurrently — ~15–20s…")

    with Spinner(f"Auditing {domain}"):
        checks = _run_checks(domain)

    max_pts   = sum(p for _,_,p in CHECKS)
    total_pts = sum(pts for cid,_,pts in CHECKS if checks.get(cid))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Check",   style="white",       min_width=36)
    table.add_column("Points",  style="dim",          width=10)
    table.add_column("Result",  width=18)

    failed = []
    for cid, label, pts in CHECKS:
        passed = checks.get(cid, False)
        if passed:
            table.add_row(label, f"{pts}/{pts}", "[green]✓ Pass[/green]")
        else:
            table.add_row(label, f"0/{pts}",     "[red]✗ Fail[/red]")
            failed.append((label, pts))

    console.print(table)

    pct   = int(total_pts / max_pts * 100)
    grade = score_to_grade(pct)
    color = grade_color(grade)

    console.print()
    console.print(Panel(
        f"[{color}]Grade: {grade}[/{color}]   [{color}]{pct}%[/{color}]  "
        f"({total_pts}/{max_pts} pts)   "
        f"[green]✓ {len(CHECKS)-len(failed)}[/green]  [red]✗ {len(failed)}[/red]",
        title=f"[bold white]DNS Health Score — {domain}[/bold white]",
        border_style=color, padding=(0, 2)
    ))

    if failed:
        console.print("\n  [bold]Issues to fix (highest impact first):[/bold]")
        for label, pts in sorted(failed, key=lambda x: -x[1]):
            console.print(f"    [red]✗[/red]  {label}  [dim]({pts} pts)[/dim]")

    result = {"score": total_pts, "max": max_pts, "grade": grade, "pct": pct,
              "passed": [l for c,l,p in CHECKS if checks.get(c)],
              "failed": [l for c,l,p in CHECKS if not checks.get(c)],
              "checks": checks}
    session.store("health_score", domain, result)
    return result

# ── Redirect Chain Follower ───────────────────────────────────────────────────
def redirect_chain(domain=None):
    if domain is None: domain = get_domain()
    section(f"Redirect Chain Follower — {domain}")

    start = f"http://{domain}"
    info(f"Starting from: {start}")

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("#",      style="dim",          width=4)
    table.add_column("URL",    style="white")
    table.add_column("Code",   style="bold yellow",  width=6)
    table.add_column("Note",   style="dim")

    try:
        resp = requests.get(start, allow_redirects=True, timeout=15,
                            headers={"User-Agent": APP_USER_AGENT})
        history = resp.history + [resp]

        prev_scheme = None
        chains = []
        for i, r in enumerate(history):
            url = r.url; code = r.status_code
            scheme = url.split("://")[0] if "://" in url else "http"
            note = ""
            if   prev_scheme == "http" and scheme == "https": note = "HTTP → HTTPS ✓"
            elif prev_scheme == "https" and scheme == "http": note = "[red]HTTPS → HTTP downgrade![/red]"
            elif code in (301, 308): note = "Permanent"
            elif code in (302, 307): note = "[yellow]Temporary[/yellow]"
            table.add_row(str(i+1), url[:90], str(code), note)
            chains.append({"url": url, "code": code})
            prev_scheme = scheme

        console.print(table)
        console.print()

        if len(history) > 5:
            warn(f"Long chain ({len(history)} hops) — impacts performance and SEO.")
        else:
            ok(f"Chain has {len(history)-1} redirect(s).")

        if resp.url.startswith("https://"):
            ok("Final destination is HTTPS.")
        else:
            warn("Final destination is HTTP — unencrypted.")

        session.store("redirects", domain, {"chain": chains})
        return chains

    except requests.exceptions.TooManyRedirects:
        err("Redirect loop — exceeded 30 hops.")
    except requests.exceptions.SSLError as e:
        err(f"SSL error during redirect follow: {e}")
    except Exception as e:
        err(f"Could not follow redirects: {e}")

# ── Transfer Eligibility Checker ──────────────────────────────────────────────
def transfer_eligibility(domain=None):
    if domain is None: domain = get_domain()
    section(f"Transfer Eligibility Checker — {domain}")

    try:
        w = whois.whois(domain)
        statuses = w.status or []
        if isinstance(statuses, str): statuses = [statuses]
        statuses = [s.split()[0].lower() for s in statuses]
        expiry = w.expiration_date
        if isinstance(expiry, list): expiry = expiry[0]
    except Exception as e:
        err(f"Could not retrieve domain status: {e}"); return

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Condition",    style="white", min_width=46)
    table.add_column("Finding",      style="white", width=30)
    table.add_column("Block?",       width=8)

    eligible = True

    def chk(label, pass_cond, ok_msg, fail_msg, blocking=True):
        nonlocal eligible
        if pass_cond:
            table.add_row(label, f"[green]{ok_msg}[/green]",  "[green]✓[/green]")
        else:
            table.add_row(label, f"[red]{fail_msg}[/red]",
                          "[red]✗ BLOCK[/red]" if blocking else "[yellow]⚠ WARN[/yellow]")
            if blocking: eligible = False

    chk("No serverTransferProhibited (registry lock)",
        "servertransferprohibited" not in statuses,
        "No registry lock", "REGISTRY LOCK active — only registry can remove")
    chk("No clientTransferProhibited (registrar lock)",
        "clienttransferprohibited" not in statuses,
        "No registrar lock", "Registrar lock — unlock via registrar panel")
    chk("Domain not expired",
        not (isinstance(expiry, datetime.datetime) and
             expiry.replace(tzinfo=None) < datetime.datetime.utcnow()),
        "Active", "EXPIRED — renew first")
    chk("Not in pendingDelete",
        "pendingdelete" not in statuses,
        "Not pending deletion", "Pending deletion — cannot transfer")
    chk("Not in redemptionPeriod",
        "redemptionperiod" not in statuses,
        "Not in redemption", "In redemption — restore first")
    chk("Not in serverHold / clientHold",
        "serverhold" not in statuses and "clienthold" not in statuses,
        "No holds active", "HOLD active — resolve hold before transfer")
    chk("Not in 60-day transferPeriod lock",
        "transferperiod" not in statuses,
        "Outside transfer lock", "Recently transferred — 60-day ICANN lock", blocking=False)
    chk("Not in addPeriod (new reg lock)",
        "addperiod" not in statuses,
        "Outside add grace period", "Newly registered — possible 60-day lock", blocking=False)

    console.print(table)
    console.print()

    if eligible:
        ok("[bold]Domain is eligible for transfer.[/bold]")
        info("Ensure you have the EPP/Auth code from the current registrar.")
        info("Initiate at the gaining registrar — 5-day ICANN window will apply.")
    else:
        err("[bold]Transfer NOT possible. Resolve all blocking conditions first.[/bold]")

    result = {"domain": domain, "eligible": eligible, "statuses": statuses}
    session.store("transfer_eligibility", domain, result)
    return result

# ── Domain Expiry Calendar ────────────────────────────────────────────────────
def expiry_calendar():
    section("Domain Expiry Calendar — Portfolio View")

    filepath = Prompt.ask("  [cyan]Path to domain list[/cyan] [dim](.txt — one domain per line)[/dim]").strip()
    path = Path(filepath)
    if not path.exists():
        err(f"File not found: {filepath}"); return

    domains = []
    with open(path) as f:
        for line in f:
            d = line.strip().split(",")[0].strip().lower()
            if d and not d.startswith("#"): domains.append(d)

    if not domains:
        warn("No domains found in file."); return

    info(f"Checking {len(domains)} domain(s) — this may take a moment…")

    def get_expiry(d):
        try:
            w = whois.whois(d)
            exp = w.expiration_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(exp, datetime.datetime):
                return d, exp.replace(tzinfo=None)
        except: pass
        return d, None

    with Spinner("Fetching WHOIS for portfolio"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            results = list(ex.map(get_expiry, domains))

    now = datetime.datetime.utcnow()
    results.sort(key=lambda x: (x[1] is None, x[1] or datetime.datetime.max))

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Domain",    style="white")
    table.add_column("Expires",   style="cyan",  width=14)
    table.add_column("Days",      style="dim",   width=8)
    table.add_column("Priority",  width=26)

    for domain, exp in results:
        if exp is None:
            table.add_row(domain, "Unknown", "–", "[dim]Could not retrieve[/dim]")
            continue
        diff = (exp - now).days
        if   diff < 0:   priority = "[bold red]⚠⚠  EXPIRED[/bold red]"
        elif diff < 30:  priority = "[bold red]⚠  CRITICAL — renew now[/bold red]"
        elif diff < 60:  priority = "[red]WARNING — renew soon[/red]"
        elif diff < 90:  priority = "[yellow]Renew in next 30 days[/yellow]"
        else:            priority = "[green]OK[/green]"
        table.add_row(domain, exp.strftime("%Y-%m-%d"), str(diff), priority)

    console.print(table)

    critical = sum(1 for _, e in results if e and (e - now).days < 30)
    if critical:
        warn(f"{critical} domain(s) expiring within 30 days — action required.")

    session.store("expiry_calendar", "portfolio",
                  [{"domain": d, "expiry": str(e)} for d, e in results])
