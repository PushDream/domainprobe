"""
Reporter
────────
• Ticket-Ready Summary Generator — full scan → formatted plaintext report
• Diff Mode — before/after DNS snapshot comparison
• Live Propagation Watcher — polls a record at interval, alerts on change
"""

import re, socket, ssl, datetime, time
import requests
import whois
from rich.panel  import Panel
from rich.table  import Table
from rich        import box
from rich.prompt import Prompt, Confirm
from .display    import console, section, ok, warn, err, info, get_domain, days_label, Spinner
from .dns_core   import resolve_safe
from .meta       import app_label
from . import session

# ── Ticket Summary Generator ──────────────────────────────────────────────────
def ticket_summary(domain=None):
    if domain is None: domain = get_domain()
    section(f"Ticket-Ready Summary Generator — {domain}")
    info("Running full scan (20–30 s)…")

    lines, issues, recs = [], [], []
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def add(line=""): lines.append(line)

    add("=" * 68)
    add("  DOMAIN SUPPORT / INCIDENT REPORT")
    add(f"  Tool: {app_label()}   Generated: {now_str}")
    add("=" * 68)
    add()
    add(f"  DOMAIN:    {domain.upper()}")

    # WHOIS
    try:
        w = whois.whois(domain)
        add(f"  REGISTRAR: {w.registrar or 'Unknown'}")
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(exp, datetime.datetime):
            exp_n = exp.replace(tzinfo=None)
            diff = (exp_n - datetime.datetime.utcnow()).days
            add(f"  EXPIRES:   {exp_n.strftime('%Y-%m-%d')} ({diff} days)")
            if   diff < 0:  issues.append("CRITICAL: Domain has EXPIRED")
            elif diff < 30: issues.append(f"WARNING: Expires in {diff} days")
        statuses = w.status or []
        if isinstance(statuses, str): statuses = [statuses]
        sc = [s.split()[0] for s in statuses]
        add(f"  STATUS:    {', '.join(sc)}")
        ns = w.name_servers or []
        if isinstance(ns, list): ns = sorted({n.lower() for n in ns})
        add(f"  NS:        {', '.join(ns)}")
    except Exception as e:
        add(f"  WHOIS: Error — {e}")
    add()

    # DNS
    add("─" * 68)
    add("  DNS RECORDS")
    add("─" * 68)
    for rtype in ["A","AAAA","MX","NS","TXT","SOA","CAA"]:
        vals, ttl, status = resolve_safe(domain, rtype)
        if status == "ok" and vals:
            for v in vals: add(f"  {rtype:<6} {v}  [TTL:{ttl}]")
        elif status == "NXDOMAIN":
            add(f"  {rtype:<6} NXDOMAIN")
            issues.append(f"NXDOMAIN returned for {rtype} lookup")
        else:
            add(f"  {rtype:<6} {status}")
    add()

    # Email
    add("─" * 68)
    add("  EMAIL DELIVERABILITY")
    add("─" * 68)
    txt_vals, _, _ = resolve_safe(domain, "TXT")
    spf = next((v.strip('"') for v in txt_vals if "v=spf1" in v.strip('"')), None)
    if spf:
        add(f"  SPF:   {spf}")
        if   "+all" in spf:       issues.append("CRITICAL: SPF +all — anyone can spoof domain"); recs.append("Change SPF from +all to -all immediately")
        elif "-all" in spf:       add("  SPF:   ✓ Strict (-all)")
        else:                     recs.append("Consider tightening SPF to -all")
    else:
        add("  SPF:   ✗ Not found"); issues.append("No SPF record")
        recs.append(f"Add TXT: v=spf1 include:_spf.yourprovider.com -all")

    dv, _, _ = resolve_safe(f"_dmarc.{domain}", "TXT")
    dmarc = next((v.strip('"') for v in dv if "v=DMARC1" in v.strip('"')), None)
    if dmarc:
        add(f"  DMARC: {dmarc}")
        pm = re.search(r'p=(\w+)', dmarc)
        pval = pm.group(1) if pm else "none"
        if pval == "none": issues.append("DMARC policy is none — no enforcement"); recs.append("Upgrade DMARC from p=none to p=quarantine or p=reject")
    else:
        add("  DMARC: ✗ Not found"); issues.append("No DMARC record")
        recs.append(f"Add TXT at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}")
    add()

    # Security
    add("─" * 68)
    add("  SECURITY")
    add("─" * 68)
    ds, _, sds = resolve_safe(domain, "DS", "8.8.8.8")
    add(f"  DNSSEC: {'✓ DS record present' if (sds=='ok' and ds) else '✗ Not configured'}")
    if not (sds=="ok" and ds):
        issues.append("DNSSEC not enabled"); recs.append("Enable DNSSEC at registrar")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                na = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                issuer = dict(x[0] for x in cert["issuer"]).get("commonName","Unknown")
                diff_ssl = (na - datetime.datetime.utcnow()).days
                add(f"  SSL:   ✓ Valid until {na.strftime('%Y-%m-%d')} ({diff_ssl}d) — {issuer}")
                if diff_ssl < 30: issues.append(f"SSL expires in {diff_ssl} days"); recs.append("Renew SSL certificate immediately")
    except Exception as e:
        add(f"  SSL:   ✗ Error — {e}"); issues.append(f"SSL error: {e}")

    caa, _, scaa = resolve_safe(domain, "CAA")
    add(f"  CAA:   {'✓ ' + str(len(caa)) + ' record(s)' if (scaa=='ok' and caa) else '✗ Not configured'}")
    if not (scaa == "ok" and caa):
        recs.append("Add CAA record to restrict certificate issuance")
    add()

    # NS consistency (quick)
    add("─" * 68)
    add("  NAMESERVER CONSISTENCY")
    add("─" * 68)
    ns_vals, _, _ = resolve_safe(domain, "NS")
    serials = {}
    for ns_raw in ns_vals[:3]:
        ns_host = ns_raw.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_host)
            soa_v, _, _ = resolve_safe(domain, "SOA", ns_ip, timeout=4)
            if soa_v:
                serial = soa_v[0].split()[2] if len(soa_v[0].split()) > 2 else "?"
                serials[ns_host] = serial
                add(f"  {ns_host} → serial {serial}")
        except: add(f"  {ns_host} → (unresolvable)")

    unique_serials = set(serials.values())
    if len(unique_serials) > 1:
        add(f"  ⚠ SOA SERIAL MISMATCH: {', '.join(unique_serials)}")
        issues.append("SOA serial mismatch between nameservers")
    elif unique_serials:
        add(f"  ✓ All serials match: {list(unique_serials)[0]}")
    add()

    # Issues & recommendations
    add("=" * 68)
    add("  ISSUES DETECTED")
    add("=" * 68)
    if issues:
        for i, issue in enumerate(issues, 1): add(f"  {i}. {issue}")
    else:
        add("  None detected.")
    add()
    add("=" * 68)
    add("  RECOMMENDED ACTIONS")
    add("=" * 68)
    if recs:
        for i, r in enumerate(recs, 1): add(f"  {i}. {r}")
    else:
        add("  No immediate actions required.")
    add()
    add("=" * 68)
    add(f"  END OF REPORT — {domain.upper()}")
    add("=" * 68)

    report = "\n".join(lines)
    console.print(Panel(report, border_style="cyan", padding=(0,1)))

    if Confirm.ask("\n  [cyan]Save report to file?[/cyan]", default=True):
        ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fn  = Prompt.ask("  [cyan]Filename[/cyan]", default=f"report_{domain}_{ts}.txt")
        with open(fn, "w", encoding="utf-8") as f: f.write(report)
        ok(f"Saved → [bold]{fn}[/bold]")

    session.store("ticket_summary", domain, {"issues": issues, "recs": recs})
    return report

# ── Diff Mode ─────────────────────────────────────────────────────────────────
def diff_mode():
    section("Diff Mode — Before / After DNS Comparison")
    domain = get_domain()
    rtypes = ["A","AAAA","MX","NS","TXT","SOA","CAA","CNAME"]

    def take_snap(label):
        info(f"Taking '{label}' snapshot of {domain}…")
        snap = {}
        for rt in rtypes:
            vals, ttl, status = resolve_safe(domain, rt)
            snap[rt] = {"values": sorted(vals), "ttl": ttl, "status": status}
        session.snapshot(label, domain, snap)
        return snap

    snap_a = take_snap("BEFORE")
    ok("BEFORE snapshot captured.")
    Prompt.ask("  [dim]Make your DNS changes, then press Enter to take the AFTER snapshot[/dim]")
    snap_b = take_snap("AFTER")
    ok("AFTER snapshot captured.")

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Record", style="bold yellow", width=8)
    table.add_column("Before", style="red")
    table.add_column("After",  style="green")
    table.add_column("Change", width=18)

    changed = False
    for rt in rtypes:
        a = snap_a.get(rt, {}); b = snap_b.get(rt, {})
        va = a.get("values",[]); vb = b.get("values",[])
        ta = a.get("ttl","–");    tb = b.get("ttl","–")
        if va != vb:
            changed = True
            table.add_row(rt,
                          "\n".join(va) or "[dim]None[/dim]",
                          "\n".join(vb) or "[dim]None[/dim]",
                          "[yellow]Values changed[/yellow]")
        elif ta != tb and va:
            changed = True
            table.add_row(rt, f"TTL: {ta}", f"TTL: {tb}", "[cyan]TTL changed[/cyan]")

    console.print()
    if changed:
        console.print(table)
        ok("Diff complete — changes highlighted above.")
    else:
        ok("No changes detected between snapshots.")
        info("If expected, DNS may still be propagating — use Propagation Check (option 3).")

    session.store("diff", domain, {"before": snap_a, "after": snap_b, "changed": changed})

# ── Live Propagation Watcher ──────────────────────────────────────────────────
def live_watcher():
    section("Live Propagation Watcher")
    domain   = get_domain()
    rtype    = Prompt.ask("  [cyan]Record type[/cyan]", default="A").upper()
    resolver = Prompt.ask("  [cyan]Resolver IP[/cyan]", default="1.1.1.1")
    interval = int(Prompt.ask("  [cyan]Poll interval (seconds)[/cyan]", default="30"))

    info(f"Watching {domain} [{rtype}] via {resolver} every {interval}s — [bold]Ctrl+C[/bold] to stop")
    console.print()

    last_vals  = None
    iteration  = 0
    change_log = []

    try:
        while True:
            iteration += 1
            now = datetime.datetime.utcnow().strftime("%H:%M:%S")
            vals, ttl, status = resolve_safe(domain, rtype, resolver, timeout=6)
            vs = sorted(vals)

            if last_vals is None:
                last_vals = vs
                console.print(f"  [dim]{now}[/dim] #{iteration:04}  Initial: "
                               f"[cyan]{', '.join(vs) or status}[/cyan]  TTL:{ttl}")
            elif vs != last_vals:
                console.print(f"  [dim]{now}[/dim] #{iteration:04}  "
                               f"[bold green]CHANGED![/bold green]  "
                               f"[red]{', '.join(last_vals)}[/red] → [green]{', '.join(vs)}[/green]  TTL:{ttl}")
                change_log.append({"time": now, "from": last_vals, "to": vs})
                last_vals = vs
            else:
                console.print(f"  [dim]{now}[/dim] #{iteration:04}  "
                               f"{', '.join(vs) or status}  TTL:{ttl}  [dim]unchanged[/dim]")

            time.sleep(interval)

    except KeyboardInterrupt:
        console.print()
        ok(f"Watcher stopped after {iteration} poll(s).")
        if change_log:
            ok(f"{len(change_log)} change(s) observed during watch session.")
