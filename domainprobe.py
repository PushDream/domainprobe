#!/usr/bin/env python3
"""
DomainProbe v2.0
Advanced DNS & Domain Intelligence Platform
Tier 2 DNS / Domain Technical Support
"""

import argparse
import sys, os

# ── Dependency pre-check ──────────────────────────────────────────────────────
DEPS = [("dnspython","dns"), ("python-whois","whois"),
        ("requests","requests"), ("rich","rich")]
MISSING = []
for pkg, imp in DEPS:
    try: __import__(imp)
    except ImportError: MISSING.append(pkg)
if MISSING:
    print(f"\n[!] Missing packages. Install with:\n    pip install {' '.join(MISSING)}\n")
    sys.exit(1)

# ── Module imports ─────────────────────────────────────────────────────────────
from rich.console  import Console
from rich.panel    import Panel
from rich.table    import Table
from rich.prompt   import Prompt, Confirm
from rich          import box

from modules.display      import console, banner, section, ok, warn, err, info, press_enter
from modules              import session
from modules.audit_engine import actionable_audit, render_audit_text, run_actionable_audit, save_audit_report, should_fail
from modules.diagnose     import diagnose_domain, diagnose_website, render_domain_diagnosis_text, render_website_diagnosis_text, run_domain_diagnosis, run_website_diagnosis, save_diagnosis_report
from modules.dns_core     import dns_lookup, propagation_check, ns_consistency_check, cname_ttl_analyzer
from modules.whois_rdap   import whois_lookup, rdap_lookup, epp_decoder
from modules.email_suite  import spf_analyzer, dmarc_inspector, dkim_prober, mx_validator, rbl_checker
from modules.security     import ssl_inspector, dnssec_validator, doh_probe, caa_analyzer
from modules.diagnostics  import dns_health_score, redirect_chain, transfer_eligibility, expiry_calendar
from modules.connectivity import connectivity_check
from modules.reporter     import ticket_summary, diff_mode, live_watcher

# ── Bulk lookup ───────────────────────────────────────────────────────────────
def bulk_lookup():
    section("Bulk Domain Lookup")
    raw = Prompt.ask("  [cyan]Enter domains[/cyan] [dim](comma or space separated)[/dim]")
    import re
    domains = [d.strip() for d in re.split(r'[,\s]+', raw) if d.strip()]
    if not domains:
        warn("No domains entered."); return

    rtype = Prompt.ask("  [cyan]Record type[/cyan]", default="A").upper()
    info(f"Querying {len(domains)} domain(s) for [{rtype}] records…")

    from modules.dns_core import resolve_safe
    from rich.table import Table
    from rich import box

    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold white")
    table.add_column("Domain",  style="white")
    table.add_column("Answer",  style="cyan")
    table.add_column("TTL",     style="dim", width=7)
    table.add_column("Status",  width=14)

    import concurrent.futures
    def query(d):
        vals, ttl, status = resolve_safe(d, rtype)
        return d, vals, ttl, status

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(query, domains))

    for d, vals, ttl, status in results:
        if status == "ok" and vals:
            table.add_row(d, "\n".join(vals), str(ttl), "[green]✓ OK[/green]")
        elif status == "NXDOMAIN":
            table.add_row(d, "[red]NXDOMAIN[/red]", "–", "[red]NXDOMAIN[/red]")
        else:
            table.add_row(d, f"[dim]{status}[/dim]", "–", "[yellow]–[/yellow]")

    console.print(table)

# ── Export session ────────────────────────────────────────────────────────────
def export_menu():
    section("Export Session Results")
    if session.count() == 0:
        warn("No results in this session yet."); return

    info(f"{session.count()} result(s) stored this session.")
    fmt = Prompt.ask("  [cyan]Format[/cyan]", choices=["json","csv"], default="json")
    fn  = Prompt.ask("  [cyan]Filename[/cyan]", default=f"domainprobe_session.{fmt}")

    if fmt == "json":  session.export_json(fn)
    else:              session.export_csv(fn)
    ok(f"Exported → [bold]{fn}[/bold]")

# ── Menu definition ───────────────────────────────────────────────────────────
ADVANCED_MENU_ITEMS = [
    (None, "DNS CORE", None),
    ("1",  "DNS Record Lookup",                    dns_lookup),
    ("2",  "NS Consistency & SOA Validation",      ns_consistency_check),
    ("3",  "Propagation Check",                    propagation_check),
    ("4",  "CNAME Conflict & TTL Analyzer",        cname_ttl_analyzer),

    (None, "DOMAIN LIFECYCLE", None),
    ("5",  "WHOIS Lookup",                         whois_lookup),
    ("6",  "RDAP Lookup",                          rdap_lookup),
    ("7",  "EPP / IANA Status Decoder",            epp_decoder),
    ("8",  "Expiry Calendar",                      expiry_calendar),

    (None, "EMAIL & SECURITY", None),
    ("9",  "SPF Analyzer",                         spf_analyzer),
    ("10", "DMARC Inspector",                      dmarc_inspector),
    ("11", "DKIM Selector Prober",                 dkim_prober),
    ("12", "MX Validator + Port Check",            mx_validator),
    ("13", "Blacklist / RBL Checker",              rbl_checker),
    ("14", "SSL / TLS Certificate Inspector",      ssl_inspector),
    ("15", "DNSSEC Validator",                     dnssec_validator),
    ("16", "DNS-over-HTTPS Probe",                 doh_probe),
    ("17", "CAA Record Analyzer",                  caa_analyzer),

    (None, "WEB / NETWORK", None),
    ("18", "Redirect Chain Follower",              redirect_chain),
    ("19", "Network Connectivity",                 connectivity_check),
    ("20", "Live Propagation Watcher",             live_watcher),
    ("0",  "Back",                                 None),
]

REPORT_MENU_ITEMS = [
    ("1", "Actionable Audit Report",               actionable_audit),
    ("2", "Ticket-Ready Summary Generator",        ticket_summary),
    ("3", "DNS Health Score",                      dns_health_score),
    ("4", "Diff Mode",                             diff_mode),
    ("5", "Bulk Domain Lookup",                    bulk_lookup),
    ("6", "Export Session Results",                export_menu),
    ("0", "Back",                                  None),
]

MAIN_MENU_ITEMS = [
    ("1", "Diagnose Domain",                       diagnose_domain),
    ("2", "Diagnose Website",                      diagnose_website),
    ("3", "Transfer Diagnosis",                    transfer_eligibility),
    ("4", "Advanced Tools",                        "advanced"),
    ("5", "Reports / Export",                      "reports"),
    ("0", "Exit",                                  None),
]

def _run_menu(title, items, default_choice):
    dispatch = {item[0]: item[2] for item in items if item[0] not in (None, "0")}

    while True:
        section(title)
        for key, label, fn in items:
            if key is None:
                console.print(f"\n  [bold dim]── {label}[/bold dim]")
            elif key == "0":
                console.print(f"\n   [dim]0[/dim]   {label}")
            else:
                console.print(f"   [cyan]{key.rjust(2)}[/cyan]  {label}")
        console.print()

        choice = Prompt.ask("  [bold cyan]Select[/bold cyan]", default=default_choice).strip()
        if choice == "0":
            return None

        fn = dispatch.get(choice)
        if fn is None:
            warn("Invalid option — enter a number from the menu.")
            continue

        try:
            fn()
        except KeyboardInterrupt:
            console.print()
            warn("Interrupted — returning to menu.")
        except Exception as e:
            err(f"Unexpected error: {e}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")

        press_enter()

def advanced_menu():
    _run_menu("Advanced Tools", ADVANCED_MENU_ITEMS, "1")

def reports_menu():
    _run_menu("Reports / Export", REPORT_MENU_ITEMS, "1")

MAIN_DISPATCH = {
    "1": diagnose_domain,
    "2": diagnose_website,
    "3": transfer_eligibility,
    "4": advanced_menu,
    "5": reports_menu,
}

def print_main_menu():
    section("Main Menu")
    console.print("  [dim]Focused workflows first. Granular checks live under Advanced Tools.[/dim]\n")
    for key, label, _ in MAIN_MENU_ITEMS:
        if key == "0":
            console.print(f"\n   [dim]0[/dim]   {label}")
        else:
            console.print(f"   [cyan]{key.rjust(2)}[/cyan]  {label}")
    console.print()

# ── CLI mode ──────────────────────────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        description="DomainProbe v2.0 — DNS, mail, and domain diagnostics"
    )
    subparsers = parser.add_subparsers(dest="command")

    domain_parser = subparsers.add_parser(
        "diagnose-domain",
        help="Run the flagship domain resolution diagnosis flow",
    )
    domain_parser.add_argument("domain", help="Domain name to diagnose")
    domain_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stdout or --output",
    )
    domain_parser.add_argument(
        "--output",
        help="Write the diagnosis report to a file instead of stdout",
    )
    domain_parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low"],
        default="never",
        help="Exit with code 2 if a finding at or above this severity is present",
    )

    website_parser = subparsers.add_parser(
        "diagnose-website",
        help="Run the flagship website diagnosis flow",
    )
    website_parser.add_argument("domain", help="Domain name to diagnose")
    website_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stdout or --output",
    )
    website_parser.add_argument(
        "--output",
        help="Write the diagnosis report to a file instead of stdout",
    )
    website_parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low"],
        default="never",
        help="Exit with code 2 if a finding at or above this severity is present",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run a structured actionable audit for a domain",
    )
    audit_parser.add_argument("domain", help="Domain name to audit")
    audit_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stdout or --output",
    )
    audit_parser.add_argument(
        "--output",
        help="Write the audit report to a file instead of stdout",
    )
    audit_parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low"],
        default="never",
        help="Exit with code 2 if a finding at or above this severity is present",
    )

    return parser


def run_cli(argv):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return None

    if args.command == "diagnose-domain":
        report = run_domain_diagnosis(args.domain)
        if args.output:
            save_diagnosis_report(report, args.output, args.format, render_domain_diagnosis_text)
            print(f"Saved {args.format} diagnosis report to {args.output}")
        elif args.format == "json":
            import json
            print(json.dumps(report, indent=2, default=str))
        else:
            print(render_domain_diagnosis_text(report))

        return 2 if should_fail(report["findings"], args.fail_on) else 0

    if args.command == "diagnose-website":
        report = run_website_diagnosis(args.domain)
        if args.output:
            save_diagnosis_report(report, args.output, args.format, render_website_diagnosis_text)
            print(f"Saved {args.format} diagnosis report to {args.output}")
        elif args.format == "json":
            import json
            print(json.dumps(report, indent=2, default=str))
        else:
            print(render_website_diagnosis_text(report))

        return 2 if should_fail(report["findings"], args.fail_on) else 0

    if args.command == "audit":
        audit = run_actionable_audit(args.domain)
        if args.output:
            save_audit_report(audit, args.output, args.format)
            print(f"Saved {args.format} audit report to {args.output}")
        elif args.format == "json":
            import json
            print(json.dumps(audit, indent=2, default=str))
        else:
            print(render_audit_text(audit))

        return 2 if should_fail(audit["findings"], args.fail_on) else 0

    return 0


# ── Main loop ─────────────────────────────────────────────────────────────────
def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        cli_code = run_cli(argv)
        if cli_code is not None:
            return cli_code

    banner()

    while True:
        print_main_menu()
        choice = Prompt.ask("  [bold cyan]Select[/bold cyan]", default="1").strip()

        if choice == "0":
            if session.count() > 0:
                if Confirm.ask(f"  [cyan]Export {session.count()} session result(s) before exiting?[/cyan]", default=False):
                    export_menu()
            console.print("\n  [dim]DomainProbe v2.0 — goodbye.[/dim]\n")
            return 0

        fn = MAIN_DISPATCH.get(choice)
        if fn is None:
            warn("Invalid option — enter a number from the menu.")
            continue

        try:
            fn()
            if choice in ("4", "5"):
                continue
        except KeyboardInterrupt:
            console.print()
            warn("Interrupted — returning to menu.")
        except Exception as e:
            err(f"Unexpected error: {e}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")

        press_enter()

if __name__ == "__main__":
    sys.exit(main())
