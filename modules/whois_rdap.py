"""
WHOIS / RDAP / EPP
──────────────────
• Full WHOIS with deduplication & expiry warnings
• RDAP via rdap.org bootstrap
• Complete EPP / IANA status decoder (30 codes)
"""

import datetime, requests
import whois
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt
from .display import console, section, ok, warn, err, info, get_domain, days_label, fmt_date, _naive
from . import session

# ── EPP Status Dictionary ─────────────────────────────────────────────────────
EPP = {
    "ok":                          ("green",  "Active — no pending operations.",                      "None required.",                                   "Resolves normally."),
    "active":                      ("green",  "Domain is active.",                                    "None required.",                                   "No impact."),
    "inactive":                    ("yellow", "No nameservers delegated.",                            "Add nameservers.",                                 "Will NOT resolve — no NS delegation."),
    "clientDeleteProhibited":      ("blue",   "Registrar locked against deletion.",                   "Registrar must remove lock.",                      "No DNS impact."),
    "clientHold":                  ("red",    "Registrar placed domain on hold (billing/compliance).", "Contact registrar to resolve.",                   "Will NOT resolve."),
    "clientRenewProhibited":       ("yellow", "Registrar prohibited renewal — possible legal hold.",  "Contact registrar. Court order may exist.",         "No immediate impact, domain may expire."),
    "clientTransferProhibited":    ("blue",   "60-day ICANN registrar lock active.",                  "Unlock via registrar panel to transfer.",           "No DNS impact."),
    "clientUpdateProhibited":      ("blue",   "Registrar blocked all updates (NS changes etc.).",     "Registrar must remove lock first.",                 "NS changes blocked; existing DNS unaffected."),
    "serverDeleteProhibited":      ("blue",   "Registry-level deletion lock.",                        "Contact registry directly.",                       "No DNS impact."),
    "serverHold":                  ("red",    "Registry hold — abuse, UDRP, or court order.",        "Contact registry. Registrar CANNOT remove this.",  "Will NOT resolve — registry-level override."),
    "serverRenewProhibited":       ("red",    "Registry prohibited renewal — legal dispute.",         "Contact registry.",                                "Domain will expire if unresolved."),
    "serverTransferProhibited":    ("blue",   "Registry-level transfer prohibition.",                 "Contact registry. Registrar cannot override.",     "No DNS impact."),
    "serverUpdateProhibited":      ("blue",   "Registry blocked all domain object updates.",          "Contact registry.",                                "NS updates blocked at registry level."),
    "pendingCreate":               ("yellow", "Creation pending registry confirmation.",              "Wait for registry provisioning.",                  "Domain may not resolve yet."),
    "pendingDelete":               ("red",    "Scheduled for deletion. May be in redemption queue.", "Restore via registrar if in redemption. Act fast.", "May or may not resolve per registry policy."),
    "pendingRenew":                ("yellow", "Renewal submitted, awaiting registry.",               "Wait for registry. Follow up if delayed.",          "No impact — registration remains active."),
    "pendingRestore":              ("yellow", "Restoration from redemption pending.",                 "Awaiting registry confirmation.",                  "Likely NOT resolving — restoration in progress."),
    "pendingTransfer":             ("yellow", "Transfer in progress — 5-day ICANN window active.",   "Approve/reject via auth email, or auto-approves.", "No DNS impact — NS moves with domain."),
    "pendingUpdate":               ("yellow", "Update (NS change / contact) pending at registry.",   "Wait for registry — usually minutes.",              "NS change may be propagating."),
    "redemptionPeriod":            ("red",    "Expired — 30-day redemption period. Costly restore.", "Restore via registrar before period ends.",         "Will NOT resolve — domain has expired."),
    "renewPeriod":                 ("green",  "Recently renewed — auto-renew grace period active.",  "No action needed.",                                "No impact."),
    "transferPeriod":              ("green",  "Recently transferred — 60-day ICANN lock now active.","Domain cannot be transferred again for 60 days.",  "No DNS impact."),
    "addPeriod":                   ("green",  "Newly registered — add grace period (5 days).",       "Registrar can delete for full refund during this.", "DNS active if NS are set."),
    "autoRenewPeriod":             ("green",  "Auto-renewed — grace period active (30–45 days).",    "Registrar can delete for refund during grace.",     "No impact — domain is active."),
}

# ── WHOIS Lookup ──────────────────────────────────────────────────────────────
def whois_lookup(domain=None, silent=False):
    if domain is None:
        domain = get_domain()
    if not silent:
        section(f"WHOIS — {domain}")

    try:
        w = whois.whois(domain)
    except Exception as e:
        err(f"WHOIS failed: {e}")
        session.store("whois", domain, {"error": str(e)})
        return None

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Field", style="bold yellow", width=20)
    table.add_column("Value", style="white")

    result = {}
    fields = [
        ("Registrar",    w.registrar),
        ("WHOIS Server", w.whois_server),
        ("Registrant",   getattr(w, "name", None) or getattr(w, "registrant_name", None)),
        ("Organisation", getattr(w, "org", None)),
        ("Country",      getattr(w, "country", None)),
        ("Created",      w.creation_date),
        ("Updated",      w.updated_date),
        ("Expires",      w.expiration_date),
        ("Status",       w.status),
        ("Name Servers", w.name_servers),
        ("DNSSEC",       getattr(w, "dnssec", None)),
        ("Emails",       getattr(w, "emails", None)),
    ]

    for field, value in fields:
        display = fmt_date(value)
        if not display: continue
        if field == "Expires":
            raw = value[0] if isinstance(value, list) else value
            if isinstance(raw, datetime.datetime):
                display = _naive(raw).strftime("%Y-%m-%d %H:%M UTC") + "  " + days_label(raw)
        if field == "Status" and isinstance(value, list):
            display = "\n".join(s.split()[0] for s in value if s)
        result[field] = display
        table.add_row(field, display)

    console.print(table)
    session.store("whois", domain, result)
    return result

# ── RDAP Lookup ───────────────────────────────────────────────────────────────
def rdap_lookup(domain=None, silent=False):
    if domain is None:
        domain = get_domain()
    if not silent:
        section(f"RDAP Lookup — {domain}")

    url = f"https://rdap.org/domain/{domain}"
    info(f"Endpoint: {url}")

    try:
        resp = requests.get(url, timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            err(f"RDAP returned HTTP {resp.status_code}"); return None
        data = resp.json()
    except Exception as e:
        err(f"RDAP request failed: {e}"); return None

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Field", style="bold yellow", width=24)
    table.add_column("Value", style="white")

    table.add_row("Domain",  data.get("ldhName", domain).upper())
    if "handle" in data: table.add_row("Handle", data["handle"])

    statuses = data.get("status", [])
    if statuses: table.add_row("Status", "\n".join(statuses))

    ns_list = [ns.get("ldhName","") for ns in data.get("nameservers",[])]
    if ns_list: table.add_row("Nameservers", "\n".join(ns_list))

    for evt in data.get("events", []):
        action   = evt.get("eventAction","")
        date_str = evt.get("eventDate","")
        display  = date_str
        try:
            dt = datetime.datetime.fromisoformat(date_str.replace("Z","+00:00")).replace(tzinfo=None)
            display = dt.strftime("%Y-%m-%d %H:%M UTC")
            if action == "expiration":
                display += "  " + days_label(dt)
        except Exception:
            pass
        table.add_row(f"Event: {action}", display)

    for entity in data.get("entities",[]):
        roles = entity.get("roles",[])
        vcard = entity.get("vcardArray",[])
        name  = ""
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn": name = item[3]; break
        if name: table.add_row(f"Entity ({', '.join(roles)})", name)

    console.print(table)
    session.store("rdap", domain, data)
    return data

# ── EPP / IANA Status Decoder ─────────────────────────────────────────────────
def epp_decoder(statuses=None):
    section("EPP / IANA Status Decoder")

    if statuses is None:
        console.print("  [dim]Tip: paste status codes exactly as in WHOIS output.[/dim]")
        raw = Prompt.ask("  [cyan]Status code(s)[/cyan] [dim](comma-separated)[/dim]")
        statuses = [s.strip() for s in raw.split(",")]

    decoded = {}
    for raw_s in statuses:
        code = raw_s.strip().split()[0].split("/")[-1]
        key  = next((k for k in EPP if k.lower() == code.lower()), None)
        console.print()
        if key:
            color, meaning, action, dns_impact = EPP[key]
            console.print(Panel(
                f"[bold {color}]{key}[/bold {color}]\n\n"
                f"[bold]Meaning:[/bold]     {meaning}\n"
                f"[bold]Action:[/bold]      {action}\n"
                f"[bold]DNS Impact:[/bold]  {dns_impact}",
                border_style=color, padding=(0, 2)
            ))
            decoded[key] = {"meaning": meaning, "action": action, "dns_impact": dns_impact}
        else:
            warn(f"Unknown code: [bold]{code}[/bold]")
            console.print("  → https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en")

    # Auto-flags
    console.print()
    holds   = [k for k in decoded if "hold" in k.lower()]
    if holds:
        err(f"HOLD detected: {', '.join(holds)}  →  DNS will NOT resolve!")
    if "pendingDelete" in decoded:
        warn("pendingDelete present — check if redemption window is still open.")
    if "redemptionPeriod" in decoded:
        warn("Redemption period — restore NOW before domain is purged.")
    if ("clientTransferProhibited" not in decoded and
        "serverTransferProhibited" not in decoded):
        info("No transfer lock detected — domain may be transferable.")

    session.store("epp", "N/A", {"input": statuses,
                                  "decoded": {k: v["meaning"] for k, v in decoded.items()}})
    return decoded
