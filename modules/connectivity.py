"""
Connectivity
────────────
• Ping — ICMP reachability test
• Port scan — 10 essential ports in parallel
• Traceroute — Windows (tracert) & Linux/Mac (traceroute) compatible
• ASN / BGP lookup — carrier, org, prefix, country via ipinfo.io
"""

import socket, subprocess, platform, concurrent.futures
import requests
from rich.table import Table
from rich import box
from rich.prompt import Confirm
from .display import console, section, subsection, ok, warn, err, info, get_domain, Spinner
from . import session

PORTS = [
    (80,   "HTTP"),
    (443,  "HTTPS"),
    (25,   "SMTP"),
    (587,  "SMTP-TLS"),
    (53,   "DNS"),
    (21,   "FTP"),
    (22,   "SSH"),
    (110,  "POP3"),
    (143,  "IMAP"),
    (8443, "HTTPS-ALT"),
]

def connectivity_check(domain=None):
    if domain is None: domain = get_domain("Enter domain or IP")
    section(f"Connectivity Check — {domain}")
    result_data = {}

    # ── Resolve IP ──
    try:
        ip = socket.gethostbyname(domain)
        ok(f"Resolves to: [bold]{ip}[/bold]")
        result_data["ip"] = ip
    except socket.gaierror:
        warn("Could not resolve — treating input as IP.")
        ip = domain
        result_data["ip"] = "unresolvable"

    # ── Ping ──
    subsection("Ping (4 packets)")
    flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        res = subprocess.run(["ping", flag, "4", ip],
                             capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                lo = line.lower()
                if any(kw in lo for kw in ("loss","rtt","round-trip","average","minimum","maximum")):
                    console.print(f"  [dim]{line.strip()}[/dim]")
            ok("Host is reachable via ICMP.")
            result_data["ping"] = "reachable"
        else:
            warn("Ping failed — host may block ICMP or be unreachable.")
            result_data["ping"] = "unreachable"
    except subprocess.TimeoutExpired:
        warn("Ping timed out."); result_data["ping"] = "timeout"
    except FileNotFoundError:
        warn("ping not available in this environment.")
    except Exception as e:
        err(f"Ping error: {e}")

    # ── Port scan ──
    subsection("Port Scan")

    def check_port(args):
        port, svc = args
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3); r = s.connect_ex((ip, port)); s.close()
            return port, svc, r == 0
        except: return port, svc, False

    with Spinner("Scanning ports"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            port_results = list(ex.map(check_port, PORTS))

    t = Table(box=box.SIMPLE, header_style="bold white")
    t.add_column("Port",    style="bold yellow", width=7)
    t.add_column("Service", width=12)
    t.add_column("Status",  width=14)
    for port, svc, is_open in port_results:
        t.add_row(str(port), svc,
                  "[green]● OPEN[/green]" if is_open else "[red]● CLOSED[/red]")
    console.print(t)
    result_data["ports"] = {f"{p}/{s}": o for p, s, o in port_results}

    # ── Traceroute ──
    if Confirm.ask("\n  [cyan]Run traceroute?[/cyan]", default=True):
        if platform.system() == "Windows":
            tr_cmd = ["tracert", "-d", "-h", "20", ip]
        else:
            tr_cmd = ["traceroute", "-n", "-m", "20", ip]
        try:
            info("Running traceroute (up to 60 s)…")
            tr = subprocess.run(tr_cmd, capture_output=True, text=True, timeout=65)
            console.print(f"[dim]{tr.stdout}[/dim]")
            result_data["traceroute"] = tr.stdout
        except FileNotFoundError:
            warn("traceroute/tracert not available.")
        except subprocess.TimeoutExpired:
            warn("Traceroute timed out after 60 s.")
        except Exception as e:
            err(f"Traceroute error: {e}")

    session.store("connectivity", domain, result_data)
    return result_data


# ── ASN / BGP Lookup ──────────────────────────────────────────────────────────
def asn_lookup(target=None):
    if target is None:
        target = get_domain("Enter domain or IP")
    section(f"ASN / BGP Lookup — {target}")

    # Resolve to IP if domain given
    ip = target
    if not target.replace(".", "").isdigit():
        try:
            ip = socket.gethostbyname(target)
            ok(f"Resolved: [bold]{target}[/bold] → [bold]{ip}[/bold]")
        except socket.gaierror:
            err(f"Could not resolve {target}"); return None

    info(f"Querying ASN data for [bold]{ip}[/bold]…")

    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=8,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            err(f"ipinfo.io returned HTTP {resp.status_code}"); return None
        data = resp.json()
    except Exception as e:
        err(f"ASN lookup failed: {e}"); return None

    from rich.table import Table
    from rich import box

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Field", style="bold yellow", width=18)
    table.add_column("Value", style="white")

    asn_raw  = data.get("org", "")
    asn_num  = asn_raw.split()[0] if asn_raw else "–"
    asn_name = " ".join(asn_raw.split()[1:]) if asn_raw and " " in asn_raw else asn_raw

    fields = [
        ("IP",          data.get("ip", ip)),
        ("Hostname",    data.get("hostname", "–")),
        ("ASN",         asn_num),
        ("Organisation",asn_name or "–"),
        ("City",        data.get("city", "–")),
        ("Region",      data.get("region", "–")),
        ("Country",     data.get("country", "–")),
        ("Prefix",      data.get("prefix") or data.get("network", "–")),
        ("Timezone",    data.get("timezone", "–")),
    ]
    for field, value in fields:
        if value and value != "–":
            table.add_row(field, str(value))

    console.print(table)
    console.print()

    if "bogon" in data:
        warn("Bogon IP — private/reserved address space, not routable on the public internet.")
    elif asn_num and asn_num.startswith("AS"):
        ok(f"Routed via {asn_num} ({asn_name})")

    result = {
        "ip": ip, "asn": asn_num, "org": asn_name,
        "country": data.get("country"), "city": data.get("city"),
        "prefix": data.get("prefix") or data.get("network"),
    }
    session.store("asn", target, result)
    return result
