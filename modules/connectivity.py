"""
Connectivity
────────────
• Ping — ICMP reachability test
• Port scan — 10 essential ports in parallel
• Traceroute — Windows (tracert) & Linux/Mac (traceroute) compatible
"""

import socket, subprocess, platform, concurrent.futures
from rich.table import Table
from rich import box
from rich.prompt import Confirm
from .display import console, section, ok, warn, err, info, get_domain, Spinner
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
    console.print("\n  [bold]Ping (4 packets)[/bold]")
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
    console.print("\n  [bold]Port Scan[/bold]")

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
