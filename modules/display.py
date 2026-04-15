"""Shared display utilities — Rich console, helpers, formatters."""
import datetime
from rich.console import Console
from rich.panel   import Panel
from rich.prompt  import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn

from .meta import APP_NAME, APP_SUBTITLE, APP_TAGLINE, APP_VERSION, APP_WEBSITE

console = Console()

# ── Layout helpers ────────────────────────────────────────────────────────────
def banner():
    console.print(Panel.fit(
        f"[bold cyan]{APP_NAME}[/bold cyan] [yellow]v{APP_VERSION}[/yellow]\n"
        f"[white]{APP_TAGLINE}[/white]\n"
        f"[dim]{APP_SUBTITLE}[/dim]\n"
        f"[dim]{APP_WEBSITE}[/dim]",
        border_style="cyan",
        padding=(0, 2),
    ))

def section(title):
    console.print(f"\n[bold cyan]┌─ {title}[/bold cyan]")
    console.rule(style="dim cyan")

def ok(msg):   console.print(f"  [green]✓[/green]  {msg}")
def warn(msg): console.print(f"  [yellow]⚠[/yellow]  {msg}")
def err(msg):  console.print(f"  [red]✗[/red]  {msg}")
def info(msg): console.print(f"  [cyan]ℹ[/cyan]  {msg}")

def get_domain(prompt_text="Enter domain name"):
    raw = Prompt.ask(f"  [cyan]{prompt_text}[/cyan]").strip().lower()
    return raw.split()[0]

def press_enter():
    Prompt.ask("\n  [dim]Press Enter to return to menu[/dim]")

# ── Date helpers ──────────────────────────────────────────────────────────────
def _naive(dt):
    if isinstance(dt, datetime.datetime):
        return dt.replace(tzinfo=None)
    return dt

def days_label(dt):
    try:
        if isinstance(dt, list): dt = dt[0]
        dt = _naive(dt)
        diff = (dt - datetime.datetime.utcnow()).days
        if   diff < 0:   return f"[bold red]EXPIRED {abs(diff)}d ago[/bold red]"
        elif diff < 30:  return f"[bold red]{diff}d remaining ⚠[/bold red]"
        elif diff < 90:  return f"[yellow]{diff}d remaining[/yellow]"
        else:            return f"[dim]{diff}d remaining[/dim]"
    except Exception:
        return ""

def fmt_date(v):
    """Deduplicate and normalise datetime values from python-whois."""
    if isinstance(v, list):
        seen, out = set(), []
        for i in v:
            if i is None: continue
            if isinstance(i, datetime.datetime):
                n = _naive(i)
                k = n.strftime("%Y-%m-%d %H:%M")
                if k not in seen and not k.startswith("0001"):
                    seen.add(k); out.append(n.strftime("%Y-%m-%d %H:%M UTC"))
            else:
                s = str(i).strip()
                if s and s not in seen: seen.add(s); out.append(s)
        return "\n".join(out)
    if isinstance(v, datetime.datetime):
        return _naive(v).strftime("%Y-%m-%d %H:%M UTC")
    return str(v) if v else ""

# ── Scoring helpers ───────────────────────────────────────────────────────────
def score_to_grade(pct):
    if pct >= 90: return "A"
    if pct >= 75: return "B"
    if pct >= 60: return "C"
    if pct >= 45: return "D"
    return "F"

def grade_color(g):
    return {"A": "bold green", "B": "green", "C": "yellow",
            "D": "red", "F": "bold red"}.get(g, "white")

# ── Spinner context manager ───────────────────────────────────────────────────
class Spinner:
    def __init__(self, msg="Working"):
        self._p = Progress(SpinnerColumn(),
                           TextColumn(f"[cyan]{msg}...[/cyan]"),
                           transient=True, console=console)
    def __enter__(self):
        self._t = self._p.add_task("", total=None)
        self._p.start(); return self
    def __exit__(self, *_):
        self._p.stop()
