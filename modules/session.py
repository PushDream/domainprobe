"""Session — result storage, snapshots for diff mode, JSON/CSV export."""
import json, csv, datetime

_results   = []
_snapshots = {}

def store(module: str, domain: str, data: dict):
    _results.append({
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "module":    module,
        "domain":    domain,
        "data":      data,
    })

def snapshot(label: str, domain: str, data: dict):
    _snapshots.setdefault(domain, {})[label] = data

def get_snapshots(domain: str) -> dict:
    return _snapshots.get(domain, {})

def count() -> int:
    return len(_results)

def get_all() -> list:
    return list(_results)

def export_json(filename: str):
    from pathlib import Path
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(_results, f, indent=2, default=str)

def export_csv(filename: str):
    from pathlib import Path
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "module", "domain", "data"])
        for r in _results:
            w.writerow([r["timestamp"], r["module"], r["domain"],
                        json.dumps(r["data"], default=str)])
