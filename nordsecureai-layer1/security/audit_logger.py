import json, os, datetime
from pathlib import Path

LOG_DIR = Path("outputs/audit_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

class AuditLogger:
    def _write(self, entry):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        path = LOG_DIR / f"audit_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)
        return entry

    def log_scan_operation(self, **kwargs):
        entry = {"operation": "scan", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_linking_operation(self, **kwargs):
        entry = {"operation": "linking", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_erasure_operation(self, **kwargs):
        entry = {"operation": "erasure", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def log_access_operation(self, **kwargs):
        entry = {"operation": "access", "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z", **kwargs}
        return self._write(entry)

    def get_recent_logs(self, limit=20):
        logs = sorted(LOG_DIR.glob("audit_*.json"), reverse=True)
        return [json.load(open(l)) for l in logs[:limit]]
