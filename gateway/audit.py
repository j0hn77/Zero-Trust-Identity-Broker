from datetime import datetime
from pathlib import Path

AUDIT_LOG_FILE = Path(__file__).resolve().parent / "access_audit.log"


def log_event(event_type: str, username: str, role_level: int, request=None, extra: str = ""):
    ts = datetime.utcnow().isoformat()

    ip = "N/A"
    ua = "N/A"
    method = "N/A"
    path = "N/A"

    if request is not None:
        try:
            ip = request.client.host
        except Exception:
            ip = "N/A"
        try:
            ua = request.headers.get("user-agent", "N/A")
        except Exception:
            ua = "N/A"
        try:
            method = request.method
            path = str(request.url.path)
        except Exception:
            pass

    line = (
        f"[{ts}] "
        f"EVENT={event_type} | "
        f"USER={username} | "
        f"ROLE={role_level} | "
        f"IP={ip} | "
        f"METHOD={method} | "
        f"PATH={path} | "
        f"UA={ua} | "
        f"{extra}\n"
    )

    # Ensure file exists
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
