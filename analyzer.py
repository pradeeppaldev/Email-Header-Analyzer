# analyzer.py
import re

AUTH_LINE_KEYS = [
    "Authentication-Results",
    "ARC-Authentication-Results",
    "Received-SPF",
]

def find_auth_results(headers: dict) -> dict:
    auth_text = []
    for k in AUTH_LINE_KEYS:
        for v in headers.get(k, []):
            auth_text.append(f"{k}: {v}")
    blob = " | ".join(auth_text)

    def _grab(label):
        m = re.search(rf"{label}\s*=\s*(pass|fail|softfail|neutral|temperror|permerror)", blob, re.IGNORECASE)
        return (m.group(1).lower() if m else None)

    return {
        "spf": _grab("spf"),
        "dkim": _grab("dkim"),
        "dmarc": _grab("dmarc"),
        "raw": auth_text
    }

def alignment_hint(headers: dict) -> dict:
    # Very light alignment hint: compare From: domain with Return-Path/domain in auth fields
    from_field = (headers.get("From") or headers.get("FROM") or headers.get("from") or [None])[0]
    return_path = (headers.get("Return-Path") or headers.get("RETURN-PATH") or headers.get("return-path") or [None])[0]

    def domain_of(addr: str | None) -> str | None:
        if not addr:
            return None
        m = re.search(r"<([^>]+)>", addr)
        if m:
            addr = m.group(1)
        m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", addr)
        return m.group(1).lower() if m else None

    return {
        "from_domain": domain_of(from_field),
        "return_path_domain": domain_of(return_path)
    }

def risk_flags(headers: dict, received_hops: list[dict], auth: dict) -> list[str]:
    flags = []
    if not headers.get("Message-ID"):
        flags.append("Missing Message-ID")
    if not headers.get("Date"):
        flags.append("Missing Date")
    if not headers.get("From"):
        flags.append("Missing From")
    if auth.get("spf") == "fail":
        flags.append("SPF failed")
    if auth.get("dkim") == "fail":
        flags.append("DKIM failed")
    if auth.get("dmarc") == "fail":
        flags.append("DMARC failed")
    if len(received_hops) == 0:
        flags.append("No Received chain present")

    # Simple time ordering check: top Received is last hop; not doing strict chrono parse here
    # You can expand by parsing dates to datetime and verifying order and big delays.

    return flags
