# parser.py
import re

def unfold_headers(raw: str) -> list[str]:
    lines = raw.splitlines()
    out = []
    for line in lines:
        if not line.strip() and out:
            out.append("")  # preserve blank as separator (body boundary)
            continue
        if line.startswith((" ", "\t")) and out:
            out[-1] += " " + line.strip()
        else:
            out.append(line.strip())
    return out

def parse_headers(raw: str) -> dict:
    lines = unfold_headers(raw)
    headers = {}
    for line in lines:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        headers.setdefault(k, [])
        headers[k].append(v)
    return headers

def get_first(headers: dict, key: str) -> str | None:
    vals = headers.get(key) or headers.get(key.title()) or headers.get(key.upper())
    return vals[0] if vals else None

RECEIVED_RE = re.compile(
    r"from\s+(?P<from>.+?)\s+by\s+(?P<by>.+?)\s+(?:with\s+(?P<with>\S+))?.*?;\s*(?P<date>.+)$",
    re.IGNORECASE
)

IP_RE = re.compile(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")

def parse_received(headers: dict) -> list[dict]:
    hops = []
    for rec in headers.get("Received", []) + headers.get("RECEIVED", []) + headers.get("received", []):
        m = RECEIVED_RE.search(rec)
        hop = {"raw": rec}
        if m:
            hop.update({
                "from": m.group("from"),
                "by": m.group("by"),
                "with": m.group("with") or "",
                "date": m.group("date")
            })
        ipm = IP_RE.search(rec)
        if ipm:
            hop["ip"] = ipm.group("ip")
        hops.append(hop)
    return hops
