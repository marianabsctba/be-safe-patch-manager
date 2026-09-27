import json
import os
from dataclasses import dataclass
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class ThreatIntelConfig:
    enabled: bool
    interval_seconds: int
    timeout_seconds: int
    epss_url: str
    kev_url: str


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, value)


def get_config() -> ThreatIntelConfig:
    return ThreatIntelConfig(
        enabled=_bool_env("THREAT_INTEL_ENABLED", False),
        interval_seconds=_int_env("THREAT_INTEL_SYNC_INTERVAL", 21600, 300),
        timeout_seconds=_int_env("THREAT_INTEL_TIMEOUT", 20, 5),
        epss_url=os.getenv("THREAT_INTEL_EPSS_URL", DEFAULT_EPSS_URL).strip() or DEFAULT_EPSS_URL,
        kev_url=os.getenv("THREAT_INTEL_KEV_URL", DEFAULT_KEV_URL).strip() or DEFAULT_KEV_URL,
    )


def public_config(config: ThreatIntelConfig | None = None) -> dict:
    config = config or get_config()
    return {
        "enabled": config.enabled,
        "configured": bool(config.epss_url and config.kev_url),
        "interval_seconds": config.interval_seconds,
        "timeout_seconds": config.timeout_seconds,
        "sources": {
            "epss": "FIRST EPSS",
            "kev": "CISA KEV",
        },
    }


def _get_json(url: str, timeout: int) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Be-Safe-Patch-Manager/0.18 threat-intel",
        },
        method="GET",
    )
    with urlopen(request, timeout=timeout) as response:
        if getattr(response, "status", 200) != 200:
            raise RuntimeError(f"unexpected HTTP status {response.status}")
        payload = response.read()
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("unexpected JSON payload")
    return data


def fetch_epss(cves: list[str], config: ThreatIntelConfig | None = None) -> dict[str, dict]:
    config = config or get_config()
    normalized = sorted({str(cve).strip().upper() for cve in cves if str(cve).strip()})
    results: dict[str, dict] = {}

    # FIRST documents a 2000-character maximum for the cve query parameter.
    current: list[str] = []
    current_len = 0
    chunks: list[list[str]] = []
    for cve in normalized:
        added = len(cve) + (1 if current else 0)
        if current and current_len + added > 1800:
            chunks.append(current)
            current = []
            current_len = 0
        current.append(cve)
        current_len += added
    if current:
        chunks.append(current)

    for chunk in chunks:
        query = urlencode({"cve": ",".join(chunk)})
        data = _get_json(f"{config.epss_url}?{query}", config.timeout_seconds)
        for row in data.get("data") or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                score = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            try:
                percentile = float(row.get("percentile"))
            except (TypeError, ValueError):
                percentile = None
            results[cve] = {
                "epss": max(0.0, min(1.0, score)),
                "epss_percentile": (
                    max(0.0, min(1.0, percentile))
                    if percentile is not None
                    else None
                ),
                "epss_date": str(row.get("date") or row.get("created") or ""),
            }

    return results


def fetch_kev(config: ThreatIntelConfig | None = None) -> dict[str, dict]:
    config = config or get_config()
    data = _get_json(config.kev_url, config.timeout_seconds)
    results: dict[str, dict] = {}
    for row in data.get("vulnerabilities") or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID") or row.get("cve") or "").strip().upper()
        if not cve:
            continue
        results[cve] = {
            "kev": True,
            "kev_date_added": str(row.get("dateAdded") or ""),
            "kev_due_date": str(row.get("dueDate") or ""),
            "kev_vendor_project": str(row.get("vendorProject") or ""),
            "kev_product": str(row.get("product") or ""),
            "kev_required_action": str(row.get("requiredAction") or ""),
            "kev_ransomware_use": str(row.get("knownRansomwareCampaignUse") or ""),
        }
    return results
