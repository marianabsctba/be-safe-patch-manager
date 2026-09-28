import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
UBUNTU_NOTICES = "https://ubuntu.com/security/notices.json"
UBUNTU_NOTICE_DETAIL = "https://ubuntu.com/security/notices/{notice_id}.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
KB_RE = re.compile(r"(?:KB)?(\d{6,8})", re.I)

class PatchFeedAdapterError(RuntimeError):
    pass

def _utc(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(text)
            except (TypeError, ValueError) as exc:
                raise PatchFeedAdapterError(f"invalid date from provider: {text[:120]}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def _http_get(url, *, accept, timeout=20, etag="", last_modified=""):
    if not str(url).startswith("https://"):
        raise PatchFeedAdapterError("patch feed adapters only allow HTTPS")
    headers = {"Accept": accept, "User-Agent": "Be-Safe-Patch-Manager/0.34"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=max(5, min(int(timeout), 60))) as response:
            body = response.read(12 * 1024 * 1024 + 1)
            if len(body) > 12 * 1024 * 1024:
                raise PatchFeedAdapterError("provider response exceeds 12 MiB")
            return {"status": int(getattr(response, "status", 200)), "body": body,
                    "etag": response.headers.get("ETag", ""),
                    "last_modified": response.headers.get("Last-Modified", "")}
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return {"status": 304, "body": b"", "etag": etag, "last_modified": last_modified}
        raise PatchFeedAdapterError(f"provider HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PatchFeedAdapterError(f"provider request failed: {str(exc)[:300]}") from exc

def _json_body(response):
    try:
        return json.loads(response["body"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PatchFeedAdapterError("provider returned invalid JSON") from exc

def _local(tag):
    return str(tag).rsplit("}", 1)[-1]

def _children(node, name):
    return [item for item in list(node) if _local(item.tag) == name]

def _desc(node, name):
    return [item for item in node.iter() if _local(item.tag) == name]

def _value(node):
    if node is None:
        return ""
    values = _children(node, "Value")
    target = values[0] if values else node
    return (target.text or "").strip()

def _severity_rank(value):
    return {"critical": 4, "important": 3, "high": 3, "moderate": 2, "medium": 2, "low": 1}.get(str(value).lower(), 0)

def _max_severity(values):
    cleaned = [str(x or "").strip() for x in values if str(x or "").strip()]
    return max(cleaned, key=_severity_rank) if cleaned else "unknown"

def _month_ids(months_back, reference=None):
    reference = reference or datetime.now(timezone.utc)
    result = []
    year, month = reference.year, reference.month
    for _ in range(max(1, min(int(months_back), 12))):
        result.append(f"{year:04d}-{datetime(year, month, 1).strftime('%b')}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return result

def parse_msrc_cvrf_xml(payload, document_id=""):
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise PatchFeedAdapterError("MSRC returned invalid CVRF XML") from exc
    release_date = None
    tracking = next(iter(_desc(root, "DocumentTracking")), None)
    if tracking is not None:
        nodes = _desc(tracking, "CurrentReleaseDate") or _desc(tracking, "InitialReleaseDate")
        if nodes:
            release_date = _utc(_value(nodes[0]))
    product_names = {}
    for item in _desc(root, "FullProductName"):
        pid = str(item.attrib.get("ProductID") or "").strip()
        if pid:
            product_names[pid] = _value(item)
    grouped = {}
    for vulnerability in _desc(root, "Vulnerability"):
        cve_nodes = _children(vulnerability, "CVE")
        cve = _value(cve_nodes[0]).upper() if cve_nodes else ""
        cve = cve if CVE_RE.fullmatch(cve or "") else ""
        severities = {}
        for threats in _children(vulnerability, "Threats"):
            for threat in [x for x in list(threats) if _local(x.tag) == "Threat" and str(x.attrib.get("Type")) == "3"]:
                severity = _value(next(iter(_children(threat, "Description")), None))
                for pid_node in _desc(threat, "ProductID"):
                    pid = _value(pid_node)
                    if pid:
                        severities.setdefault(pid, []).append(severity)
        for remediations in _children(vulnerability, "Remediations"):
            for remediation in [x for x in list(remediations) if _local(x.tag) == "Remediation"]:
                if str(remediation.attrib.get("Type")) != "2":
                    continue
                description = _value(next(iter(_children(remediation, "Description")), None))
                match = KB_RE.search(description or "")
                if not match:
                    continue
                patch_ref = "KB" + match.group(1)
                pids = [_value(x) for x in _desc(remediation, "ProductID") if _value(x)]
                supersedes = []
                for node in _desc(remediation, "Supercedence"):
                    for raw in re.findall(r"(?:KB)?\d{6,8}", _value(node), flags=re.I):
                        m = KB_RE.search(raw)
                        if m:
                            supersedes.append("KB" + m.group(1))
                products = sorted({product_names.get(pid, pid) for pid in pids if product_names.get(pid, pid)})
                sev = []
                for pid in pids:
                    sev.extend(severities.get(pid, []))
                record = grouped.setdefault(patch_ref.lower(), {
                    "patch_ref": patch_ref, "vendor": "Microsoft",
                    "product": "; ".join(products[:8]),
                    "title": f"Microsoft security update {patch_ref}",
                    "severity": _max_severity(sev), "classification": "security_update",
                    "release_date": release_date.isoformat() if release_date else None,
                    "supersedes": [], "cves": [],
                    "source_url": f"{MSRC_BASE}/cvrf/{document_id}" if document_id else MSRC_BASE,
                })
                record["supersedes"] = sorted(set(record["supersedes"]) | set(supersedes))
                if cve:
                    record["cves"] = sorted(set(record["cves"]) | {cve})
                record["severity"] = _max_severity([record["severity"], *sev])
    return list(grouped.values())

def fetch_msrc_records(config, state, fetcher=_http_get):
    months_back = max(1, min(int(config.get("months_back", 2)), 12))
    timeout = max(5, min(int(config.get("timeout_seconds", 20)), 60))
    previous = state.get("documents") if isinstance(state.get("documents"), dict) else {}
    next_state, records, fetched, not_modified = {"documents": {}}, {}, 0, 0
    for document_id in _month_ids(months_back):
        cache = previous.get(document_id) if isinstance(previous.get(document_id), dict) else {}
        response = fetcher(f"{MSRC_BASE}/cvrf/{document_id}", accept="application/xml", timeout=timeout,
                           etag=str(cache.get("etag") or ""), last_modified=str(cache.get("last_modified") or ""))
        if response["status"] == 304:
            parsed = cache.get("records", [])
            not_modified += 1
        else:
            parsed = parse_msrc_cvrf_xml(response["body"], document_id)
            fetched += 1
        next_state["documents"][document_id] = {"etag": response.get("etag", cache.get("etag", "")),
            "last_modified": response.get("last_modified", cache.get("last_modified", "")), "records": parsed}
        for record in parsed:
            records[str(record.get("patch_ref") or "").lower()] = record
    return {"records": list(records.values()), "state": next_state,
            "meta": {"adapter": "msrc_cvrf", "documents": months_back, "fetched_documents": fetched,
                     "not_modified": not_modified, "records": len(records)}}

def _ubuntu_notices_list(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("notices", "items", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []

def _ubuntu_notice_id(item):
    return str(item.get("id") or item.get("notice_id") or item.get("usn") or "").strip()

def _ubuntu_cves(item):
    values = item.get("cves") or item.get("cve_ids") or []
    if isinstance(values, dict):
        values = list(values)
    result = []
    for value in values if isinstance(values, list) else []:
        raw = (value.get("id") or value.get("cve") or value.get("name")) if isinstance(value, dict) else value
        raw = str(raw or "").upper()
        if CVE_RE.fullmatch(raw):
            result.append(raw)
    return sorted(set(result))

def parse_ubuntu_notice_detail(item):
    notice_id = _ubuntu_notice_id(item)
    published = item.get("published") or item.get("published_at") or item.get("date") or item.get("release_date")
    release_date = _utc(published).isoformat() if published else None
    cves = _ubuntu_cves(item)
    title = str(item.get("title") or item.get("summary") or notice_id or "Ubuntu security update").strip()
    records = {}
    releases = item.get("releases") or item.get("release_packages") or []
    if isinstance(releases, dict):
        releases = [dict(value, release=name) for name, value in releases.items() if isinstance(value, dict)]
    for release in releases if isinstance(releases, list) else []:
        packages = release.get("packages") or release.get("binaries") or []
        if isinstance(packages, dict):
            packages = [{"name": name, **(value if isinstance(value, dict) else {})} for name, value in packages.items()]
        release_name = str(release.get("release") or release.get("codename") or release.get("name") or "").strip()
        for package in packages if isinstance(packages, list) else []:
            package_name = package if isinstance(package, str) else str(package.get("name") or package.get("package") or package.get("binary_name") or "").strip()
            version = "" if isinstance(package, str) else str(package.get("version") or package.get("fixed_version") or package.get("binary_version") or "").strip()
            if not package_name:
                continue
            record = records.setdefault(package_name.lower(), {"patch_ref": package_name, "vendor": "Canonical",
                "product": "Ubuntu" + (f" {release_name}" if release_name else ""), "title": title,
                "severity": "unknown", "classification": "security_update", "release_date": release_date,
                "supersedes": [], "cves": [],
                "source_url": f"https://ubuntu.com/security/notices/{notice_id}" if notice_id else "https://ubuntu.com/security/notices"})
            if version:
                record["title"] = f"{title} · fixed {version}"
            record["cves"] = sorted(set(record["cves"]) | set(cves))
    return list(records.values())

def fetch_ubuntu_records(config, state, fetcher=_http_get):
    max_notices = max(1, min(int(config.get("max_notices", 25)), 100))
    timeout = max(5, min(int(config.get("timeout_seconds", 20)), 60))
    listing_cache = state.get("listing") if isinstance(state.get("listing"), dict) else {}
    listing = fetcher(UBUNTU_NOTICES, accept="application/json", timeout=timeout,
                      etag=str(listing_cache.get("etag") or ""), last_modified=str(listing_cache.get("last_modified") or ""))
    candidates = listing_cache.get("notices", []) if listing["status"] == 304 else _ubuntu_notices_list(_json_body(listing))[:max_notices]
    previous = state.get("details") if isinstance(state.get("details"), dict) else {}
    details_state, records, fetched = {}, {}, 0
    for summary in candidates[:max_notices]:
        notice_id = _ubuntu_notice_id(summary)
        if not notice_id:
            continue
        cache = previous.get(notice_id) if isinstance(previous.get(notice_id), dict) else {}
        response = fetcher(UBUNTU_NOTICE_DETAIL.format(notice_id=notice_id), accept="application/json", timeout=timeout,
                           etag=str(cache.get("etag") or ""), last_modified=str(cache.get("last_modified") or ""))
        if response["status"] == 304:
            detail = cache.get("payload") or summary
        else:
            detail = _json_body(response)
            fetched += 1
        details_state[notice_id] = {"etag": response.get("etag", cache.get("etag", "")),
            "last_modified": response.get("last_modified", cache.get("last_modified", "")), "payload": detail}
        for record in parse_ubuntu_notice_detail(detail):
            key = record["patch_ref"].lower()
            if key in records:
                records[key]["cves"] = sorted(set(records[key]["cves"]) | set(record["cves"]))
            else:
                records[key] = record
    return {"records": list(records.values()),
            "state": {"listing": {"etag": listing.get("etag", listing_cache.get("etag", "")),
                                  "last_modified": listing.get("last_modified", listing_cache.get("last_modified", "")),
                                  "notices": candidates[:max_notices]}, "details": details_state},
            "meta": {"adapter": "ubuntu_security", "notices": min(len(candidates), max_notices),
                     "fetched_details": fetched, "records": len(records)}}

def fetch_patch_feed_records(provider_type, config=None, state=None):
    provider_type = str(provider_type or "").strip().lower()
    config = config if isinstance(config, dict) else {}
    state = state if isinstance(state, dict) else {}
    if provider_type == "msrc_cvrf":
        return fetch_msrc_records(config, state)
    if provider_type == "ubuntu_security":
        return fetch_ubuntu_records(config, state)
    raise PatchFeedAdapterError(f"provider type not implemented: {provider_type}")
