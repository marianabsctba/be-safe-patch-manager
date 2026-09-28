from app import patch_feed_adapters as adapters
MSRC_XML=b"""<cvrfdoc><DocumentTracking><CurrentReleaseDate>2026-09-08T17:00:00Z</CurrentReleaseDate></DocumentTracking><ProductTree><FullProductName ProductID="p1"><Value>Windows 11 Version 24H2</Value></FullProductName></ProductTree><Vulnerability><CVE>CVE-2026-12345</CVE><Threats><Threat Type="3"><Description><Value>Critical</Value></Description><ProductID>p1</ProductID></Threat></Threats><Remediations><Remediation Type="2"><Description><Value>5069999</Value></Description><ProductID>p1</ProductID><Supercedence><Value>KB5068888</Value></Supercedence></Remediation></Remediations></Vulnerability></cvrfdoc>"""
def test_msrc_parser():
    item=adapters.parse_msrc_cvrf_xml(MSRC_XML,"2026-Sep")[0]
    assert item["patch_ref"]=="KB5069999"
    assert item["severity"]=="Critical"
    assert item["cves"]==["CVE-2026-12345"]
    assert item["supersedes"]==["KB5068888"]
def test_ubuntu_parser():
    payload={"id":"USN-9999-1","title":"curl vulnerabilities","published":"2026-09-28T12:00:00Z","cves":[{"id":"CVE-2026-11111"}],"releases":[{"release":"24.04 LTS","packages":[{"name":"curl","version":"8.5.0-2ubuntu10.7"},{"name":"libcurl4","version":"8.5.0-2ubuntu10.7"}]}]}
    items=adapters.parse_ubuntu_notice_detail(payload)
    assert sorted(x["patch_ref"] for x in items)==["curl","libcurl4"]
    assert all(x["cves"]==["CVE-2026-11111"] for x in items)
def test_msrc_304_reuses_cache(monkeypatch):
    monkeypatch.setattr(adapters,"_month_ids",lambda n:["2026-Sep"])
    cache={"documents":{"2026-Sep":{"etag":"abc","last_modified":"Tue","records":[{"patch_ref":"KB1","cves":[]}]}}}
    calls=[]
    def fetcher(url,**kwargs):
        calls.append(kwargs); return {"status":304,"body":b"","etag":"abc","last_modified":"Tue"}
    result=adapters.fetch_msrc_records({"months_back":1},cache,fetcher=fetcher)
    assert result["records"][0]["patch_ref"]=="KB1"
    assert result["meta"]["not_modified"]==1
    assert calls[0]["etag"]=="abc"
def test_unknown_adapter_rejected():
    try:
        adapters.fetch_patch_feed_records("evil-http")
        assert False
    except adapters.PatchFeedAdapterError:
        pass
