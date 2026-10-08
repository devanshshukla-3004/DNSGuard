from dnsguard.reporter import report_dict
from dnsguard.models import DNSData, Finding, Severity, Status


def test_report_shape():
    finding = Finding("T1", "Test", Status.PASS, Severity.INFO, 100, "ok", "none", "test")
    payload = report_dict("example.com", DNSData(domain="example.com"), [finding], 100, "A")
    assert payload["grade"] == "A"
    assert payload["findings"][0]["check_id"] == "T1"
