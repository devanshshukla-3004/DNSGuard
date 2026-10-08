from dnsguard.analyzer import analyze, summarize
from dnsguard.models import DNSData, Status


def test_secureish_domain_fixture():
    data = DNSData(
        domain="example.com",
        records={
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "NS": ["ns1.example.net.", "ns2.example.net."],
            "MX": ["10 mail.example.net."],
            "TXT": ['"v=spf1 include:mail.example.net -all"'],
            "DMARC_TXT": ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'],
        },
        cname_chain=["example.com"],
        nameservers=["ns1.example.net.", "ns2.example.net."],
        resolver_nameservers=["10.0.0.53"],
        dnssec_records={"DS": ["12345 13 2 ABC"], "DNSKEY": ["257 3 13 ABC"], "RRSIG": ["..."]},
    )
    findings = analyze(data)
    score, grade = summarize(findings)
    assert any(x.check_id == "DNSSEC-001" and x.status == Status.PASS for x in findings)
    assert score > 60
    assert grade in {"A", "B", "C", "D", "F"}


def test_missing_dnssec_is_flagged():
    data = DNSData(domain="test.invalid", records={"NS": ["ns1.test.invalid."]}, nameservers=["ns1.test.invalid."])
    findings = analyze(data)
    dnssec = next(x for x in findings if x.check_id == "DNSSEC-001")
    assert dnssec.status == Status.FAIL


def test_cname_chain_warning():
    data = DNSData(domain="a.example", cname_chain=["a.example", "b.example", "c.example", "d.example", "e.example", "f.example"])
    findings = analyze(data)
    cname = next(x for x in findings if x.check_id == "DNS-CNAME-001")
    assert cname.status == Status.WARN
