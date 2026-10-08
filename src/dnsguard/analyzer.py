from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import DNSData, Finding, Severity, Status

DMARC_RE = re.compile(r"^v=DMARC1", re.I)
SPF_RE = re.compile(r"^v=spf1", re.I)


def _txt(records: list[str]) -> list[str]:
    # dnspython usually returns TXT strings already joined.
    return [x.strip('"') for x in records]


def analyze(data: DNSData) -> list[Finding]:
    f: list[Finding] = []

    f.append(_record_presence(data, "A", "IPv4 resolution", Severity.INFO))
    f.append(_record_presence(data, "AAAA", "IPv6 resolution", Severity.INFO))
    f.append(_record_presence(data, "NS", "Authoritative nameservers", Severity.INFO))
    f.append(_record_presence(data, "MX", "Mail exchanger configuration", Severity.INFO))

    f.append(_dnssec(data))
    f.append(_spf(data))
    f.append(_dmarc(data))
    f.append(_cname(data))
    f.append(_ns_hygiene(data))
    f.append(_resolver(data))

    # DKIM cannot be reliably confirmed without a selector. Report discoverability honestly.
    f.append(Finding(
        "MAIL-003", "DKIM selector discoverability", Status.WARN, Severity.LOW, 70,
        "DKIM uses selector-specific records (selector._domainkey); no selector was supplied, so DKIM cannot be confirmed from the domain apex alone.",
        "Provide known DKIM selectors to a future selector-aware scan, or verify DKIM configuration from your mail provider.",
        "mail",
    ))

    return f


def _record_presence(data: DNSData, rtype: str, title: str, severity: Severity) -> Finding:
    values = data.records.get(rtype, [])
    return Finding(
        f"DNS-{rtype}", title,
        Status.PASS if values else Status.WARN,
        severity,
        100 if values else 60,
        f"{len(values)} {rtype} record(s) discovered." if values else f"No {rtype} records discovered.",
        f"Review whether the domain requires {rtype} records for its intended services.",
        "records",
        {"values": values},
    )


def _dnssec(data: DNSData) -> Finding:
    ds = data.dnssec_records.get("DS", [])
    keys = data.dnssec_records.get("DNSKEY", [])
    sigs = data.dnssec_records.get("RRSIG", [])
    if ds and keys:
        status, score, evidence = Status.PASS, 100, f"DS and DNSKEY records were discovered; RRSIG records: {len(sigs)}."
    elif ds or keys:
        status, score, evidence = Status.WARN, 55, "Partial DNSSEC-related records were discovered; full chain validation was not performed."
    else:
        status, score, evidence = Status.FAIL, 20, "No DS/DNSKEY records were discovered at the queried domain."
    return Finding(
        "DNSSEC-001", "DNSSEC deployment", status, Severity.HIGH, score, evidence,
        "Enable and correctly maintain DNSSEC at the authoritative DNS provider. Validate the chain with a DNSSEC-aware resolver.",
        "dnssec", {"ds": len(ds), "dnskey": len(keys), "rrsig": len(sigs)},
    )


def _spf(data: DNSData) -> Finding:
    values = [x for x in _txt(data.records.get("TXT", [])) if SPF_RE.match(x)]
    if not values:
        return Finding("MAIL-001", "SPF policy", Status.FAIL, Severity.HIGH, 20,
                       "No TXT record beginning with v=spf1 was discovered.",
                       "Publish an SPF policy that authorizes only legitimate sending services.",
                       "mail")
    policy = values[0]
    hard_fail = policy.lower().rstrip().endswith("-all")
    score = 100 if hard_fail else 75
    status = Status.PASS if hard_fail else Status.WARN
    return Finding("MAIL-001", "SPF policy", status, Severity.HIGH, score,
                   f"SPF record discovered: {policy}", "Prefer an explicit '-all' after validating all legitimate senders.", "mail",
                   {"records": values})


def _dmarc(data: DNSData) -> Finding:
    values = [x for x in _txt(data.records.get("DMARC_TXT", [])) if DMARC_RE.match(x)]
    if not values:
        evidence = "No DMARC policy was discovered at _dmarc."
        return Finding("MAIL-002", "DMARC policy", Status.FAIL, Severity.HIGH, 20, evidence,
                       "Publish a DMARC policy at _dmarc.<domain> and move toward enforcement after validating reporting.", "mail")
    policy = values[0]
    match = re.search(r"(?:^|;)\s*p=\s*([^;\s]+)", policy, re.I)
    p = match.group(1).lower() if match else "unknown"
    if p in {"reject", "quarantine"}:
        status, score = Status.PASS, 100
    else:
        status, score = Status.WARN, 60
    return Finding("MAIL-002", "DMARC policy", status, Severity.HIGH, score,
                   f"DMARC record discovered with p={p}.", "Use quarantine/reject when your mail flow is validated and monitor aggregate reports.", "mail",
                   {"records": values, "policy": p})


def _cname(data: DNSData) -> Finding:
    chain = data.cname_chain
    if len(chain) <= 1:
        return Finding("DNS-CNAME-001", "CNAME chain", Status.PASS, Severity.LOW, 100,
                       "No CNAME chain was observed for the queried name.", "Review DNS aliases periodically for stale dependencies.", "topology")
    if len(chain) > 5:
        return Finding("DNS-CNAME-001", "CNAME chain", Status.WARN, Severity.MEDIUM, 60,
                       "CNAME chain contains more than five hops: " + " -> ".join(chain), "Reduce unnecessary aliasing and review third-party dependencies.", "topology",
                       {"chain": chain})
    return Finding("DNS-CNAME-001", "CNAME chain", Status.PASS, Severity.LOW, 90,
                   "CNAME chain: " + " -> ".join(chain), "Keep alias chains short and review third-party targets.", "topology",
                   {"chain": chain})


def _ns_hygiene(data: DNSData) -> Finding:
    ns = data.nameservers
    if len(ns) < 2:
        return Finding("DNS-NS-001", "Authoritative NS redundancy", Status.WARN, Severity.MEDIUM, 55,
                       f"Only {len(ns)} authoritative NS record(s) were discovered.", "Use at least two independent authoritative nameservers where appropriate.", "resilience",
                       {"nameservers": ns})
    return Finding("DNS-NS-001", "Authoritative NS redundancy", Status.PASS, Severity.MEDIUM, 100,
                   f"{len(ns)} authoritative NS records were discovered.", "Maintain independent authoritative DNS infrastructure.", "resilience",
                   {"nameservers": ns})


def _resolver(data: DNSData) -> Finding:
    ns = data.resolver_nameservers
    private = [x for x in ns if x.startswith(("10.", "192.168.", "172."))]
    if private:
        return Finding("RESOLVER-001", "Configured resolver exposure", Status.PASS, Severity.INFO, 100,
                       "The scan used private/local resolver address(es): " + ", ".join(ns),
                       "Ensure local DNS forwarding and upstream policies use trusted, monitored resolvers.", "resolver",
                       {"nameservers": ns})
    return Finding("RESOLVER-001", "Configured resolver exposure", Status.PASS, Severity.INFO, 100,
                   "Resolver(s) used: " + ", ".join(ns), "Use trusted DNS infrastructure and consider protective DNS/validated resolution where appropriate.", "resolver",
                   {"nameservers": ns})


def summarize(findings: list[Finding]) -> tuple[int, str]:
    scored = [x.score for x in findings if x.status not in {Status.NA, Status.ERROR}]
    score = round(sum(scored) / len(scored)) if scored else 0
    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else: grade = "F"
    return score, grade
