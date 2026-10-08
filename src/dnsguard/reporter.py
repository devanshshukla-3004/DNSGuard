from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .models import DNSData, Finding


def report_dict(domain: str, data: DNSData, findings: list[Finding], score: int, grade: str) -> dict[str, Any]:
    counts = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    return {
        "domain": domain,
        "score": score,
        "grade": grade,
        "summary": counts,
        "records": {k: v for k, v in data.records.items() if v},
        "cname_chain": data.cname_chain,
        "authoritative_nameservers": data.nameservers,
        "resolver_nameservers": data.resolver_nameservers,
        "dnssec_records": data.dnssec_records,
        "errors": data.errors,
        "findings": [f.to_dict() for f in findings],
    }


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(path: str, findings: list[Finding]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "check_id", "title", "status", "severity", "score", "category", "evidence", "remediation"
        ])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "check_id": f.check_id, "title": f.title, "status": f.status.value,
                "severity": f.severity.value, "score": f.score, "category": f.category,
                "evidence": f.evidence, "remediation": f.remediation,
            })
