from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NA = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    score: int
    evidence: str
    remediation: str
    category: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "score": self.score,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
            "metadata": self.metadata,
        }


@dataclass
class DNSRecord:
    name: str
    rtype: str
    values: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.rtype, "values": self.values}


@dataclass
class DNSData:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    cname_chain: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    resolver_nameservers: list[str] = field(default_factory=list)
    dnssec_records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
