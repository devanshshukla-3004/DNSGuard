from __future__ import annotations

from typing import Iterable

import dns.exception
import dns.resolver

from .models import DNSData


class DNSResolver:
    """Small, testable wrapper around dnspython's resolver."""

    TYPES = ("A", "AAAA", "MX", "NS", "CNAME", "SOA", "TXT", "CAA")

    def __init__(self, timeout: float = 3.0, lifetime: float = 5.0, nameservers: Iterable[str] | None = None):
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        if nameservers:
            self.resolver.nameservers = list(nameservers)

    def query(self, domain: str, rtype: str) -> list[str]:
        answers = self.resolver.resolve(domain, rtype, raise_on_no_answer=False)
        if answers.rrset is None:
            return []
        return [str(r).strip() for r in answers]

    def collect(self, domain: str) -> DNSData:
        data = DNSData(domain=domain.rstrip(".").lower())
        data.resolver_nameservers = [str(x) for x in self.resolver.nameservers]

        for rtype in self.TYPES:
            try:
                data.records[rtype] = self.query(data.domain, rtype)
            except (dns.exception.DNSException, OSError) as exc:
                data.errors[rtype] = str(exc)

        for rtype in ("DNSKEY", "DS", "RRSIG"):
            try:
                data.dnssec_records[rtype] = self.query(data.domain, rtype)
            except (dns.exception.DNSException, OSError) as exc:
                data.errors[rtype] = str(exc)

        data.nameservers = data.records.get("NS", [])
        data.cname_chain = self._cname_chain(data.domain)
        return data

    def _cname_chain(self, domain: str, limit: int = 10) -> list[str]:
        chain = [domain.rstrip(".")]
        current = domain
        seen = {current.rstrip(".").lower()}
        for _ in range(limit):
            try:
                values = self.query(current, "CNAME")
            except (dns.exception.DNSException, OSError):
                break
            if not values:
                break
            target = values[0].rstrip(".")
            if target.lower() in seen:
                chain.append(target)
                break
            chain.append(target)
            seen.add(target.lower())
            current = target
        return chain
