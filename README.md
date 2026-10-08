# 🛡️ DNSGuard

### Day 09 — 100 Days, 100 Cybersecurity Projects

**DNSGuard is a defensive DNS security and configuration analyzer that turns ordinary DNS resolution into a structured security posture assessment.**

Instead of acting like a thin `nslookup` wrapper, DNSGuard collects DNS records, examines DNSSEC and email-security signals, evaluates CNAME and nameserver configuration, assigns evidence-backed findings, and exports machine-readable reports.

> **Scope:** DNSGuard is a practical security-auditing utility. It does not claim full DNSSEC validation, CIS/NIST compliance, or a complete DNS penetration test.

---

## 🎯 Why DNSGuard?

DNS is a critical trust layer for web infrastructure, email, identity, and application discovery. Weak DNS configuration can contribute to spoofing, redirection, mail abuse, stale dependencies, and loss of resilience.

DNSGuard focuses on **defensive visibility**:

```text
Domain
   ↓
DNS Resolver
   ↓
Record Collection
   ├── A / AAAA
   ├── MX / NS / SOA
   ├── CNAME / TXT / CAA
   └── DNSSEC records
   ↓
Security Analyzer
   ├── DNSSEC signals
   ├── SPF / DMARC
   ├── CNAME topology
   ├── NS redundancy
   └── Resolver visibility
   ↓
Risk Scoring
   ↓
CLI / JSON / CSV
```

---

## ✨ Current Capabilities

| Area | DNSGuard |
|---|---|
| A / AAAA discovery | ✅ |
| MX / NS / SOA discovery | ✅ |
| CNAME discovery + chain | ✅ |
| TXT / CAA discovery | ✅ |
| DNSSEC record signals | ✅ DS / DNSKEY / RRSIG |
| SPF analysis | ✅ |
| DMARC analysis | ✅ |
| DKIM assessment | ⚠️ Selector required |
| Nameserver redundancy | ✅ |
| Resolver visibility | ✅ |
| Security posture score | ✅ 0–100 |
| Letter grade | ✅ A–F |
| Evidence + remediation | ✅ |
| JSON export | ✅ |
| CSV export | ✅ |
| Automated tests | ✅ |
| GitHub Actions CI | ✅ Python 3.10–3.13 |

---

## 🚀 Quick Start

### 1. Clone

```bash
git clone https://github.com/devanshshukla-3004/DNSGuard.git
cd DNSGuard
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install

```bash
pip install -r requirements.txt
```

### 4. Analyze a domain

```bash
dnsguard example.com
```

Example workflow:

```text
DNSGuard — example.com
============================================================
Security posture: 78/100  Grade: C
Resolver(s): 192.168.1.1

[PASS] ...
[WARN] ...
[FAIL] ...
```

---

## 📊 Reports

JSON:

```bash
dnsguard example.com --json reports/example.json
```

CSV:

```bash
dnsguard example.com --csv reports/example.csv
```

Both:

```bash
dnsguard example.com --json reports/example.json --csv reports/example.csv
```

Quiet automation mode:

```bash
dnsguard example.com --quiet --json reports/example.json
```

The command returns a non-zero exit code when a security finding is marked `FAIL`, making the tool suitable for basic CI or scheduled-audit workflows.

---

## 🔍 What It Checks

### DNSSEC

DNSGuard looks for DNSSEC-related `DS`, `DNSKEY`, and `RRSIG` records.

A domain with both DS and DNSKEY records receives a stronger result, while partial signals produce a warning.

**Important:** record presence is **not equivalent to cryptographic DNSSEC validation**. Full chain validation requires a DNSSEC-validating resolver.

CISA describes DNSSEC as a mechanism for authenticating DNS data and integrity and notes that it can mitigate certain DNS redirection and hijacking attacks.

### SPF

DNSGuard searches TXT records for `v=spf1`.

It gives a stronger result when the policy ends with an explicit `-all`, while still requiring administrators to validate legitimate senders before enforcing a strict policy.

### DMARC

DNSGuard queries:

```text
_dmarc.example.com
```

It recognizes `p=quarantine` and `p=reject` as enforcement-oriented policies.

### DKIM

DKIM is selector-specific:

```text
<selector>._domainkey.example.com
```

Because a selector cannot reliably be inferred from the domain apex, DNSGuard explicitly reports that DKIM cannot be confirmed without selector information rather than pretending a negative result is authoritative.

### CNAME topology

Long CNAME chains are flagged because unnecessary aliasing can increase operational complexity and third-party dependency surface.

### Nameserver resilience

A single discovered authoritative nameserver produces a warning. Multiple authoritative nameservers receive a stronger result.

---

## 🧮 Scoring

DNSGuard produces a **security posture score from 0–100**.

The score is the average of scored findings:

```text
Posture Score = average(finding scores)
```

Grades:

| Score | Grade |
|---:|:---:|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

The score is a **triage signal**, not a compliance percentage.

---

## 🏗️ Architecture

```text
                 ┌─────────────────┐
                 │     Domain      │
                 └────────┬────────┘
                          ↓
                 ┌─────────────────┐
                 │   DNSResolver   │
                 └────────┬────────┘
                          ↓
             ┌─────────────────────────┐
             │      DNSData model      │
             └────────────┬────────────┘
                          ↓
                 ┌─────────────────┐
                 │ SecurityAnalyzer│
                 └────────┬────────┘
                          ↓
                 ┌─────────────────┐
                 │  Risk / Grade   │
                 └────────┬────────┘
                          ↓
              ┌───────────┴───────────┐
              ↓                       ↓
            CLI                  JSON / CSV
```

---

## 🧪 Testing

Run:

```bash
python -m pytest
```

The test suite covers:

- security finding generation
- DNSSEC fixture analysis
- missing DNSSEC detection
- CNAME chain warnings
- report structure

GitHub Actions tests Python **3.10, 3.11, 3.12, and 3.13**.

---

## 🔐 Security & Privacy Design

DNSGuard is designed as a **read-oriented defensive tool**.

It:

- performs DNS lookups only
- does not exploit DNS servers
- does not perform DNS flooding
- does not modify authoritative DNS
- does not collect credentials
- does not require an external threat-intelligence account
- produces local reports

Only analyze domains and infrastructure you own or are authorized to assess.

---

## ⚠️ Limitations

The current release intentionally has a narrow scope.

It does **not**:

- perform full DNSSEC cryptographic validation
- prove that an SPF policy is operationally correct
- infer every possible DKIM selector
- identify every third-party DNS dependency
- perform DNS takeover testing
- scan DNS zone transfers
- assess authoritative-server vulnerabilities
- provide full NIST/CIS compliance mapping
- inspect private enterprise DNS zones unless the configured resolver can access them

---

## 📚 Security References

DNSGuard's design is informed by defensive DNS guidance from CISA, including DNSSEC, DNS monitoring, protective DNS, and email-related DNS controls.

- CISA DNS Risk Assessment
- CISA TIC 3.0 DNS security guidance
- DNSSEC standards and operational guidance
- SPF / DKIM / DMARC email-authentication practices

---

## 🎓 Learning Outcomes

Building DNSGuard covers:

- DNS record types
- DNS resolution
- DNSSEC concepts
- email authentication
- DNS topology
- security scoring
- defensive automation
- structured security findings
- Python CLI design
- testable network tooling
- machine-readable security reporting
- CI/CD quality gates

---

## 📁 Project Structure

```text
DNSGuard/
├── .github/workflows/ci.yml
├── samples/
│   └── example-report.txt
├── src/dnsguard/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── cli.py
│   ├── models.py
│   ├── reporter.py
│   └── resolver.py
├── tests/
│   ├── test_analyzer.py
│   └── test_reporter.py
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 🏆 Challenge Positioning

**Day 09 of 100 Days, 100 Cybersecurity Projects**

DNSGuard increases the challenge complexity from individual configuration/header checks toward **network-aware security analysis** while remaining safe, explainable, and offline-reportable.

---

## 📜 License

MIT

## 👨‍💻 Author

**Devansh Shukla**

Cybersecurity • AI/Data Science • Security Engineering

GitHub: https://github.com/devanshshukla-3004

---

## ⚠️ Disclaimer

DNSGuard is an educational and defensive security tool. It is not a substitute for a professional DNS security assessment, incident-response investigation, or compliance audit.
