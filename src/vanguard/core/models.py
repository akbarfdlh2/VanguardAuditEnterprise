from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.HIGH: 16,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
    Severity.PASS: 0,
}


@dataclass(frozen=True)
class AuditFinding:
    category: str
    item: str
    severity: Severity
    status: str
    description: str
    remediation: str
    reference: str = "OWASP / RFC Standard"


@dataclass
class AuditReport:
    target_url: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    duration_seconds: float = 0.0
    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        if not self.findings:
            return 0
        total_penalty = sum(SEVERITY_PENALTIES[f.severity] for f in self.findings)
        return max(0, 100 - total_penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 95:
            return "A+"
        if s >= 85:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 45:
            return "D"
        return "F"

    def count_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def filter_by_category(self, category: str) -> list[AuditFinding]:
        if not category or category.upper() == "ALL":
            return self.findings
        return [f for f in self.findings if f.category.lower() == category.lower()]

    def securityscorecard_summary(self) -> dict[str, Any]:
        factors = [
            "Application Security",
            "Network Security",
            "Patching Cadence",
            "DNS Health",
            "Endpoint Security",
            "Information Leak",
            "IP Reputation",
            "Cubit Score",
            "Hacker Chatter",
            "Social Engineering",
        ]
        mapping: dict[str, list[str]] = {
            "Application Security": ["HTTP Headers", "Application Security", "CORS Policy"],
            "Network Security": ["Network Security", "SSL/TLS"],
            "Patching Cadence": ["Patching Cadence", "Info Exposure"],
            "DNS Health": ["DNS Security"],
            "Endpoint Security": ["Cookie Security", "API & Endpoints"],
            "Information Leak": ["Governance", "Info Exposure", "API & Endpoints"],
            "IP Reputation": ["DNS Security"],
            "Cubit Score": ["Network Security", "DNS Security"],
            "Hacker Chatter": [],
            "Social Engineering": ["DNS Security"],
        }
        res: dict[str, dict[str, Any]] = {}
        for factor in factors:
            cats = mapping.get(factor, [])
            relevant = [f for f in self.findings if f.category in cats]
            issues = [
                f for f in relevant if f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
            ]
            deduction = sum(SEVERITY_PENALTIES[f.severity] for f in issues)
            score = max(0, 100 - deduction) if relevant else 100
            res[factor] = {
                "score": score,
                "issues_count": len(issues),
                "status": "PASS" if not issues else f"{len(issues)} issues detected",
            }
        return {
            "overall_score": self.score,
            "overall_grade": self.grade,
            "factors": res,
        }
