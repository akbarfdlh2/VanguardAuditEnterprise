from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


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
        """
        Menghitung skor postur keamanan (0-100) berdasarkan penalti berbobot.
        """
        if not self.findings:
            return 0
        penalties: dict[Severity, int] = {
            Severity.HIGH: 16,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
            Severity.PASS: 0,
        }
        total_penalty = sum(penalties[f.severity] for f in self.findings)
        return max(0, 100 - total_penalty)

    @property
    def grade(self) -> str:
        """Mengonversi skor numerik menjadi Grade huruf standar industri."""
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
