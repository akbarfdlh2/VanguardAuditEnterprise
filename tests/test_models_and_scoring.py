from vanguard.core.models import AuditFinding, AuditReport, Severity


def test_security_score_and_grade_calculation() -> None:
    report = AuditReport(target_url="https://example.com")
    report.findings = [
        AuditFinding(
            category="DNS Security",
            item="SPF Record",
            severity=Severity.HIGH,
            status="Tidak Ditemukan",
            description="SPF belum ada",
            remediation="Tambahkan v=spf1 -all",
        ),
        AuditFinding(
            category="HTTP Headers",
            item="X-Content-Type-Options",
            severity=Severity.PASS,
            status="Terkonfigurasi",
            description="nosniff aktif",
            remediation="Aman",
        ),
    ]
    # Skor 100 dikurangi penalti HIGH (16) = 84 (Grade B)
    assert report.score == 84
    assert report.grade == "B"
    assert len(report.filter_by_category("DNS Security")) == 1
    assert len(report.filter_by_category("ALL")) == 2
    assert len(report.filter_by_category("")) == 2

    counts = report.count_by_severity()
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.PASS] == 1
    assert counts[Severity.LOW] == 0


def test_empty_findings_score_and_grade() -> None:
    report = AuditReport(target_url="https://example.com")
    assert report.score == 0
    assert report.grade == "F"


def test_all_grades() -> None:
    # A+ (>=95)
    r_a_plus = AuditReport(
        target_url="https://example.com",
        findings=[
            AuditFinding(
                category="Test",
                item="Item",
                severity=Severity.LOW,
                status="S",
                description="D",
                remediation="R",
            )
        ],
    )
    assert r_a_plus.score == 97
    assert r_a_plus.grade == "A+"

    # A (>=85)
    r_a = AuditReport(
        target_url="https://example.com",
        findings=[
            AuditFinding(
                category="Test",
                item="Item",
                severity=Severity.MEDIUM,
                status="S",
                description="D",
                remediation="R",
            )
        ],
    )
    assert r_a.score == 92
    assert r_a.grade == "A"

    # C (>=60)
    r_c = AuditReport(
        target_url="https://example.com",
        findings=[
            AuditFinding(
                category="Test",
                item="Item",
                severity=Severity.HIGH,
                status="S",
                description="D",
                remediation="R",
            )
            for _ in range(2)
        ],
    )
    assert r_c.score == 68
    assert r_c.grade == "C"

    # D (>=45)
    r_d = AuditReport(
        target_url="https://example.com",
        findings=[
            AuditFinding(
                category="Test",
                item="Item",
                severity=Severity.HIGH,
                status="S",
                description="D",
                remediation="R",
            )
            for _ in range(3)
        ],
    )
    assert r_d.score == 52
    assert r_d.grade == "D"

    # F (<45)
    r_f = AuditReport(
        target_url="https://example.com",
        findings=[
            AuditFinding(
                category="Test",
                item="Item",
                severity=Severity.HIGH,
                status="S",
                description="D",
                remediation="R",
            )
            for _ in range(5)
        ],
    )
    assert r_f.score == 20
    assert r_f.grade == "F"
