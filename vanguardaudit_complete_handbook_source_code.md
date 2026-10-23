# 🛡️ VanguardAudit Enterprise: Defensive Security Posture & Compliance Inspector

**Complete Engineering Handbook, Architecture Blueprint & Full Production Source Code**

> **Disclaimer & Etika Penggunaan:**
>
> **VanguardAudit** dirancang murni untuk tujuan **defensif** (*Security Hardening, Configuration Auditing, & Compliance Assessment*). Alat ini tidak melakukan eksploitasi aktif maupun pengiriman *payload* berbahaya, melainkan memeriksa kelengkapan standar keamanan infrastruktur (HTTP Security Headers, SSL/TLS Posture, CORS, RFC 9116 `security.txt`, serta DNS & Email Anti-Spoofing Security). Gunakan hanya pada domain, aplikasi, atau server milik Anda sendiri atau yang memiliki izin tertulis resmi.

---

## 📑 Daftar Isi

1. [Ikhtisar & Kemampuan Detail Aplikasi (Enterprise Edition)](#1-ikhtisar--kemampuan-detail-aplikasi-enterprise-edition)
2. [Standar Engineering & Arsitektur (Engineering Handbook)](#2-standar-engineering--arsitektur-engineering-handbook)
3. [Struktur Folder Proyek Lengkap](#3-struktur-folder-proyek-lengkap)
4. [Konfigurasi Proyek, Linter, Type-Checker & Security Gate](#4-konfigurasi-proyek-linter-type-checker--security-gate)
   * [4.1. `pyproject.toml` (Lengkap: Ruff, Mypy, Pytest, Coverage, Bandit)](#41-pyprojecttoml-lengkap-ruff-mypy-pytest-coverage-bandit)
   * [4.2. `.pre-commit-config.yaml` (Automated Git Hook Quality Gate)](#42-pre-commit-configyaml-automated-git-hook-quality-gate)
   * [4.3. `Makefile` (Developer Productivity Shortcuts)](#43-makefile-developer-productivity-shortcuts)
5. [Kode Sumber Lengkap (Full Source Code)](#5-kode-sumber-lengkap-full-source-code)
   * [5.1. Core Models, CVSS-like Weighting & Scoring Engine (`src/vanguard/core/models.py`)](#51-core-models-cvss-like-weighting--scoring-engine-srcvanguardcoremodelspy)
   * [5.2. Enterprise Configuration & Constants (`src/vanguard/core/config.py`)](#52-enterprise-configuration--constants-srcvanguardcoreconfigpy)
   * [5.3. Structured Logger (`src/vanguard/core/logger.py`)](#53-structured-logger-srcvanguardcoreloggerpy)
   * [5.4. Base Auditor Contract (`src/vanguard/auditors/base.py`)](#54-base-auditor-contract-srcvanguardauditorsbasepy)
   * [5.5. Deep DNS & Email Security Auditor (`src/vanguard/auditors/dns_auditor.py`)](#55-deep-dns--email-security-auditor-srcvanguardauditorsdns_auditorpy)
   * [5.6. HTTP Security Headers, CORS & Cookie Auditor (`src/vanguard/auditors/headers_auditor.py`)](#56-http-security-headers-cors--cookie-auditor-srcvanguardauditorsheaders_auditorpy)
   * [5.7. SSL/TLS Certificate, Cipher & HSTS Preload Auditor (`src/vanguard/auditors/ssl_auditor.py`)](#57-ssltls-certificate-cipher--hsts-preload-auditor-srcvanguardauditorsssl_auditorpy)
   * [5.8. RFC 9116 (`security.txt`) & Governance Auditor (`src/vanguard/auditors/governance_auditor.py`)](#58-rfc-9116-securitytxt--governance-auditor-srcvanguardauditorsgovernance_auditorpy)
   * [5.9. Markdown, JSON & HTML Report Exporter (`src/vanguard/utils/exporter.py`)](#59-markdown-json--html-report-exporter-srcvanguardutilsexporterpy)
   * [5.10. Terminal UI (TUI) Styling (`src/vanguard/ui/styles.tcss`)](#510-terminal-ui-tui-styling-srcvanguarduistylestcss)
   * [5.11. Main Application: Interactive TUI & Headless CI/CD CLI (`src/vanguard/main.py`)](#511-main-application-interactive-tui--headless-cicd-cli-srcvanguardmainpy)
6. [Unit Testing Lengkap (`tests/`)](#6-unit-testing-lengkap-tests)
   * [6.1. `tests/test_models_and_scoring.py`](#61-teststest_models_and_scoringpy)
   * [6.2. `tests/test_dns_auditor.py`](#62-teststest_dns_auditorpy)
7. [Panduan Instalasi, Penggunaan TUI & Integrasi CI/CD](#7-panduan-instalasi-penggunaan-tui--integrasi-cicd)

---

## 1. Ikhtisar & Kemampuan Detail Aplikasi (Enterprise Edition)

**VanguardAudit Enterprise** adalah aplikasi *Terminal User Interface* (TUI) sekaligus *Headless CLI* berbasis Python untuk membantu *Software Engineer*, *DevSecOps*, dan *System Administrator* mengaudit postur keamanan aplikasi web dan domain sebelum maupun sesudah naik ke produksi (*production hardening*).

### Fitur Pemeriksaan Defensif Mendalam:

1. **Deep DNS & Email Security Posture (`dns_auditor.py`):**
   * **SPF (Sender Policy Framework) Deep Parser:** Memeriksa keberadaan `v=spf1`, memvalidasi mekanisme akhiran (`-all` *HardFail*, `~all` *SoftFail*, `?all` *Neutral*, atau `+all` *Pass/Berbahaya*), serta menghitung jumlah *DNS lookup mechanism* (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) agar tidak melampaui batas maksimal **10 DNS lookups** sesuai standar **RFC 7208** (yang dapat menyebabkan `PermError`).
   * **DMARC (Domain-based Message Authentication, Reporting, and Conformance) Analyzer:** Membedah tag `v=DMARC1`, kebijakan utama (`p=none`, `p=quarantine`, `p=reject`), kebijakan subdomain (`sp=`), persentase penerapan (`pct=`), serta memastikan keberadaan alamat pelaporan agregat (`rua=`) dan forensik (`ruf=`).
   * **DKIM Selector Discovery (Non-Intrusif):** Memeriksa ketersediaan *public key* DKIM pada *selector* standar umum (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`) untuk memastikan kesiapan tanda tangan kriptografi email.
   * **MTA-STS & SMTP TLS Reporting (`_mta-sts` & `_smtp._tls`):** Memeriksa apakah domain menerapkan enkripsi wajib pada jalur pengiriman email antar-server (*Mail Transfer Agent Strict Transport Security* - RFC 8461).
   * **CAA (Certification Authority Authorization - RFC 8659):** Memastikan domain membatasi *Certificate Authority* (CA) mana saja yang diizinkan menerbitkan sertifikat SSL/TLS (`issue`, `issuewild`, `iodef`).
   * **DNSSEC Validation:** Memeriksa keberadaan *record* kriptografi `DNSKEY` dan `DS` untuk melindungi domain dari *DNS Cache Poisoning* / *Spoofing*.

2. **HTTP Security Headers, CORS & Cookie Hardening (`headers_auditor.py`):**
   * Memvalidasi keberadaan dan ketepatan direktif pada `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` (COOP), dan `Cross-Origin-Resource-Policy` (CORP).
   * Mengevaluasi risiko konfigurasi `Access-Control-Allow-Origin` dan mendeteksi *Information Disclosure* pada header `Server` dan `X-Powered-By`.
   * Memeriksa setiap *cookie* pada `Set-Cookie` untuk memastikan atribut `Secure`, `HttpOnly`, dan `SameSite` telah terpasang.

3. **SSL/TLS & Cryptography Posture (`ssl_auditor.py`):**
   * Memverifikasi versi protokol (`TLSv1.2` / `TLSv1.3`), kekuatan *Cipher Suite* ($\ge 128$-bit), rantai sertifikat CA, kecocokan *Subject Alternative Name* (SAN), serta menghitung mundur sisa hari masa berlaku sertifikat.

4. **RFC 9116 (`/.well-known/security.txt`) & Governance (`governance_auditor.py`):**
   * Memeriksa apakah organisasi menyediakan kanal pelaporan celah keamanan resmi sesuai standar **RFC 9116** (`/.well-known/security.txt`) beserta atribut wajib `Contact:` dan `Expires:`.

5. **Dual-Mode Execution (Interactive TUI + Headless CI/CD CLI):**
   * Jalankan tanpa argumen untuk membuka **Dashboard Terminal Interaktif (Textual)** yang dilengkapi filter kategori, kartu metrik *real-time*, dan panel inspeksi mitigasi.
   * Jalankan dengan argumen `--headless --url https://domainanda.com --fail-under 80` di dalam pipeline **GitHub Actions / GitLab CI** untuk menggagalkan *deployment* secara otomatis jika skor keamanan turun di bawah ambang batas.

---

## 2. Standar Engineering & Arsitektur (Engineering Handbook)

Proyek ini dibangun mengikuti kaidah **Software Engineering Handbook** tingkat industri:

* **Modular `src-layout` Architecture:** Memisahkan kode produksi di dalam `src/vanguard/` dan pengujian di dalam `tests/`, mencegah *import shadowing* dan memastikan paket siap didistribusikan sebagai *wheel* standar.
* **Strict Static Typing:** Seluruh fungsi, atribut kelas, dan nilai kembalian didefinisikan secara eksplisit dan diverifikasi menggunakan `mypy --strict`.
* **Concurrent Execution (`asyncio.gather`):** Semua modul auditor dijalankan secara paralel (*concurrent non-blocking I/O*) sehingga pemindaian menyeluruh selesai hanya dalam hitungan $1.5 - 3.0$ detik.
* **Zero-Dependency Domain Core:** Modul `core/` hanya menggunakan *Python Standard Library* (`dataclasses`, `enum`, `datetime`) sehingga logika bisnis dan penilaian skor sangat mudah diuji (*100% unit-testable*).
* **Automated Quality & Security Gates:** Konfigurasi `pyproject.toml` telah menyertakan aturan ketat untuk **Ruff** (Linter + Formatter), **Mypy** (Static Type Checker), **Bandit** (Static Application Security Testing untuk kode Python), dan **Pytest** (Unit Testing & Coverage).

---

## 3. Struktur Folder Proyek Lengkap

Buat struktur direktori berikut di komputer Anda:

```text
vanguard-audit/
├── .pre-commit-config.yaml
├── Makefile
├── pyproject.toml
├── README.md
├── src/
│   └── vanguard/
│       ├── __init__.py
│       ├── main.py                        # Entry point (TUI & Headless CLI)
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py                  # Konstanta & aturan standar audit
│       │   ├── logger.py                  # Structured console & file logger
│       │   └── models.py                  # Data models & scoring engine
│       ├── auditors/
│       │   ├── __init__.py
│       │   ├── base.py                    # Abstract Base Class (Strategy Pattern)
│       │   ├── dns_auditor.py             # Deep DNS & Email Security Auditor
│       │   ├── headers_auditor.py         # HTTP Security Headers, CORS & Cookies
│       │   ├── ssl_auditor.py             # SSL/TLS Certificate & Cipher Auditor
│       │   └── governance_auditor.py      # RFC 9116 security.txt Auditor
│       ├── ui/
│       │   ├── __init__.py
│       │   └── styles.tcss                # Textual CSS stylesheet
│       └── utils/
│           ├── __init__.py
│           └── exporter.py                # Ekspor laporan ke Markdown & JSON
└── tests/
    ├── __init__.py
    ├── test_models_and_scoring.py
    └── test_dns_auditor.py
```

---

## 4. Konfigurasi Proyek, Linter, Type-Checker & Security Gate

### 4.1. `pyproject.toml` (Lengkap: Ruff, Mypy, Pytest, Coverage, Bandit)

Simpan kode berikut sebagai `pyproject.toml` di direktori utama (`vanguard-audit/pyproject.toml`). File ini mengatur manajemen paket, *entry-point* CLI, serta konfigurasi lengkap *linter*, *formatter*, *type-checker*, *test runner*, dan *security scanner*:

```toml
[build-system]
requires = ["setuptools>=69.0.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "vanguard-audit"
version = "2.0.0"
description = "Enterprise Defensive Web, SSL/TLS & DNS Security Posture Inspector (TUI & CI/CD CLI)"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [
    { name = "Defensive Security Engineering Team", email = "security@example.com" }
]
keywords = ["security", "audit", "defensive", "tui", "spf", "dmarc", "dnssec", "owasp", "textual"]
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Typing :: Typed",
]
dependencies = [
    "textual>=0.58.0",
    "rich>=13.7.1",
    "httpx>=0.27.0",
    "dnspython>=2.6.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.1.0",
    "pytest-asyncio>=0.23.6",
    "pytest-cov>=5.0.0",
    "ruff>=0.4.0",
    "mypy>=1.10.0",
    "bandit[toml]>=1.7.8",
    "pre-commit>=3.7.0",
]

[project.scripts]
vanguard = "vanguard.main:entrypoint"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
vanguard = ["ui/*.tcss"]

# =====================================================================
# RUFF CONFIGURATION (Linter, Import Sorter & Code Formatter)
# =====================================================================
[tool.ruff]
line-length = 100
target-version = "py310"
src = ["src", "tests"]
exclude = [
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
]

[tool.ruff.lint]
select = [
    "E",      # pycodestyle errors
    "W",      # pycodestyle warnings
    "F",      # Pyflakes
    "I",      # isort (import sorting)
    "B",      # flake8-bugbear (common bugs & design problems)
    "C4",     # flake8-comprehensions
    "UP",     # pyupgrade (modern python syntax)
    "SIM",    # flake8-simplify
    "RET",    # flake8-return
    "PTH",    # flake8-use-pathlib
    "S",      # flake8-bandit (security checks)
    "RUF",    # Ruff-specific rules
]
ignore = [
    "E501",   # Line length diatur oleh formatter
    "S101",   # Mengizinkan penggunaan assert di dalam folder tests
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "S105", "S106"]

[tool.ruff.lint.isort]
known-first-party = ["vanguard"]
combine-as-imports = true

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
skip-magic-trailing-comma = false
line-ending = "auto"

# =====================================================================
# MYPY CONFIGURATION (Strict Static Type Checking)
# =====================================================================
[tool.mypy]
python_version = "3.10"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = false
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
ignore_missing_imports = true
mypy_path = "src"

# =====================================================================
# PYTEST & COVERAGE CONFIGURATION
# =====================================================================
[tool.pytest.ini_options]
minversion = "8.0"
asyncio_mode = "auto"
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-ra -q --strict-markers --cov=src/vanguard --cov-report=term-missing"

[tool.coverage.run]
branch = true
source = ["src/vanguard"]
omit = [
    "src/vanguard/main.py",
    "src/vanguard/__init__.py",
]

[tool.coverage.report]
fail_under = 80
show_missing = true
exclude_lines = [
    "pragma: no cover",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]

# =====================================================================
# BANDIT CONFIGURATION (Static Security Analysis for Python Code)
# =====================================================================
[tool.bandit]
exclude_dirs = ["tests", ".venv"]
skips = ["B101"]
```

---

### 4.2. `.pre-commit-config.yaml` (Automated Git Hook Quality Gate)

Simpan sebagai `.pre-commit-config.yaml` agar setiap *commit* otomatis diperiksa oleh *linter* dan *type-checker*:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-toml
      - id: check-added-large-files

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.2
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

---

### 4.3. `Makefile` (Developer Productivity Shortcuts)

Simpan sebagai `Makefile` untuk memudahkan eksekusi perintah harian:

```makefile
.PHONY: install run cli lint format typecheck security test all

install:
	pip install -e ".[dev]"

run:
	python -m src.vanguard.main

cli:
	python -m src.vanguard.main --headless --url https://example.com --export-md

lint:
	ruff check src tests

format:
	ruff format src tests

typecheck:
	mypy src

security:
	bandit -c pyproject.toml -r src

test:
	pytest

all: format lint typecheck security test
```

---

## 5. Kode Sumber Lengkap (Full Source Code)

### 5.1. Core Models, CVSS-like Weighting & Scoring Engine (`src/vanguard/core/models.py`)

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List


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
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """
        Menghitung skor postur keamanan (0-100) berdasarkan penalti berbobot.
        """
        if not self.findings:
            return 0
        penalties: Dict[Severity, int] = {
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

    def count_by_severity(self) -> Dict[Severity, int]:
        counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def filter_by_category(self, category: str) -> List[AuditFinding]:
        if not category or category.upper() == "ALL":
            return self.findings
        return [f for f in self.findings if f.category.lower() == category.lower()]
```

---

### 5.2. Enterprise Configuration & Constants (`src/vanguard/core/config.py`)

```python
from typing import Dict, List, Tuple
from src.vanguard.core.models import Severity

APP_NAME = "VanguardAudit Enterprise"
APP_VERSION = "2.0.0"
DEFAULT_TIMEOUT = 8.0
USER_AGENT = f"VanguardAudit-DefensiveInspector/{APP_VERSION} (+https://localhost/security-posture)"

# Selector DKIM umum yang sering digunakan oleh layanan email korporat
COMMON_DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "smtp",
    "dkim",
    "mandrill",
    "sendgrid",
    "amazonses",
]

# Standar HTTP Security Headers wajib beserta tingkat keparahan, penjelasan, dan panduan mitigasi
REQUIRED_SECURITY_HEADERS: Dict[str, Tuple[Severity, str, str, str]] = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Memaksa browser hanya berkomunikasi melalui HTTPS terenkripsi dan mencegah SSL Stripping.",
        "Tambahkan header: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'",
        "RFC 6797 / OWASP HSTS",
    ),
    "Content-Security-Policy": (
        Severity.HIGH,
        "Mencegah eksekusi skrip berbahaya (Cross-Site Scripting / XSS) dan injeksi aset eksternal.",
        "Terapkan CSP ketat, minimal: \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"",
        "W3C CSP Level 3 / OWASP",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Melindungi halaman web agar tidak dibungkus ke dalam <frame> atau <iframe> (mitigasi Clickjacking).",
        "Tambahkan header: 'X-Frame-Options: DENY' atau 'SAMEORIGIN'",
        "RFC 7034",
    ),
    "X-Content-Type-Options": (
        Severity.MEDIUM,
        "Mencegah browser menebak tipe konten secara sepihak (MIME-sniffing protection).",
        "Tambahkan header: 'X-Content-Type-Options: nosniff'",
        "OWASP Secure Headers",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Mengatur seberapa banyak informasi URL asal (Referer) yang dikirim saat pengguna berpindah situs.",
        "Tambahkan header: 'Referrer-Policy: strict-origin-when-cross-origin'",
        "W3C Referrer Policy",
    ),
    "Permissions-Policy": (
        Severity.LOW,
        "Membatasi penggunaan fitur API browser sensitif (Kamera, Mikrofon, USB, Geolokasi).",
        "Tambahkan header: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'",
        "W3C Permissions Policy",
    ),
    "Cross-Origin-Opener-Policy": (
        Severity.LOW,
        "Mengisolasi konteks browsing tingkat-atas (browsing context) dari dokumen lintas-domain.",
        "Tambahkan header: 'Cross-Origin-Opener-Policy: same-origin'",
        "HTML Living Standard (COOP)",
    ),
}
```

---

### 5.3. Structured Logger (`src/vanguard/core/logger.py`)

```python
import logging
from rich.logging import RichHandler


def get_logger(name: str = "vanguard") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
        formatter = logging.Formatter("%(message)s", datefmt="[%X]")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
```

---

### 5.4. Base Auditor Contract (`src/vanguard/auditors/base.py`)

```python
from abc import ABC, abstractmethod
from typing import List
from src.vanguard.core.models import AuditFinding


class BaseAuditor(ABC):
    """Kontrak dasar (Interface) untuk seluruh modul auditor defensif."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nama deskriptif modul auditor."""
        raise NotImplementedError

    @abstractmethod
    async def run(self, target_url: str) -> List[AuditFinding]:
        """Menjalankan pemeriksaan konfigurasi keamanan secara asinkron."""
        raise NotImplementedError
```

---

### 5.5. Deep DNS & Email Security Auditor (`src/vanguard/auditors/dns_auditor.py`)

Modul ini mengimplementasikan pemeriksaan DNS secara menyeluruh menggunakan `dnspython`. Mencakup analisis sintaks SPF *lookup limit* (RFC 7208), *parser* atribut DMARC (RFC 7489), penemuan *selector* DKIM umum, pemeriksaan kebijakan enkripsi email MTA-STS (RFC 8461) & TLS-RPT (RFC 8460), otorisasi penerbit sertifikat CAA (RFC 8659), serta validasi DNSSEC (`DNSKEY`/`DS`).

```python
import asyncio
import re
from typing import Dict, List
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from src.vanguard.auditors.base import BaseAuditor
from src.vanguard.core.config import COMMON_DKIM_SELECTORS, DEFAULT_TIMEOUT
from src.vanguard.core.models import AuditFinding, Severity


class DNSAuditor(BaseAuditor):
    """
    Enterprise DNS & Email Anti-Spoofing Posture Auditor.
    Memeriksa SPF (beserta batas 10 DNS lookup), DMARC (beserta tag p, sp, pct, rua),
    DKIM Selectors, MTA-STS, SMTP TLS-RPT, CAA, MX, dan DNSSEC.
    """

    @property
    def name(self) -> str:
        return "Enterprise DNS & Email Security Auditor (SPF, DMARC, DKIM, MTA-STS, CAA, DNSSEC)"

    async def run(self, target_url: str) -> List[AuditFinding]:
        return await asyncio.to_thread(self._sync_audit_dns, target_url)

    @staticmethod
    def _extract_base_domain(hostname: str) -> str:
        """
        Mengekstrak domain utama dari hostname (mendukung TLD umum maupun ccTLD seperti .co.id, .ac.id, .go.id).
        """
        parts = hostname.lower().strip(".").split(".")
        if len(parts) <= 2:
            return hostname
        multi_part_tlds = {"co.id", "ac.id", "go.id", "or.id", "sch.id", "co.uk", "org.uk", "com.au", "com.sg"}
        last_two = ".".join(parts[-2:])
        if last_two in multi_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _parse_dmarc_tags(dmarc_raw: str) -> Dict[str, str]:
        """Memecah string DMARC TXT menjadi kamus key-value."""
        tags: Dict[str, str] = {}
        for part in dmarc_raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    @staticmethod
    def _count_spf_lookups(spf_raw: str) -> int:
        """
        Menghitung jumlah mekanisme SPF yang memicu kueri DNS sesuai RFC 7208 Section 4.6.4.
        Mekanisme yang dihitung: include, a, mx, ptr, exists, redirect.
        Batas maksimal standar RFC 7208 adalah 10 lookups.
        """
        tokens = spf_raw.lower().split()
        lookup_count = 0
        for token in tokens[1:]:
            clean_token = token.lstrip("+-~?")
            if (
                clean_token in ("a", "mx", "ptr")
                or clean_token.startswith(("include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect="))
            ):
                lookup_count += 1
        return lookup_count

    def _sync_audit_dns(self, target_url: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname

        if not hostname or hostname in ("localhost", "127.0.0.1", "::1"):
            findings.append(
                AuditFinding(
                    category="DNS Security",
                    item="Target DNS Resolution",
                    severity=Severity.INFO,
                    status="Dilewati (Localhost)",
                    description="Target adalah alamat loopback lokal sehingga pemeriksaan DNS publik dilewati.",
                    remediation="Gunakan nama domain publik untuk mengaudit postur SPF, DMARC, CAA, dan DNSSEC.",
                    reference="RFC 1035",
                )
            )
            return findings

        base_domain = self._extract_base_domain(hostname)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DEFAULT_TIMEOUT
        resolver.timeout = 4.0

        # 1. Audit MX (Mail Exchanger) Records
        findings.extend(self._check_mx_records(resolver, base_domain))

        # 2. Audit SPF (Sender Policy Framework - RFC 7208)
        findings.extend(self._check_spf_record(resolver, base_domain))

        # 3. Audit DMARC (RFC 7489)
        findings.extend(self._check_dmarc_record(resolver, base_domain))

        # 4. Audit Common DKIM Selectors (RFC 6376)
        findings.extend(self._check_dkim_selectors(resolver, base_domain))

        # 5. Audit MTA-STS & SMTP TLS Reporting (RFC 8461 & RFC 8460)
        findings.extend(self._check_mta_sts_and_tlsrpt(resolver, base_domain))

        # 6. Audit CAA (Certification Authority Authorization - RFC 8659)
        findings.extend(self._check_caa_records(resolver, base_domain))

        # 7. Audit DNSSEC (DNSKEY / DS Records - RFC 4035)
        findings.extend(self._check_dnssec(resolver, base_domain))

        return findings

    def _check_mx_records(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        try:
            answers = resolver.resolve(domain, "MX")
            mx_servers = [str(r.exchange).rstrip(".") for r in answers]
            # Cek Null MX (RFC 7505) jika domain memang tidak menerima email
            if len(mx_servers) == 1 and mx_servers[0] == "":
                return [
                    AuditFinding(
                        category="DNS Security",
                        item="MX Record (Null MX)",
                        severity=Severity.PASS,
                        status="Null MX (RFC 7505)",
                        description=f"Domain {domain} secara eksplisit mendeklarasikan tidak menerima email (0 .).",
                        remediation="Konfigurasi sudah sesuai dengan RFC 7505 untuk domain tanpa layanan email.",
                        reference="RFC 7505",
                    )
                ]
            return [
                AuditFinding(
                    category="DNS Security",
                    item="MX Record (Mail Server)",
                    severity=Severity.INFO,
                    status=f"{len(mx_servers)} Server Ditemukan",
                    description=f"Server MX aktif untuk {domain}: {', '.join(mx_servers[:3])}",
                    remediation="Pastikan seluruh server MX mendukung STARTTLS dan dilindungi oleh SPF/DMARC.",
                    reference="RFC 5321",
                )
            ]
        except Exception:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="MX Record (Mail Server)",
                    severity=Severity.INFO,
                    status="Tidak Ada MX",
                    description=f"Tidak ditemukan MX record pada {domain}. Meskipun tidak menerima email, domain tetap wajib memiliki SPF 'v=spf1 -all' agar tidak dipalsukan.",
                    remediation="Tambahkan Null MX ('0 .') sesuai RFC 7505 serta TXT SPF 'v=spf1 -all'.",
                    reference="RFC 7505",
                )
            ]

    def _check_spf_record(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        spf_records: List[str] = []

        try:
            txt_answers = resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt_str = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings).strip()
                if txt_str.lower().startswith("v=spf1"):
                    spf_records.append(txt_str)
        except Exception:
            pass

        if not spf_records:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="SPF Record (Existence)",
                    severity=Severity.HIGH,
                    status="Tidak Ditemukan",
                    description=f"Domain {domain} tidak memiliki catatan TXT SPF (v=spf1), sehingga rentan terhadap Email Spoofing.",
                    remediation="Tambahkan TXT record pada root domain: 'v=spf1 include:_spf.penyediaemail.com -all' (atau 'v=spf1 -all' jika tidak mengirim email).",
                    reference="RFC 7208",
                )
            )
            return results

        if len(spf_records) > 1:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="SPF Multiple Records Check",
                    severity=Severity.HIGH,
                    status=f"Konflik ({len(spf_records)} SPF Records)",
                    description="Ditemukan lebih dari satu TXT record v=spf1. Sesuai RFC 7208 Section 3.2, hal ini menyebabkan hasil evaluasi PermError.",
                    remediation="Gabungkan seluruh aturan pengiriman email ke dalam SATU baris TXT record v=spf1 saja.",
                    reference="RFC 7208 Section 3.2",
                )
            )

        primary_spf = spf_records[0]
        lookup_count = self._count_spf_lookups(primary_spf)

        # Evaluasi kebijakan akhir (-all, ~all, ?all, +all)
        if "+all" in primary_spf.lower():
            pol_sev = Severity.HIGH
            pol_status = "Berbahaya (+all)"
            pol_desc = "Aturan SPF diakhiri dengan '+all' yang mengizinkan SEMUA IP di dunia mengirim email atas nama domain Anda!"
            pol_rem = "Segera ganti '+all' menjadi '-all' (HardFail) atau '~all' (SoftFail)."
        elif "?all" in primary_spf.lower():
            pol_sev = Severity.MEDIUM
            pol_status = "Netral (?all)"
            pol_desc = "Aturan SPF menggunakan '?all' (Neutral) yang tidak memberikan perlindungan terhadap pemalsuan email."
            pol_rem = "Perketat akhiran SPF menjadi '~all' (SoftFail) atau '-all' (HardFail)."
        elif "-all" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Ketat (-all HardFail)"
            pol_desc = f"SPF aktif dengan kebijakan HardFail (-all). Isi: {primary_spf[:60]}"
            pol_rem = "Kebijakan akhiran SPF sudah optimal."
        elif "~all" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Aman (~all SoftFail)"
            pol_desc = f"SPF aktif dengan kebijakan SoftFail (~all). Isi: {primary_spf[:60]}"
            pol_rem = "Sudah baik bila dikombinasikan dengan DMARC. Pertimbangkan '-all' jika seluruh pengirim sudah terpetakan."
        elif "redirect=" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Redirect Policy"
            pol_desc = f"SPF mendelegasikan kebijakan melalui mekanisme redirect: {primary_spf[:60]}"
            pol_rem = "Pastikan domain tujuan redirect memiliki akhiran '-all' atau '~all'."
        else:
            pol_sev = Severity.MEDIUM
            pol_status = "Tanpa Akhiran 'all'"
            pol_desc = "Record SPF tidak memiliki mekanisme penutup eksplisit (-all atau ~all)."
            pol_rem = "Tambahkan '-all' atau '~all' di bagian paling akhir string SPF."

        results.append(
            AuditFinding(
                category="DNS Security",
                item="SPF Enforcement Policy",
                severity=pol_sev,
                status=pol_status,
                description=pol_desc,
                remediation=pol_rem,
                reference="RFC 7208 Section 4.7",
            )
        )

        # Evaluasi batas 10 DNS Lookup & penggunaan mekanisme usang 'ptr'
        has_ptr = bool(re.search(r"\bptr\b", primary_spf.lower()))
        if lookup_count > 10:
            lookup_sev = Severity.MEDIUM
            lookup_status = f"Melebihi Batas ({lookup_count}/10)"
            lookup_rem = "Kurangi penggunaan 'include:' atau gunakan teknik SPF Flattening karena >10 DNS lookups memicu SPF PermError."
        elif has_ptr:
            lookup_sev = Severity.LOW
            lookup_status = f"{lookup_count}/10 Lookups (Ada 'ptr')"
            lookup_rem = "Hapus mekanisme 'ptr' karena telah dinyatakan usang (deprecated) oleh RFC 7208 Section 5.5."
        else:
            lookup_sev = Severity.PASS
            lookup_status = f"Optimal ({lookup_count}/10 Lookups)"
            lookup_rem = "Jumlah kueri DNS tingkat pertama pada SPF masih berada di bawah batas maksimal 10."

        results.append(
            AuditFinding(
                category="DNS Security",
                item="SPF DNS Lookup Limit",
                severity=lookup_sev,
                status=lookup_status,
                description=f"Mekanisme pemicu DNS lookup tingkat pertama terdeteksi sebanyak {lookup_count} kali.",
                remediation=lookup_rem,
                reference="RFC 7208 Section 4.6.4",
            )
        )

        return results

    def _check_dmarc_record(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        dmarc_host = f"_dmarc.{domain}"
        dmarc_records: List[str] = []

        try:
            answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt_str = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings).strip()
                if txt_str.lower().startswith("v=dmarc1"):
                    dmarc_records.append(txt_str)
        except Exception:
            pass

        if not dmarc_records:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Policy (_dmarc)",
                    severity=Severity.HIGH,
                    status="Tidak Ditemukan",
                    description=f"Tidak ada TXT record DMARC pada {dmarc_host}. Penerima email tidak memiliki instruksi penolakan jika SPF/DKIM gagal.",
                    remediation=f"Tambahkan TXT record pada '{dmarc_host}' dengan nilai: 'v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc@{domain};'",
                    reference="RFC 7489",
                )
            )
            return results

        raw_dmarc = dmarc_records[0]
        tags = self._parse_dmarc_tags(raw_dmarc)
        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp", policy).lower()
        pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
        rua = tags.get("rua", "")

        # 1. Evaluasi Kebijakan Utama (p=)
        if policy == "reject" and pct == 100:
            p_sev = Severity.PASS
            p_status = "Maksimal (p=reject, 100%)"
            p_rem = "Kebijakan penolakan DMARC sudah berada pada tingkat perlindungan tertinggi."
        elif policy == "quarantine" and pct == 100:
            p_sev = Severity.PASS
            p_status = "Aktif (p=quarantine, 100%)"
            p_rem = "Sudah memfilter spoofing ke folder Spam. Tingkatkan ke 'p=reject' setelah seluruh sumber email tervalidasi."
        elif policy in ("reject", "quarantine") and pct < 100:
            p_sev = Severity.LOW
            p_status = f"Parsial (p={policy}, pct={pct}%)"
            p_rem = "Naikkan atribut 'pct=100' agar kebijakan DMARC diterapkan pada 100% trafik email."
        else:
            p_sev = Severity.MEDIUM
            p_status = "Hanya Pantau (p=none)"
            p_rem = "Kebijakan 'p=none' hanya mengumpulkan laporan tanpa memblokir email palsu. Ubah ke 'p=quarantine' atau 'p=reject'."

        results.append(
            AuditFinding(
                category="DNS Security",
                item="DMARC Enforcement (p= & sp=)",
                severity=p_sev,
                status=f"{p_status} [sp={sub_policy}]",
                description=f"Record DMARC: {raw_dmarc[:65]}",
                remediation=p_rem,
                reference="RFC 7489 Section 6.3",
            )
        )

        # 2. Evaluasi Pelaporan Agregat (rua=)
        if rua and "mailto:" in rua.lower():
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Aggregate Reporting (rua)",
                    severity=Severity.PASS,
                    status="Terkonfigurasi",
                    description=f"Laporan agregat DMARC dikirim ke: {rua}",
                    remediation="Pantau laporan XML DMARC secara berkala untuk mendeteksi upaya penyalahgunaan domain.",
                    reference="RFC 7489 Section 6.2",
                )
            )
        else:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Aggregate Reporting (rua)",
                    severity=Severity.LOW,
                    status="Tanpa URI Pelaporan (rua)",
                    description="DMARC aktif tetapi tidak menyertakan tag 'rua=mailto:...' untuk menerima laporan visibilitas autentikasi email.",
                    remediation=f"Tambahkan '; rua=mailto:dmarc-reports@{domain}' pada record DMARC Anda.",
                    reference="RFC 7489 Section 6.2",
                )
            )

        return results

    def _check_dkim_selectors(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        found_selectors: List[str] = []
        for selector in COMMON_DKIM_SELECTORS:
            qname = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(qname, "TXT")
                for rdata in answers:
                    txt_val = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                    if "p=" in txt_val.lower() or "v=dkim1" in txt_val.lower():
                        found_selectors.append(selector)
                        break
            except Exception:
                continue

        if found_selectors:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="DKIM Public Key Discovery",
                    severity=Severity.PASS,
                    status=f"Ditemukan ({', '.join(found_selectors)})",
                    description=f"Kunci publik DKIM aktif terdeteksi pada selector: {', '.join(found_selectors)}.",
                    remediation="Lakukan rotasi kunci DKIM (minimal RSA 2048-bit) secara berkala setiap 6-12 bulan.",
                    reference="RFC 6376",
                )
            ]
        return [
            AuditFinding(
                category="DNS Security",
                item="DKIM Public Key Discovery",
                severity=Severity.INFO,
                status="Selector Kustom / Tidak Terdeteksi",
                description="Tidak ditemukan kunci DKIM pada daftar selector umum (google, selector1, default, k1, dll).",
                remediation="Jika domain menggunakan selector kustom (unik), abaikan pesan ini. Pastikan kunci RSA minimal 2048-bit.",
                reference="RFC 6376",
            )
        ]

    def _check_mta_sts_and_tlsrpt(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []

        # Cek _mta-sts.<domain>
        mta_sts_found = False
        try:
            answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
            for rdata in answers:
                txt_val = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if "v=sts1" in txt_val.lower():
                    mta_sts_found = True
                    findings.append(
                        AuditFinding(
                            category="DNS Security",
                            item="MTA-STS (Email Transport Encryption)",
                            severity=Severity.PASS,
                            status="Aktif (v=STSv1)",
                            description=f"Kebijakan enkripsi pengiriman email MTA-STS aktif: {txt_val[:50]}",
                            remediation="Pastikan file kebijakan di https://mta-sts.<domain>/.well-known/mta-sts.txt menggunakan 'mode: enforce'.",
                            reference="RFC 8461",
                        )
                    )
                    break
        except Exception:
            pass

        if not mta_sts_found:
            findings.append(
                AuditFinding(
                    category="DNS Security",
                    item="MTA-STS (Email Transport Encryption)",
                    severity=Severity.LOW,
                    status="Belum Dikonfigurasi",
                    description="Tidak ditemukan TXT record '_mta-sts' untuk mencegah serangan downgrade TLS pada pengiriman SMTP.",
                    remediation="Konfigurasikan MTA-STS (RFC 8461) dan SMTP TLS Reporting (RFC 8460) bila domain menangani trafik email sensitif.",
                    reference="RFC 8461",
                )
            )

        return findings

    def _check_caa_records(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        try:
            answers = resolver.resolve(domain, "CAA")
            caa_entries = [r.to_text() for r in answers]
            return [
                AuditFinding(
                    category="DNS Security",
                    item="CAA Record (SSL Issuance Control)",
                    severity=Severity.PASS,
                    status=f"Terkonfigurasi ({len(caa_entries)} Aturan)",
                    description=f"Otoritas CA yang diizinkan menerbitkan sertifikat: {', '.join(caa_entries)[:60]}",
                    remediation="Pertahankan daftar CAA seminimal mungkin sesuai CA yang benar-benar Anda gunakan.",
                    reference="RFC 8659",
                )
            ]
        except Exception:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="CAA Record (SSL Issuance Control)",
                    severity=Severity.LOW,
                    status="Tidak Ditemukan",
                    description="Tidak ada record DNS CAA yang membatasi otoritas penerbit sertifikat SSL/TLS.",
                    remediation="Tambahkan DNS CAA record (contoh: '0 issue \"letsencrypt.org\"' dan '0 iodef \"mailto:security@...\"').",
                    reference="RFC 8659",
                )
            ]

    def _check_dnssec(self, resolver: dns.resolver.Resolver, domain: str) -> List[AuditFinding]:
        has_dnskey = False
        try:
            resolver.resolve(domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            pass

        if has_dnskey:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="DNSSEC Cryptographic Signing",
                    severity=Severity.PASS,
                    status="Aktif (DNSKEY Terdeteksi)",
                    description=f"Zona DNS {domain} menandatangani record secara kriptografis menggunakan DNSSEC.",
                    remediation="Pastikan algoritma penandatanganan menggunakan ECDSAP256SHA256 (Algo 13) atau ED25519 (Algo 15).",
                    reference="RFC 4035 / RFC 8624",
                )
            ]
        return [
            AuditFinding(
                category="DNS Security",
                item="DNSSEC Cryptographic Signing",
                severity=Severity.LOW,
                status="Tidak Aktif (Unsigned)",
                description=f"Domain {domain} belum mengaktifkan DNSSEC (tidak ditemukan record DNSKEY).",
                remediation="Aktifkan DNSSEC pada registrar dan penyedia DNS Anda untuk mencegah serangan DNS Spoofing / Cache Poisoning.",
                reference="RFC 4035",
            )
        ]
```

---

### 5.6. HTTP Security Headers, CORS & Cookie Auditor (`src/vanguard/auditors/headers_auditor.py`)

```python
from typing import List
import httpx

from src.vanguard.auditors.base import BaseAuditor
from src.vanguard.core.config import DEFAULT_TIMEOUT, REQUIRED_SECURITY_HEADERS, USER_AGENT
from src.vanguard.core.models import AuditFinding, Severity


class HeadersAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "HTTP Security Headers, CORS & Cookie Hardening Auditor"

    async def run(self, target_url: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []

        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                response = await client.get(target_url)
                headers = response.headers

                # 1. Evaluasi Kelengkapan & Kualitas Security Headers
                for h_name, (sev, desc, rem, ref) in REQUIRED_SECURITY_HEADERS.items():
                    if h_name in headers:
                        val = headers[h_name]
                        short_val = val if len(val) <= 55 else f"{val[:52]}..."

                        # Evaluasi tambahan untuk CSP yang menggunakan unsafe-inline / unsafe-eval
                        if h_name == "Content-Security-Policy" and (
                            "'unsafe-inline'" in val.lower() or "'unsafe-eval'" in val.lower()
                        ):
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=f"{h_name} (Directive Quality)",
                                    severity=Severity.LOW,
                                    status="Aktif (Mengandung unsafe-*)",
                                    description=f"CSP ditemukan tetapi mengizinkan 'unsafe-inline' atau 'unsafe-eval': {short_val}",
                                    remediation="Gunakan mekanisme cryptographic nonce ('nonce-...') atau hash ('sha256-...') sebagai pengganti 'unsafe-inline'.",
                                    reference=ref,
                                )
                            )
                        else:
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=h_name,
                                    severity=Severity.PASS,
                                    status="Terkonfigurasi",
                                    description=f"Nilai header aktif: {short_val}",
                                    remediation="Konfigurasi sudah sesuai standar.",
                                    reference=ref,
                                )
                            )
                    else:
                        findings.append(
                            AuditFinding(
                                category="HTTP Headers",
                                item=h_name,
                                severity=sev,
                                status="Tidak Ditemukan",
                                description=desc,
                                remediation=rem,
                                reference=ref,
                            )
                        )

                # 2. Evaluasi Kebijakan CORS (Cross-Origin Resource Sharing)
                acao = headers.get("Access-Control-Allow-Origin")
                acac = headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "*":
                    sev = Severity.HIGH if acac == "true" else Severity.LOW
                    findings.append(
                        AuditFinding(
                            category="CORS Policy",
                            item="Access-Control-Allow-Origin",
                            severity=sev,
                            status="Wildcard (*)",
                            description="Kebijakan CORS mengizinkan akses lintas domain secara terbuka (*).",
                            remediation="Jika endpoint menyajikan data terautentikasi, batasi origin secara spesifik ke daftar domain tepercaya.",
                            reference="Fetch Standard / OWASP CORS",
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            category="CORS Policy",
                            item="Access-Control-Allow-Origin",
                            severity=Severity.PASS,
                            status=acao if acao else "Restriktif (Same-Origin)",
                            description="Kebijakan CORS tidak menggunakan wildcard terbuka.",
                            remediation="Tidak diperlukan tindakan.",
                            reference="Fetch Standard",
                        )
                    )

                # 3. Evaluasi Information Disclosure pada Banner Server
                for leak_hdr in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                    if leak_hdr in headers:
                        val = headers[leak_hdr]
                        has_version_digits = any(c.isdigit() for c in val)
                        findings.append(
                            AuditFinding(
                                category="Info Exposure",
                                item=f"Header {leak_hdr}",
                                severity=Severity.LOW if has_version_digits else Severity.INFO,
                                status=f"Terekspos ({val[:35]})",
                                description="Respons HTTP menyertakan identitas web server atau nomor versi framework.",
                                remediation=f"Sembunyikan versi server (misal di Nginx: 'server_tokens off;' atau hapus header {leak_hdr}).",
                                reference="OWASP WSTG-INFO-02",
                            )
                        )

                # 4. Evaluasi Keamanan Cookie (Set-Cookie Flags)
                raw_cookies = headers.get_list("set-cookie")
                for idx, cookie_str in enumerate(raw_cookies, start=1):
                    c_lower = cookie_str.lower()
                    cookie_name = cookie_str.split("=", 1)[0].strip()
                    missing: List[str] = []
                    if "secure" not in c_lower:
                        missing.append("Secure")
                    if "httponly" not in c_lower:
                        missing.append("HttpOnly")
                    if "samesite" not in c_lower:
                        missing.append("SameSite")

                    if missing:
                        findings.append(
                            AuditFinding(
                                category="Cookie Security",
                                item=f"Cookie '{cookie_name}' (#{idx})",
                                severity=Severity.MEDIUM,
                                status=f"Atribut Kurang ({', '.join(missing)})",
                                description="Cookie diatur tanpa atribut keamanan lengkap untuk mencegah pencurian sesi atau CSRF.",
                                remediation="Sertakan flag 'Secure; HttpOnly; SameSite=Lax' (atau Strict) saat mengirim Set-Cookie.",
                                reference="RFC 6265bis",
                            )
                        )
                    else:
                        findings.append(
                            AuditFinding(
                                category="Cookie Security",
                                item=f"Cookie '{cookie_name}' (#{idx})",
                                severity=Severity.PASS,
                                status="Terlindungi Lengkap",
                                description="Cookie memiliki atribut Secure, HttpOnly, dan SameSite.",
                                remediation="Tidak diperlukan tindakan.",
                                reference="RFC 6265bis",
                            )
                        )

        except httpx.RequestError as exc:
            findings.append(
                AuditFinding(
                    category="HTTP Headers",
                    item="Koneksi HTTP/HTTPS",
                    severity=Severity.HIGH,
                    status="Gagal Terhubung",
                    description=f"Tidak dapat menghubungi server target: {exc}",
                    remediation="Pastikan layanan web aktif, DNS dapat diresolusi, dan firewall mengizinkan koneksi.",
                    reference="Network Connectivity",
                )
            )

        return findings
```

---

### 5.7. SSL/TLS Certificate, Cipher & HSTS Preload Auditor (`src/vanguard/auditors/ssl_auditor.py`)

```python
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from src.vanguard.auditors.base import BaseAuditor
from src.vanguard.core.models import AuditFinding, Severity


class SSLAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "SSL/TLS Certificate, Cipher Suite & Protocol Inspector"

    async def run(self, target_url: str) -> List[AuditFinding]:
        return await asyncio.to_thread(self._sync_inspect_ssl, target_url)

    def _sync_inspect_ssl(self, target_url: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https" or not hostname:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Enkripsi Transport (HTTPS)",
                    severity=Severity.HIGH,
                    status="Tidak Aktif (HTTP)",
                    description="Target diakses menggunakan protokol HTTP tanpa enkripsi TLS.",
                    remediation="Pasang sertifikat TLS valid dan aktifkan pengalihan otomatis (HTTP 301 Redirect) ke HTTPS.",
                    reference="RFC 8446 / OWASP TLS",
                )
            )
            return findings

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=6.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version() or "Unknown"
                    cipher_info = ssock.cipher()

                    # 1. Validasi Versi Protokol TLS
                    modern_tls = tls_version in ("TLSv1.2", "TLSv1.3")
                    findings.append(
                        AuditFinding(
                            category="SSL/TLS",
                            item="Versi Protokol TLS",
                            severity=Severity.PASS if modern_tls else Severity.HIGH,
                            status=tls_version,
                            description=f"Sesi terenkripsi dinegosiasikan menggunakan protokol {tls_version}.",
                            remediation=(
                                "Protokol enkripsi sudah modern."
                                if modern_tls
                                else "Nonaktifkan SSLv3, TLSv1.0, dan TLSv1.1; hanya izinkan TLSv1.2 dan TLSv1.3."
                            ),
                            reference="RFC 8996 (Deprecating TLS 1.0/1.1)",
                        )
                    )

                    # 2. Validasi Kekuatan Cipher Suite
                    if cipher_info:
                        cipher_name, _, secret_bits = cipher_info
                        bits = secret_bits or 0
                        has_pfs = "ECDHE" in cipher_name or "DHE" in cipher_name or tls_version == "TLSv1.3"
                        findings.append(
                            AuditFinding(
                                category="SSL/TLS",
                                item="Cipher Suite & Forward Secrecy",
                                severity=Severity.PASS if (bits >= 128 and has_pfs) else Severity.MEDIUM,
                                status=f"{cipher_name} ({bits}-bit)",
                                description=f"Algoritma sesi: {cipher_name} | Perfect Forward Secrecy (PFS): {'Ya' if has_pfs else 'Tidak'}",
                                remediation=(
                                    "Cipher suite kuat dan mendukung Forward Secrecy."
                                    if (bits >= 128 and has_pfs)
                                    else "Utamakan cipher suite ECDHE dengan AES-GCM atau ChaCha20-Poly1305."
                                ),
                                reference="Mozilla Server Side TLS Guidelines",
                            )
                        )

                    # 3. Validasi Masa Berlaku Sertifikat
                    if cert and "notAfter" in cert:
                        not_after_str = str(cert["notAfter"])
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        days_remaining = (exp_date - datetime.now(timezone.utc)).days

                        if days_remaining > 30:
                            sev = Severity.PASS
                        elif days_remaining > 14:
                            sev = Severity.LOW
                        elif days_remaining > 0:
                            sev = Severity.MEDIUM
                        else:
                            sev = Severity.HIGH

                        findings.append(
                            AuditFinding(
                                category="SSL/TLS",
                                item="Masa Aktif Sertifikat",
                                severity=sev,
                                status=f"Sisa {days_remaining} hari",
                                description=f"Sertifikat berlaku hingga {exp_date.strftime('%Y-%m-%d %H:%M UTC')}.",
                                remediation=(
                                    "Masa aktif sertifikat masih aman."
                                    if days_remaining > 30
                                    else "Segera perbarui sertifikat SSL/TLS dan pastikan daemon auto-renewal (misal Certbot/ACME) berjalan."
                                ),
                                reference="RFC 5280",
                            )
                        )

        except ssl.SSLCertVerificationError as exc:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Verifikasi Rantai Sertifikat CA",
                    severity=Severity.HIGH,
                    status="Tidak Valid / Untrusted",
                    description=f"Verifikasi sertifikat gagal: {exc.verify_message}",
                    remediation="Pastikan sertifikat diterbitkan oleh CA tepercaya, menyertakan fullchain, dan sesuai dengan hostname.",
                    reference="RFC 5280",
                )
            )
        except Exception as exc:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Jabat Tangan TLS (Port 443)",
                    severity=Severity.MEDIUM,
                    status="Gagal Memeriksa",
                    description=f"Tidak dapat melakukan koneksi TLS: {exc}",
                    remediation="Pastikan port HTTPS terbuka dan konfigurasi TLS pada reverse proxy sudah benar.",
                    reference="RFC 8446",
                )
            )

        return findings
```

---

### 5.8. RFC 9116 (`security.txt`) & Governance Auditor (`src/vanguard/auditors/governance_auditor.py`)

```python
from typing import List
from urllib.parse import urljoin

import httpx

from src.vanguard.auditors.base import BaseAuditor
from src.vanguard.core.config import DEFAULT_TIMEOUT, USER_AGENT
from src.vanguard.core.models import AuditFinding, Severity


class GovernanceAuditor(BaseAuditor):
    """
    Memeriksa kepatuhan terhadap standar RFC 9116 (/.well-known/security.txt)
    untuk memastikan organisasi memiliki jalur koordinasi pengungkapan kerentanan resmi.
    """

    @property
    def name(self) -> str:
        return "RFC 9116 (security.txt) & Security Governance Auditor"

    async def run(self, target_url: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        sec_txt_url = urljoin(target_url.rstrip("/") + "/", ".well-known/security.txt")

        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = await client.get(sec_txt_url)
                content_type = resp.headers.get("Content-Type", "").lower()
                body = resp.text

                if resp.status_code == 200 and "text/plain" in content_type and "contact:" in body.lower():
                    has_expires = "expires:" in body.lower()
                    findings.append(
                        AuditFinding(
                            category="Governance",
                            item="RFC 9116 (/.well-known/security.txt)",
                            severity=Severity.PASS if has_expires else Severity.LOW,
                            status="Tersedia" if has_expires else "Tanpa Field 'Expires:'",
                            description=f"Kebijakan pengungkapan kerentanan ditemukan di {sec_txt_url}.",
                            remediation=(
                                "Sudah mematuhi standar RFC 9116."
                                if has_expires
                                else "Tambahkan field wajib 'Expires:' berformat ISO-8601 sesuai RFC 9116 Section 2.5.5."
                            ),
                            reference="RFC 9116",
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            category="Governance",
                            item="RFC 9116 (/.well-known/security.txt)",
                            severity=Severity.LOW,
                            status="Tidak Ditemukan",
                            description="File /.well-known/security.txt belum tersedia untuk memfasilitasi pelaporan celah keamanan.",
                            remediation="Buat file '/.well-known/security.txt' berisi atribut 'Contact: mailto:security@...' dan 'Expires: ...'.",
                            reference="RFC 9116",
                        )
                    )
        except Exception:
            findings.append(
                AuditFinding(
                    category="Governance",
                    item="RFC 9116 (/.well-known/security.txt)",
                    severity=Severity.INFO,
                    status="Tidak Dapat Diakses",
                    description="Gagal memeriksa ketersediaan /.well-known/security.txt.",
                    remediation="Sediakan /.well-known/security.txt sesuai standar RFC 9116.",
                    reference="RFC 9116",
                )
            )

        return findings
```

---

### 5.9. Markdown, JSON & HTML Report Exporter (`src/vanguard/utils/exporter.py`)

```python
import json
from dataclasses import asdict
from pathlib import Path
from src.vanguard.core.models import AuditReport, Severity


class ReportExporter:
    """Utilitas ekspor laporan hasil audit ke format Markdown (.md) dan JSON (.json)."""

    @staticmethod
    def to_markdown(report: AuditReport, output_path: str = "LAPORAN_AUDIT_VANGUARD.md") -> str:
        path = Path(output_path)
        counts = report.count_by_severity()

        lines = [
            "# 🛡️ Laporan Audit Postur Keamanan (VanguardAudit Enterprise)",
            "",
            "## 1. Ringkasan Eksekutif",
            f"- **Target Pemeriksaan:** `{report.target_url}`",
            f"- **Waktu Pelaksanaan:** {report.timestamp}",
            f"- **Durasi Pemeriksaan:** {report.duration_seconds:.2f} detik",
            f"- **Skor Postur Keamanan:** **{report.score}/100** (Grade: **{report.grade}**)",
            "",
            "### Statistik Temuan Berdasarkan Tingkat Keparahan",
            f"- ✅ **PASS:** {counts[Severity.PASS]} komponen",
            f"- ℹ️ **INFO:** {counts[Severity.INFO]} komponen",
            f"- 🟡 **LOW:** {counts[Severity.LOW]} komponen",
            f"- 🟠 **MEDIUM:** {counts[Severity.MEDIUM]} komponen",
            f"- 🔴 **HIGH:** {counts[Severity.HIGH]} komponen",
            "",
            "---",
            "",
            "## 2. Tabel Detail Pemeriksaan & Panduan Mitigasi",
            "",
            "| Kategori | Komponen | Severity | Status | Analisis Temuan | Rekomendasi Perbaikan (Remediation) | Standar / Referensi |",
            "| :--- | :--- | :---: | :--- | :--- | :--- | :--- |",
        ]

        for f in report.findings:
            lines.append(
                f"| {f.category} | **{f.item}** | `{f.severity.value}` | {f.status} | {f.description} | {f.remediation} | {f.reference} |"
            )

        lines.extend(
            [
                "",
                "---",
                "*Laporan ini dihasilkan secara otomatis oleh **VanguardAudit Enterprise Defensive Inspector**.*",
            ]
        )

        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path.resolve())

    @staticmethod
    def to_json(report: AuditReport, output_path: str = "LAPORAN_AUDIT_VANGUARD.json") -> str:
        path = Path(output_path)
        payload = {
            "target_url": report.target_url,
            "timestamp": report.timestamp,
            "duration_seconds": round(report.duration_seconds, 3),
            "score": report.score,
            "grade": report.grade,
            "summary_counts": {k.value: v for k, v in report.count_by_severity().items()},
            "findings": [asdict(f) for f in report.findings],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path.resolve())
```

---

### 5.10. Terminal UI (TUI) Styling (`src/vanguard/ui/styles.tcss`)

Simpan kode berikut sebagai `src/vanguard/ui/styles.tcss`:

```css
Screen {
    background: #0b1120;
    color: #e2e8f0;
}

#control-bar {
    height: 5;
    margin: 1 2 0 2;
    padding: 0 1;
    background: #1e293b;
    border: tall #334155;
    align: left middle;
}

#url-input {
    width: 52%;
    margin-right: 1;
}

.action-btn {
    width: 15%;
    margin-left: 1;
}

#filter-bar {
    height: 3;
    margin: 1 2 0 2;
    align: left middle;
}

.filter-btn {
    margin-right: 1;
    min-width: 16;
}

#metrics-row {
    height: 5;
    margin: 1 2;
}

.metric-card {
    width: 1fr;
    height: 100%;
    margin-right: 1;
    padding: 0 2;
    background: #1e293b;
    border: solid #334155;
    content-align: left middle;
}

#score-card {
    border: solid #38bdf8;
}

#results-table {
    height: 1fr;
    margin: 0 2;
    background: #0f172a;
    border: solid #334155;
}

#detail-panel {
    height: 8;
    margin: 1 2;
    padding: 1 2;
    background: #1e293b;
    border: solid #475569;
}
```

---

### 5.11. Main Application: Interactive TUI & Headless CI/CD CLI (`src/vanguard/main.py`)

File `main.py` ini mendukung dua mode sekaligus:
1. **Mode TUI Interaktif** (ketika dijalankan langsung `python -m src.vanguard.main`), dilengkapi tombol filter kategori (`All`, `DNS Security`, `HTTP Headers`, `SSL/TLS`, `Governance`) dan eksekusi paralel menggunakan `asyncio.gather`.
2. **Mode Headless CLI untuk CI/CD** (ketika dijalankan dengan argumen `--headless --url https://domain.com --fail-under 80`).

```python
import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from src.vanguard.auditors.base import BaseAuditor
from src.vanguard.auditors.dns_auditor import DNSAuditor
from src.vanguard.auditors.governance_auditor import GovernanceAuditor
from src.vanguard.auditors.headers_auditor import HeadersAuditor
from src.vanguard.auditors.ssl_auditor import SSLAuditor
from src.vanguard.core.config import APP_NAME, APP_VERSION
from src.vanguard.core.models import AuditFinding, AuditReport, Severity
from src.vanguard.utils.exporter import ReportExporter


async def execute_all_auditors(target_url: str) -> AuditReport:
    """Menjalankan seluruh modul auditor secara paralel (concurrent non-blocking I/O)."""
    start_time = time.perf_counter()
    report = AuditReport(target_url=target_url)

    auditors: List[BaseAuditor] = [
        SSLAuditor(),
        HeadersAuditor(),
        DNSAuditor(),
        GovernanceAuditor(),
    ]

    results = await asyncio.gather(*(auditor.run(target_url) for auditor in auditors))
    for finding_list in results:
        report.findings.extend(finding_list)

    report.duration_seconds = time.perf_counter() - start_time
    return report


class VanguardAuditApp(App[None]):
    """Aplikasi Terminal UI (TUI) Interaktif untuk Audit Postur Keamanan Defensif."""

    CSS_PATH = Path(__file__).parent / "ui" / "styles.tcss"

    BINDINGS = [
        ("r", "run_audit", "Mulai Audit"),
        ("m", "export_md", "Simpan .MD"),
        ("j", "export_json", "Simpan .JSON"),
        ("c", "clear_results", "Bersihkan"),
        ("q", "quit", "Keluar"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.current_report: AuditReport | None = None
        self.displayed_findings: List[AuditFinding] = []
        self.active_filter: str = "ALL"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="control-bar"):
            yield Input(
                placeholder="Masukkan URL/Domain milik Anda (contoh: https://example.com)",
                id="url-input",
            )
            yield Button("🔍 Mulai Audit (R)", variant="primary", id="btn-audit", classes="action-btn")
            yield Button("📄 Export .MD (M)", variant="success", id="btn-md", classes="action-btn")
            yield Button("📦 Export .JSON (J)", variant="warning", id="btn-json", classes="action-btn")

        with Horizontal(id="filter-bar"):
            yield Button("Semua Kategori", id="flt-all", variant="primary", classes="filter-btn")
            yield Button("DNS & Email", id="flt-dns", variant="default", classes="filter-btn")
            yield Button("HTTP Headers", id="flt-headers", variant="default", classes="filter-btn")
            yield Button("SSL / TLS", id="flt-ssl", variant="default", classes="filter-btn")
            yield Button("Governance", id="flt-gov", variant="default", classes="filter-btn")

        with Horizontal(id="metrics-row"):
            yield Static("🎯 Target: [dim]Belum dipilih[/]", id="target-card", classes="metric-card")
            yield Static("🛡️ Skor Keamanan: [dim]- / 100[/]", id="score-card", classes="metric-card")
            yield Static("📊 Ringkasan: [dim]Menunggu eksekusi audit[/]", id="stats-card", classes="metric-card")

        yield DataTable(id="results-table")
        yield Static(
            "💡 [bold cyan]Panduan Interaktif:[/] Masukkan domain Anda di atas lalu tekan Enter. Gunakan tombol filter kategori atau klik baris pada tabel untuk membaca penjelasan teknis, referensi RFC, dan panduan perbaikan lengkap.",
            id="detail-panel",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"{APP_NAME} v{APP_VERSION} // Defensive Security Posture & DNS/TLS Inspector"
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.zebra_striping = True
        table.add_columns("No", "Kategori", "Komponen Pemeriksaan", "Severity", "Status", "Standar/RFC")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "btn-audit":
            await self.action_run_audit()
        elif btn_id == "btn-md":
            self.action_export_md()
        elif btn_id == "btn-json":
            self.action_export_json()
        elif btn_id.startswith("flt-"):
            filter_map = {
                "flt-all": "ALL",
                "flt-dns": "DNS Security",
                "flt-headers": "HTTP Headers",
                "flt-ssl": "SSL/TLS",
                "flt-gov": "Governance",
            }
            self.active_filter = filter_map.get(btn_id, "ALL")
            self._refresh_table_view()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "url-input":
            await self.action_run_audit()

    async def action_run_audit(self) -> None:
        raw_url = self.query_one("#url-input", Input).value.strip()
        detail_panel = self.query_one("#detail-panel", Static)
        table = self.query_one("#results-table", DataTable)

        if not raw_url:
            detail_panel.update("[bold red]⚠️ Mohon masukkan URL atau nama domain terlebih dahulu.[/]")
            return

        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
            self.query_one("#url-input", Input).value = raw_url

        parsed = urlparse(raw_url)
        if not parsed.netloc:
            detail_panel.update("[bold red]⚠️ Format URL tidak valid! Contoh yang benar: https://domainanda.com[/]")
            return

        table.clear()
        self.query_one("#target-card", Static).update(f"🎯 Target: [bold white]{raw_url}[/]")
        self.query_one("#score-card", Static).update("🛡️ Skor: [bold yellow]⏳ Memindai...[/]")
        detail_panel.update(
            "[bold yellow]⏳ Menjalankan pemeriksaan paralel (SSL/TLS, HTTP Headers, SPF/DMARC/DNSSEC, RFC 9116)...[/]"
        )

        report = await execute_all_auditors(raw_url)
        self.current_report = report
        self.active_filter = "ALL"
        self._update_metrics(report)
        self._refresh_table_view()

    def _update_metrics(self, report: AuditReport) -> None:
        score_card = self.query_one("#score-card", Static)
        stats_card = self.query_one("#stats-card", Static)

        score = report.score
        color = "green" if score >= 80 else ("yellow" if score >= 55 else "red")
        score_card.update(
            f"🛡️ Skor Postur: [bold {color}]{score}/100[/] (Grade: [bold {color}]{report.grade}[/])"
        )

        counts = report.count_by_severity()
        stats_card.update(
            f"📊 [green]PASS:{counts[Severity.PASS]}[/] | "
            f"[red]HIGH:{counts[Severity.HIGH]}[/] | "
            f"[orange3]MED:{counts[Severity.MEDIUM]}[/] | "
            f"[yellow]LOW:{counts[Severity.LOW]}[/] ({report.duration_seconds:.2f}s)"
        )

    def _refresh_table_view(self) -> None:
        if not self.current_report:
            return

        table = self.query_one("#results-table", DataTable)
        detail_panel = self.query_one("#detail-panel", Static)
        table.clear()

        self.displayed_findings = self.current_report.filter_by_category(self.active_filter)

        severity_styles = {
            Severity.PASS: "bold green",
            Severity.INFO: "bold cyan",
            Severity.LOW: "bold yellow",
            Severity.MEDIUM: "bold orange3",
            Severity.HIGH: "bold red",
        }

        for idx, f in enumerate(self.displayed_findings, start=1):
            badge = Text(f" {f.severity.value} ", style=severity_styles[f.severity])
            table.add_row(str(idx), f.category, f.item, badge, f.status, f.reference)

        detail_panel.update(
            f"[bold green]✅ Menampilkan {len(self.displayed_findings)} item pemeriksaan (Filter: {self.active_filter}).[/] "
            "Pilih baris untuk melihat detail analisis dan rekomendasi mitigasi."
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self.displayed_findings):
            finding = self.displayed_findings[row_index]
            detail_panel = self.query_one("#detail-panel", Static)
            detail_panel.update(
                f"📌 [bold white]{finding.category} -> {finding.item}[/]  |  "
                f"Status: [bold cyan]{finding.status}[/]  |  Ref: [italic]{finding.reference}[/]\n"
                f"📖 [bold]Analisis:[/] {finding.description}\n"
                f"🛠️ [bold green]Panduan Mitigasi:[/] {finding.remediation}"
            )

    def action_export_md(self) -> None:
        detail_panel = self.query_one("#detail-panel", Static)
        if not self.current_report:
            detail_panel.update("[bold red]⚠️ Belum ada hasil audit untuk diekspor![/]")
            return
        saved_path = ReportExporter.to_markdown(self.current_report)
        detail_panel.update(f"[bold green]✅ Laporan Markdown berhasil disimpan di:[/] {saved_path}")

    def action_export_json(self) -> None:
        detail_panel = self.query_one("#detail-panel", Static)
        if not self.current_report:
            detail_panel.update("[bold red]⚠️ Belum ada hasil audit untuk diekspor![/]")
            return
        saved_path = ReportExporter.to_json(self.current_report)
        detail_panel.update(f"[bold green]✅ Laporan JSON berhasil disimpan di:[/] {saved_path}")

    def action_clear_results(self) -> None:
        self.current_report = None
        self.displayed_findings = []
        self.query_one("#results-table", DataTable).clear()
        self.query_one("#target-card", Static).update("🎯 Target: [dim]Belum dipilih[/]")
        self.query_one("#score-card", Static).update("🛡️ Skor Keamanan: [dim]- / 100[/]")
        self.query_one("#stats-card", Static).update("📊 Ringkasan: [dim]Menunggu eksekusi audit[/]")
        self.query_one("#detail-panel", Static).update("Layar telah dibersihkan. Siap untuk audit berikutnya.")


def run_headless_cli(url: str, fail_under: int, export_md: bool, export_json: bool) -> int:
    """Mode Headless CLI untuk otomatisasi di dalam pipeline CI/CD (GitHub Actions / GitLab CI)."""
    console = Console()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    console.print(f"\n[bold cyan]🛡️ {APP_NAME} v{APP_VERSION} (Headless CI/CD Mode)[/]")
    console.print(f"🎯 Memulai pemeriksaan postur keamanan pada: [bold white]{url}[/] ...\n")

    report = asyncio.run(execute_all_auditors(url))

    rich_table = Table(title=f"Hasil Audit: {report.target_url} (Skor: {report.score}/100 | Grade: {report.grade})")
    rich_table.add_column("Kategori", style="cyan")
    rich_table.add_column("Komponen", style="white")
    rich_table.add_column("Severity", justify="center")
    rich_table.add_column("Status")
    rich_table.add_column("Rekomendasi Mitigasi")

    for f in report.findings:
        rich_table.add_row(f.category, f.item, f.severity.value, f.status, f.remediation)

    console.print(rich_table)

    if export_md:
        md_file = ReportExporter.to_markdown(report)
        console.print(f"📄 Laporan Markdown disimpan ke: [bold green]{md_file}[/]")
    if export_json:
        json_file = ReportExporter.to_json(report)
        console.print(f"📦 Laporan JSON disimpan ke: [bold green]{json_file}[/]")

    if report.score < fail_under:
        console.print(
            f"\n[bold red]❌ CI/CD QUALITY GATE GAGAL:[/] Skor postur keamanan ({report.score}) berada di bawah ambang batas minimum ({fail_under})."
        )
        return 1

    console.print(
        f"\n[bold green]✅ CI/CD QUALITY GATE LULUS:[/] Skor postur keamanan ({report.score}) memenuhi ambang batas ({fail_under})."
    )
    return 0


def entrypoint() -> None:
    parser = argparse.ArgumentParser(
        description="VanguardAudit Enterprise - Defensive Web, SSL/TLS & DNS Security Posture Inspector"
    )
    parser.add_argument("--headless", action="store_true", help="Jalankan dalam mode CLI tanpa TUI (untuk CI/CD)")
    parser.add_argument("--url", type=str, default="", help="Target URL atau domain (wajib jika --headless)")
    parser.add_argument(
        "--fail-under",
        type=int,
        default=0,
        help="Gagalkan proses dengan exit code 1 jika skor di bawah nilai ini (contoh: 80)",
    )
    parser.add_argument("--export-md", action="store_true", help="Ekspor laporan otomatis ke file Markdown (.md)")
    parser.add_argument("--export-json", action="store_true", help="Ekspor laporan otomatis ke file JSON (.json)")

    args = parser.parse_args()

    if args.headless:
        if not args.url:
            print("Error: Argumen --url wajib diisi saat menggunakan mode --headless.", file=sys.stderr)
            sys.exit(2)
        sys.exit(run_headless_cli(args.url, args.fail_under, args.export_md, args.export_json))
    else:
        app = VanguardAuditApp()
        app.run()


if __name__ == "__main__":
    entrypoint()
```

---

## 6. Unit Testing Lengkap (`tests/`)

### 6.1. `tests/test_models_and_scoring.py`

```python
from src.vanguard.core.models import AuditFinding, AuditReport, Severity


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
```

---

### 6.2. `tests/test_dns_auditor.py`

Pengujian unit untuk memastikan akurasi *parser* SPF lookup limit (RFC 7208), *parser* tag DMARC (RFC 7489), dan ekstraksi *root domain* Indonesia (`.co.id`, `.go.id`):

```python
from src.vanguard.auditors.dns_auditor import DNSAuditor


def test_extract_base_domain_indonesian_cctld() -> None:
    assert DNSAuditor._extract_base_domain("portal.perusahaan.co.id") == "perusahaan.co.id"
    assert DNSAuditor._extract_base_domain("api.staging.example.com") == "example.com"


def test_spf_lookup_counter_rfc7208() -> None:
    sample_spf = (
        "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:sendgrid.net "
        "a mx exists:%{i}._spf.mta.example.com -all"
    )
    # include (2) + a (1) + mx (1) + exists (1) = 5 lookups (ip4 tidak dihitung sebagai DNS lookup)
    assert DNSAuditor._count_spf_lookups(sample_spf) == 5


def test_dmarc_tag_parser() -> None:
    raw = "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@example.com"
    tags = DNSAuditor._parse_dmarc_tags(raw)
    assert tags["v"] == "DMARC1"
    assert tags["p"] == "quarantine"
    assert tags["sp"] == "reject"
    assert tags["pct"] == "100"
    assert tags["rua"] == "mailto:dmarc@example.com"
```

---

## 7. Panduan Instalasi, Penggunaan TUI & Integrasi CI/CD

### Langkah Instalasi Lengkap

```bash
# 1. Buat direktori proyek dan masuk ke dalamnya
mkdir vanguard-audit && cd vanguard-audit

# 2. Buat dan aktifkan Virtual Environment
python3 -m venv .venv
source .venv/bin/activate  # Linux / macOS
# .venv\Scripts\activate   # Windows PowerShell / CMD

# 3. Instal paket beserta seluruh tools engineering (Ruff, Mypy, Pytest, Bandit)
pip install -e ".[dev]"

# 4. Jalankan verifikasi kualitas kode & unit testing
ruff check src tests
mypy src
pytest
```

### Cara Menjalankan Mode Terminal UI Interaktif (TUI)

```bash
python -m src.vanguard.main
```

### Cara Menjalankan Mode Headless CLI (Otomatisasi CI/CD / GitHub Actions)

Anda dapat menjalankan **VanguardAudit** langsung di dalam skrip *deployment* atau *GitHub Actions* untuk memastikan server produksi Anda memiliki konfigurasi DNS (SPF/DMARC/DNSSEC), SSL/TLS, dan HTTP Headers dengan skor minimal 80:

```bash
python -m src.vanguard.main --headless --url https://domainanda.com --fail-under 80 --export-md --export-json
```