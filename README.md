# 🛡️ VanguardAudit Enterprise

**Defensive Security Posture & Compliance Inspector**
*Enterprise Terminal UI (TUI) & Headless CI/CD Security Gate*

---

## 📌 Ikhtisar

**VanguardAudit Enterprise** adalah platform audit keamanan defensif modern (*Security Hardening, Configuration Auditing, & Compliance Assessment*) berbasis Python. Aplikasi ini membantu *Software Engineer*, *DevSecOps*, dan *System Administrator* menginspeksi konfigurasi keamanan aplikasi web, SSL/TLS, header HTTP, dan catatan DNS sebelum maupun sesudah rilis produksi.

Aplikasi ini mendukung **Dual-Mode Execution**:
1. **Interactive Terminal UI (TUI):** Dibangun dengan framework [Textual](https://textual.textualize.io/) dan Rich styling untuk inspeksi visual interaktif, filtering kategori, serta visualisasi metrik & mitigasi.
2. **Headless CI/CD CLI:** Mode non-interaktif berkecepatan tinggi yang dapat diintegrasikan ke dalam pipeline CI/CD (GitHub Actions, GitLab CI) dengan toleransi batas skor minimal (`--fail-under <skor>`).

---

## 🔍 Kemampuan Audit Defensif

1. **Deep DNS & Email Security (`dns_auditor.py`)**:
   - **SPF (Sender Policy Framework):** Analisis RFC 7208, validasi mekanisme penutup (`-all`, `~all`, `?all`, `+all`), serta penghitungan mekanisme DNS lookup (maksimal 10 lookup).
   - **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Analisis RFC 7489, pembacaan tag `p=`, `sp=`, `pct=`, `rua=`, `ruf=`.
   - **DKIM Discovery:** Non-intrusive selector discovery (`default`, `google`, `selector1`, `k1`, dll.).
   - **MTA-STS & SMTP TLS Reporting:** RFC 8461 & RFC 8460 untuk enkripsi email server-to-server.
   - **CAA (Certification Authority Authorization):** RFC 8659 pembatasan penerbit sertifikat.
   - **DNSSEC Validation:** Validasi integritas record kriptografi `DNSKEY` dan `DS`.

2. **HTTP Security Headers & Cookies (`headers_auditor.py`)**:
   - `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP.
   - CORS misconfiguration audit (`Access-Control-Allow-Origin: *`).
   - Server & technology information disclosure (`Server`, `X-Powered-By`).
   - Cookie flags security: `Secure`, `HttpOnly`, `SameSite`.

3. **SSL/TLS & Cryptography Posture (`ssl_auditor.py`)**:
   - Protokol handshake modern (`TLSv1.2`, `TLSv1.3`).
   - Kekuatan Cipher Suite (>= 128-bit) dan algoritma enkripsi.
   - Validitas sertifikat CA, validasi SAN (Subject Alternative Names), dan perhitungan sisa masa berlaku.

4. **RFC 9116 (`security.txt`) & Governance (`governance_auditor.py`)**:
   - Validasi keberadaan `/.well-known/security.txt` untuk kanal pelaporan kerentanan (*Responsible Disclosure*).
   - Validasi field wajib `Contact:` dan `Expires:`.

5. **Laporan & Ekspor (`exporter.py`)**:
   - Ekspor laporan audit ke format Markdown (`.md`) dan JSON (`.json`) lengkap dengan analisis tingkat keparahan, deskripsi, dan panduan remediasi.

---

## 🚀 Instalasi

Pastikan menggunakan **Python >= 3.10**.

```bash
# 1. Buat dan aktifkan Virtual Environment
python3 -m venv .venv
source .venv/bin/activate  # Linux / macOS
# .venv\Scripts\activate   # Windows

# 2. Instal dependensi pengembangan
pip install -e ".[dev]"
```

---

## 💻 Penggunaan

### 1. Terminal UI Interaktif (TUI)
```bash
vanguard
# atau
python -m vanguard.main
```
Atau menggunakan alias:
```bash
make run
```
*Navigasi TUI:*
- Masukkan URL target (contoh: `https://example.com`) pada input bar.
- Tekan `Enter` atau tombol `[r] Mulai Audit`.
- Tekan `[m]` untuk mengekspor laporan ke Markdown (`LAPORAN_AUDIT_VANGUARD.md`).
- Tekan `[j]` untuk mengekspor laporan ke JSON (`LAPORAN_AUDIT_VANGUARD.json`).
- Tekan `[q]` untuk keluar.

### 2. Headless CLI (Otomatisasi CI/CD)
```bash
vanguard --headless --url https://example.com --fail-under 80 --export-md --export-json
# atau
python -m vanguard.main --headless --url https://example.com --fail-under 80 --export-md --export-json
```
*Argumen CLI:*
- `--headless`: Jalankan dalam mode CLI tanpa antarmuka TUI.
- `--url`: URL target yang akan diaudit (contoh: `https://example.com`).
- `--fail-under`: Skor minimal yang dapat diterima (0-100). Jika skor audit di bawah nilai ini, exit code bernilai `1` (menggagalkan pipeline CI/CD).
- `--export-md`: Simpan hasil audit ke file Markdown (`audit_report.md`).
- `--export-json`: Simpan hasil audit ke file JSON (`audit_report.json`).

---

## 🛠️ Perintah Pengembangan & Quality Gate

Tersedia perintah praktis melalui `Makefile`:

```bash
make format       # Format kode sumber dengan Ruff
make lint         # Linter dengan Ruff
make typecheck    # Static type check dengan Mypy (Strict)
make security     # Pemindaian keamanan kode dengan Bandit
make test         # Menjalankan pengujian unit dengan Pytest & Coverage
make all          # Menjalankan format, lint, typecheck, security, dan test
```

---

## ⚖️ Lisensi & Etika
Lisensi MIT. VanguardAudit dirancang khusus untuk audit pertahanan (*defensive hardening*) dan penilaian kepatuhan (*compliance assessment*). Gunakan hanya pada sistem yang Anda miliki atau dengan otorisasi resmi.
