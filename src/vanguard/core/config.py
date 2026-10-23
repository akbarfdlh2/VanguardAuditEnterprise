from vanguard.core.models import Severity

APP_NAME = "VanguardAudit Enterprise"
APP_VERSION = "2.0.0"
DEFAULT_TIMEOUT = 8.0
USER_AGENT = f"VanguardAudit-DefensiveInspector/{APP_VERSION} (+https://localhost/security-posture)"

# Selector DKIM umum yang sering digunakan oleh layanan email korporat
COMMON_DKIM_SELECTORS: list[str] = [
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
REQUIRED_SECURITY_HEADERS: dict[str, tuple[Severity, str, str, str]] = {
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
