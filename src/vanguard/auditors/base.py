from abc import ABC, abstractmethod

from vanguard.core.models import AuditFinding


class BaseAuditor(ABC):
    """Kontrak dasar (Interface) untuk seluruh modul auditor defensif."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nama deskriptif modul auditor."""
        raise NotImplementedError

    @abstractmethod
    async def run(self, target_url: str) -> list[AuditFinding]:
        """Menjalankan pemeriksaan konfigurasi keamanan secara asinkron."""
        raise NotImplementedError
