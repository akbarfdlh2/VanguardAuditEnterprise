from abc import ABC, abstractmethod

from vanguard.core.models import AuditFinding


class BaseAuditor(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def run(self, target_url: str) -> list[AuditFinding]:
        raise NotImplementedError
