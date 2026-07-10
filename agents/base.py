from abc import ABC, abstractmethod

from core.models import AgentResult, ScanContext, utcnow


class BaseAgent(ABC):
    name: str
    display_name: str

    @abstractmethod
    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        """Populate result.findings / result.raw_data. Raise on fatal error."""

    def run(self, ctx: ScanContext) -> AgentResult:
        result = AgentResult(agent_name=self.display_name, started_at=utcnow())
        try:
            self._run(ctx, result)
        except Exception as exc:  # noqa: BLE001 - one agent's failure must not abort the pipeline
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.finished_at = utcnow()
        return result
