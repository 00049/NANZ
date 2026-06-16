from typing import Literal

from pydantic import BaseModel, ConfigDict


class FixRequest(BaseModel):
    """Request body for generating AI-powered remediation steps."""

    finding_id: str
    finding_title: str
    finding_description: str
    finding_detail: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    target_domain: str
    scan_id: str

    model_config = ConfigDict(from_attributes=True)


class FixStep(BaseModel):
    """A single ordered remediation step."""

    order: int
    title: str
    description: str
    code_snippet: str | None = None
    code_language: str | None = None

    model_config = ConfigDict(from_attributes=True)


class FixResponse(BaseModel):
    """Full remediation guide returned to the frontend."""

    finding_id: str
    summary: str
    impact: str
    steps: list[FixStep]
    verification: str
    verification_command: str | None = None
    estimated_minutes: int
    difficulty: Literal["easy", "medium", "hard"]
    references: list[str]
    cached: bool = False

    model_config = ConfigDict(from_attributes=True)
