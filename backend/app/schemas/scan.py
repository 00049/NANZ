from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    """Request body for creating a scan."""

    url: str

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    """Response returned when a scan is accepted."""

    scan_id: UUID
    status: str
    estimated_duration_seconds: int

    model_config = ConfigDict(from_attributes=True)


class ScanStatusResponse(BaseModel):
    """Polling response for scan status and progress."""

    scan_id: UUID
    status: str
    progress: dict[str, str] = Field(default_factory=dict)
    error_message: str | None = None

    overall_severity: str | None = None
    preview_risk: dict | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanPreviewResponse(BaseModel):
    """Locked free preview for a completed report."""

    overall_severity: str
    risk_item: dict
    locked_risks_count: int = 2
    is_paid: bool

    model_config = ConfigDict(from_attributes=True)
