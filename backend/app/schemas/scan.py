from pydantic import BaseModel, ConfigDict
from typing import Optional
from uuid import UUID
from datetime import datetime

class ScanCreateRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    scan_id: UUID
    status: str
    estimated_duration_seconds: int
    
class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: dict[str, str] = {}
    error_message: Optional[str] = None
    
    overall_severity: Optional[str] = None
    preview_risk: Optional[dict] = None

class ScanPreviewResponse(BaseModel):
    overall_severity: str
    risk_item: dict
    locked_risks_count: int = 2
    is_paid: bool

    model_config = ConfigDict(from_attributes=True)
