from typing import Generic, TypeVar, Optional, Any
from pydantic import BaseModel, ConfigDict

T = TypeVar("T")

class WrappedResponse(BaseModel, Generic[T]):
    status: str
    data: Optional[T] = None
    error: Optional[str] = None

    model_config = ConfigDict(extra="allow")

def success_response(data: Any) -> dict:
    response = {"status": "success", "data": data, "error": None}
    if isinstance(data, dict):
        response.update(data)
    return response

def error_response(msg: str) -> dict:
    return {"status": "error", "data": None, "error": msg, "detail": msg}
