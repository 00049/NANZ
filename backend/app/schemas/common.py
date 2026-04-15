from typing import Generic, TypeVar, Optional, Any
from pydantic import BaseModel

T = TypeVar("T")

class WrappedResponse(BaseModel, Generic[T]):
    status: str
    data: Optional[T] = None
    error: Optional[str] = None

def success_response(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}

def error_response(msg: str) -> dict:
    return {"status": "error", "data": None, "error": msg}
