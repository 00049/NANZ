from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class WrappedResponse(BaseModel, Generic[T]):
    status: str
    data: T | None = None
    error: str | None = None

    model_config = ConfigDict(extra="allow")


def success_response(data: Any) -> dict:
    response = {"status": "success", "data": data, "error": None}
    if isinstance(data, dict):
        response.update(data)
    return response


def error_response(msg: str) -> dict:
    return {"status": "error", "data": None, "error": msg, "detail": msg}
