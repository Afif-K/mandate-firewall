"""JSON-RPC 2.0 message parsing and construction.

A request looks like:
    {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": ["0x..", "latest"]}
and a response carries the same id plus exactly one of "result" or "error".
A batch is a JSON array of requests; the reply is an array of responses.

We validate strictly and rebuild every message we send from validated fields,
so nothing the client sent beyond (method, params) ever reaches the upstream.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# Standard JSON-RPC 2.0 codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# EIP-1474 server codes.
RESOURCE_UNAVAILABLE = -32002  # the upstream node could not be reached or misbehaved
TRANSACTION_REJECTED = -32003  # the firewall refused to forward a transaction

RequestId = int | str | None

MAX_METHOD_LENGTH = 128


class JsonRpcRequest(BaseModel):
    # strict: no coercion, so id=true or id=1.5 is rejected rather than turned
    # into an int. Unknown top-level keys are ignored and never forwarded.
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")

    jsonrpc: Literal["2.0"]
    method: str = Field(min_length=1, max_length=MAX_METHOD_LENGTH)
    params: list[Any] | dict[str, Any] | None = None
    id: RequestId = None


class JsonRpcErrorObject(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")

    code: int
    message: str
    data: Any = None


class JsonRpcProtocolError(Exception):
    """A request we refuse to process, reported back as a JSON-RPC error."""

    def __init__(self, code: int, message: str, request_id: RequestId = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


def parse_request(obj: Any) -> JsonRpcRequest:
    """Validate one decoded JSON value as a request. Raises JsonRpcProtocolError."""
    if not isinstance(obj, dict):
        raise JsonRpcProtocolError(INVALID_REQUEST, "request must be a JSON object")
    # Echo the id in the error if it is at least a valid id, so the client can match it.
    raw_id = obj.get("id")
    echo_id = raw_id if _is_valid_id(raw_id) else None
    if "id" not in obj:
        # A request without an id is a notification, which gets no response.
        # A firewall that silently swallows calls is hard to debug, and no
        # Ethereum client needs notifications, so we reject them instead.
        raise JsonRpcProtocolError(
            INVALID_REQUEST, "notifications (requests without id) are not supported"
        )
    try:
        return JsonRpcRequest.model_validate(obj)
    except ValidationError as exc:
        fields = sorted({str(err["loc"][0]) for err in exc.errors() if err["loc"]})
        detail = f" (bad fields: {', '.join(fields)})" if fields else ""
        raise JsonRpcProtocolError(INVALID_REQUEST, f"invalid request{detail}", echo_id) from exc


def _is_valid_id(value: Any) -> bool:
    # bool is a subclass of int in Python; JSON true/false are not valid ids.
    return (
        value is None
        or isinstance(value, str)
        or (isinstance(value, int) and not isinstance(value, bool))
    )


def result_response(request_id: RequestId, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(
    request_id: RequestId, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
