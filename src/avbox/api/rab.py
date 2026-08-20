from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse

from avbox.models import PROTOCOL_VERSION, ErrorCode, ProtocolError
from avbox.protocol import RABClient, RABProtocolError, RABService

router = APIRouter(prefix="/api/v1/rab", tags=["RAB Protocol v1"])


def service(request: Request) -> RABService:
    value = cast(RABService | None, request.app.state.context.rab_protocol)
    if value is None or not value.settings.enabled:
        raise RABProtocolError(503, ErrorCode.STORAGE_UNAVAILABLE, "RAB Protocol is disabled")
    return value


def client(request: Request, scope: str, authorization: str | None) -> RABClient:
    return service(request).authenticate(authorization, scope)


@router.get("/capabilities")
async def capabilities(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> dict[str, object]:
    client(request, "capabilities.read", authorization)
    return service(request).capabilities()


@router.get("/analysis-profiles")
async def profiles(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> list[dict[str, object]]:
    client(request, "capabilities.read", authorization)
    return [profile.model_dump(mode="json") for profile in service(request).profiles()]


@router.post("/analysis-jobs", status_code=202)
async def submit(
    request: Request,
    object_bytes: Annotated[UploadFile, File()],
    client_request_id: Annotated[str, Form()],
    expected_sha256: Annotated[str, Form(pattern=r"^[0-9a-fA-F]{64}$")],
    profile: Annotated[str, Form()] = "security-default@1",
    protocol_version: Annotated[str, Form()] = PROTOCOL_VERSION,
    filename: Annotated[str | None, Form()] = None,
    media_type: Annotated[str | None, Form()] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    if protocol_version != PROTOCOL_VERSION:
        raise RABProtocolError(
            422,
            ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
            "only RAB Protocol v1 is supported",
        )
    authenticated = client(request, "analysis.submit", authorization)
    accepted = service(request).submit_stream(
        stream=object_bytes.file,
        client=authenticated,
        client_request_id=client_request_id,
        idempotency_key=idempotency_key or "",
        profile_id=profile,
        expected_sha256=expected_sha256,
        filename=filename or object_bytes.filename,
        media_type=media_type or object_bytes.content_type,
    )
    return JSONResponse(
        status_code=200 if accepted.duplicate else 202, content=accepted.model_dump(mode="json")
    )


@router.get("/analysis-jobs/{job_id}")
async def job_status(
    job_id: str, request: Request, authorization: Annotated[str | None, Header()] = None
) -> dict[str, object]:
    authenticated = client(request, "analysis.read", authorization)
    record = service(request).jobs.rab_job(job_id)
    if record and record["client_id"] != authenticated.client_id:
        raise RABProtocolError(403, ErrorCode.FORBIDDEN, "job belongs to another client")
    return service(request).status(job_id).model_dump(mode="json")


@router.get("/analysis-jobs/{job_id}/results")
async def job_results(
    job_id: str, request: Request, authorization: Annotated[str | None, Header()] = None
) -> dict[str, object]:
    authenticated = client(request, "analysis.read", authorization)
    record = service(request).jobs.rab_job(job_id)
    if record and record["client_id"] != authenticated.client_id:
        raise RABProtocolError(403, ErrorCode.FORBIDDEN, "job belongs to another client")
    return service(request).results(job_id).model_dump(mode="json")


async def protocol_error_handler(_request: Request, exc: RABProtocolError) -> JSONResponse:
    document = ProtocolError(code=exc.code, detail=exc.detail)
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    return JSONResponse(
        status_code=exc.status_code, content=document.model_dump(mode="json"), headers=headers
    )
