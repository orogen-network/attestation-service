"""Bearer-token authentication for attestation-service.

`/v1/attest` and `/v1/reports/*` are gated by `INTERNAL_AUTH_TOKEN`. The
attestation aggregator is an internal service — only the worker-control-plane,
chain indexer, and operator-onboarding flow should call it. In production
(`OROGEN_ENV=production`) the service refuses to start without the token.
"""

from __future__ import annotations

import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_BEARER = HTTPBearer(auto_error=False)


def _is_production() -> bool:
    return os.environ.get("OROGEN_ENV", "").lower() == "production"


def require_internal_token() -> str:
    tok = os.environ.get("INTERNAL_AUTH_TOKEN", "").strip()
    if not tok and _is_production():
        raise RuntimeError(
            "INTERNAL_AUTH_TOKEN must be set in production (OROGEN_ENV=production)"
        )
    return tok


async def require_internal_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_BEARER),
) -> None:
    expected = require_internal_token()
    if not expected:
        return
    if creds is None or creds.scheme.lower() != "bearer" or creds.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="internal auth required",
            headers={"WWW-Authenticate": "Bearer"},
        )
