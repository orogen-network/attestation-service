"""Attestation aggregator HTTP API.

Endpoints:
- `POST /v1/challenges` — issue a fresh challenge nonce for an operator.
- `POST /v1/attest` — operator submits a request to be attested. We call the mock
  vendor SDKs in turn, build an RFC-0002 report, sign, persist, return.
- `GET  /v1/reports/{operator_id}` — latest report for a given operator.
- `GET  /healthz`

Security model:
- All non-healthz routes require `INTERNAL_AUTH_TOKEN` bearer.
- `/v1/attest` additionally requires the operator to have first obtained a
  challenge nonce from `/v1/challenges`, signed it with their private key,
  and submitted (challenge_nonce, challenge_signature). The signature is
  verified against the operator's pubkey from the registry.
- Stored reports are capped by an LRU (`max_reports`) to bound memory.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import OrderedDict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from mining_types import (
    AttestationReport,
    OperatorTier,
    verify_ed25519,
)
from pydantic import BaseModel

from attestation_service.auth import require_internal_auth, require_internal_token
from attestation_service.config import AttestationConfig
from attestation_service.registry import OperatorRegistry
from attestation_service.vendors import (
    MockAmdSdk,
    MockIntelTdxSdk,
    MockNvidiaSdk,
    fresh_nonce,
)

CHALLENGE_TTL_S = 120


class AttestRequest(BaseModel):
    operator_id: str
    tier: OperatorTier = OperatorTier.DC_STANDARD
    measured_vm_bundle: str
    request_vendors: list[str] = ["nvidia"]
    # Operator-supplied proof-of-possession (CRIT-SVC-002).
    challenge_nonce: str | None = None
    challenge_signature: str | None = None


class ChallengeRequest(BaseModel):
    operator_id: str


def build_app(config: AttestationConfig) -> FastAPI:
    require_internal_token()
    if (
        os.environ.get("OROGEN_ENV", "").lower() == "production"
        and not config.allow_mock_quotes_in_production
        and os.environ.get("ATTESTATION_ALLOW_MOCK_QUOTES", "").lower()
        not in {"1", "true", "yes"}
    ):
        raise RuntimeError(
            "mock attestation quote providers are not allowed in production"
        )

    app = FastAPI(title="attestation-service", version="0.1.0")
    allowed_hosts = [
        h.strip()
        for h in os.environ.get("ALLOWED_HOSTS", "*").split(",")
        if h.strip()
    ] or ["*"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    nvidia = MockNvidiaSdk()
    intel = MockIntelTdxSdk()
    amd = MockAmdSdk()
    # LRU-capped store keyed by operator_id (MED-SVC-012).
    by_operator: OrderedDict[str, AttestationReport] = OrderedDict()
    challenges: dict[str, tuple[str, float]] = {}  # operator_id -> (nonce, expiry_ms)
    registry = OperatorRegistry.from_env()

    app.state.config = config
    app.state.reports = by_operator
    app.state.challenges = challenges
    app.state.registry = registry
    app.state.max_reports = getattr(config, "max_reports", 10_000)

    def _is_production() -> bool:
        return os.environ.get("OROGEN_ENV", "").lower() == "production"

    def _verify_challenge(req: AttestRequest) -> None:
        """Either the operator passes a valid signed challenge, or this is
        non-production with an empty registry (dev fall-through)."""
        op_pubkey = registry.get(req.operator_id)
        # Production / registered-operator path — must verify the signature.
        if op_pubkey is not None or _is_production():
            if not (req.challenge_nonce and req.challenge_signature):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="missing challenge_nonce/challenge_signature",
                )
            stored = challenges.get(req.operator_id)
            if stored is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="no outstanding challenge for operator",
                )
            nonce, expiry_ms = stored
            if nonce != req.challenge_nonce:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="challenge nonce mismatch",
                )
            if time.time() * 1000 > expiry_ms:
                challenges.pop(req.operator_id, None)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="challenge expired",
                )
            if op_pubkey is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="operator not registered",
                )
            if not verify_ed25519(
                op_pubkey, nonce.encode("utf-8"), req.challenge_signature,
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="challenge signature invalid",
                )
            # Consume the challenge so it can't be reused.
            challenges.pop(req.operator_id, None)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "aggregator_id": config.aggregator_id}

    @app.post("/v1/challenges", dependencies=[Depends(require_internal_auth)])
    async def issue_challenge(req: ChallengeRequest) -> dict[str, Any]:
        nonce = secrets.token_hex(32)
        expiry_ms = (time.time() + CHALLENGE_TTL_S) * 1000
        challenges[req.operator_id] = (nonce, expiry_ms)
        return {"operator_id": req.operator_id, "nonce": nonce, "ttl_s": CHALLENGE_TTL_S}

    @app.post("/v1/attest", dependencies=[Depends(require_internal_auth)])
    async def attest(req: AttestRequest) -> dict[str, Any]:
        for v in config.required_vendors:
            if v not in req.request_vendors:
                raise HTTPException(
                    status_code=400,
                    detail=f"required vendor {v!r} missing from request",
                )

        _verify_challenge(req)

        nonce = fresh_nonce()
        gpu_q = None
        tdx_q = None
        sev_q = None

        if "nvidia" in req.request_vendors:
            gpu_q = nvidia.produce_quote(req.operator_id, nonce)
            if not nvidia.verify_quote(gpu_q):
                raise HTTPException(status_code=400, detail="nvidia quote invalid")
        if "intel_tdx" in req.request_vendors:
            tdx_q = intel.produce_quote(req.operator_id, nonce)
            if not intel.verify_quote(tdx_q):
                raise HTTPException(status_code=400, detail="tdx quote invalid")
        if "amd_sev_snp" in req.request_vendors:
            sev_q = amd.produce_quote(req.operator_id, nonce)
            if not amd.verify_quote(sev_q):
                raise HTTPException(status_code=400, detail="sev-snp report invalid")

        now_ms = int(time.time() * 1000)
        report = AttestationReport(
            operator_id=req.operator_id,
            tier=req.tier,
            gpu_quote=gpu_q,
            tdx_quote=tdx_q,
            sev_snp_report=sev_q,
            firmware_hashes=[],
            measured_vm_bundle=req.measured_vm_bundle,
            timestamp_ms=now_ms,
            validity_window_ms=config.validity_window_ms,
            vendor_pki_chain_hashes=[],
        ).sign(config.aggregator_private_key())

        # LRU-cap reports (MED-SVC-012).
        if req.operator_id in by_operator:
            by_operator.move_to_end(req.operator_id)
        by_operator[req.operator_id] = report
        while len(by_operator) > app.state.max_reports:
            by_operator.popitem(last=False)
        return {
            "report_hash": report.report_hash(),
            "report": report.model_dump(mode="json"),
        }

    @app.get("/v1/reports/{operator_id}", dependencies=[Depends(require_internal_auth)])
    async def get_report(operator_id: str) -> dict[str, Any]:
        rep = by_operator.get(operator_id)
        if rep is None:
            raise HTTPException(status_code=404, detail="no attestation for operator")
        # Touch LRU on read.
        by_operator.move_to_end(operator_id)
        return {
            "report_hash": rep.report_hash(),
            "report": rep.model_dump(mode="json"),
        }

    return app
