"""Attestation aggregator tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from mining_types import generate_keypair, sign_ed25519

from attestation_service import (
    AttestationConfig,
    MockAmdSdk,
    MockIntelTdxSdk,
    MockNvidiaSdk,
    build_app,
)

INTERNAL_TOKEN = "test-attest-internal"


@pytest.fixture(autouse=True)
def auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTERNAL_AUTH_TOKEN", INTERNAL_TOKEN)
    monkeypatch.delenv("OROGEN_ENV", raising=False)


def _hdrs() -> dict[str, str]:
    return {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


@pytest.fixture
def config() -> AttestationConfig:
    priv, _ = generate_keypair()
    return AttestationConfig(aggregator_id="att-1", aggregator_private_key_hex=priv)


def _challenge_and_sign(
    client: TestClient,
    operator_id: str,
    operator_priv_hex: str,
) -> tuple[str, str]:
    """Helper: obtain a challenge and return (nonce, signature_hex)."""
    r = client.post(
        "/v1/challenges",
        json={"operator_id": operator_id},
        headers=_hdrs(),
    )
    assert r.status_code == 200, r.text
    nonce = r.json()["nonce"]
    sig = sign_ed25519(operator_priv_hex, nonce.encode("utf-8"))
    return nonce, sig


def test_vendor_sdks_produce_and_verify() -> None:
    n = MockNvidiaSdk().produce_quote("op-1", "nonce-1")
    assert MockNvidiaSdk().verify_quote(n)
    i = MockIntelTdxSdk().produce_quote("op-1", "nonce-1")
    assert MockIntelTdxSdk().verify_quote(i)
    a = MockAmdSdk().produce_quote("op-1", "nonce-1")
    assert MockAmdSdk().verify_quote(a)


def test_healthz(config: AttestationConfig) -> None:
    app = build_app(config)
    with TestClient(app) as c:
        r = c.get("/healthz")
        assert r.status_code == 200


def test_attest_requires_auth(config: AttestationConfig) -> None:
    app = build_app(config)
    with TestClient(app) as c:
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-1",
                "tier": "dc-standard",
                "measured_vm_bundle": "ab" * 32,
                "request_vendors": ["nvidia"],
            },
        )
        assert r.status_code == 401


def test_attest_unregistered_operator_passes_in_dev(config: AttestationConfig) -> None:
    """When no operator is registered and we're not in production, dev fall-through."""
    app = build_app(config)
    with TestClient(app) as c:
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-1",
                "tier": "dc-standard",
                "measured_vm_bundle": "ab" * 32,
                "request_vendors": ["nvidia"],
            },
            headers=_hdrs(),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["report_hash"]
        assert body["report"]["gpu_quote"]
        assert body["report"]["tdx_quote"] is None


def test_attest_registered_operator_requires_challenge(config: AttestationConfig) -> None:
    """Once an operator is registered, attest must include a signed challenge."""
    app = build_app(config)
    op_priv, op_pub = generate_keypair()
    app.state.registry.register("op-1", op_pub)
    with TestClient(app) as c:
        # Missing challenge → 401.
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-1",
                "tier": "dc-standard",
                "measured_vm_bundle": "ab" * 32,
                "request_vendors": ["nvidia"],
            },
            headers=_hdrs(),
        )
        assert r.status_code == 401
        # Happy path: obtain a challenge, sign it.
        nonce, sig = _challenge_and_sign(c, "op-1", op_priv)
        r2 = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-1",
                "tier": "dc-standard",
                "measured_vm_bundle": "ab" * 32,
                "request_vendors": ["nvidia"],
                "challenge_nonce": nonce,
                "challenge_signature": sig,
            },
            headers=_hdrs(),
        )
        assert r2.status_code == 200, r2.text


def test_attest_rejects_bad_challenge_signature(config: AttestationConfig) -> None:
    app = build_app(config)
    op_priv, op_pub = generate_keypair()
    _, wrong_pub = generate_keypair()
    app.state.registry.register("op-1", wrong_pub)  # registry has WRONG pubkey
    with TestClient(app) as c:
        nonce, sig = _challenge_and_sign(c, "op-1", op_priv)
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-1",
                "tier": "dc-standard",
                "measured_vm_bundle": "ab" * 32,
                "request_vendors": ["nvidia"],
                "challenge_nonce": nonce,
                "challenge_signature": sig,
            },
            headers=_hdrs(),
        )
        assert r.status_code == 401


def test_attest_multivendor(config: AttestationConfig) -> None:
    app = build_app(config)
    with TestClient(app) as c:
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-2",
                "tier": "dc-premium",
                "measured_vm_bundle": "cd" * 32,
                "request_vendors": ["nvidia", "intel_tdx", "amd_sev_snp"],
            },
            headers=_hdrs(),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["report"]["gpu_quote"]
        assert body["report"]["tdx_quote"]
        assert body["report"]["sev_snp_report"]


def test_attest_missing_required_vendor() -> None:
    priv, _ = generate_keypair()
    cfg = AttestationConfig(
        aggregator_id="att", aggregator_private_key_hex=priv,
        required_vendors=("nvidia", "intel_tdx"),
    )
    app = build_app(cfg)
    with TestClient(app) as c:
        r = c.post(
            "/v1/attest",
            json={
                "operator_id": "op-3",
                "tier": "cloud-rented",
                "measured_vm_bundle": "ef" * 32,
                "request_vendors": ["nvidia"],
            },
            headers=_hdrs(),
        )
        assert r.status_code == 400


def test_get_report_404_then_200(config: AttestationConfig) -> None:
    app = build_app(config)
    with TestClient(app) as c:
        r = c.get("/v1/reports/missing", headers=_hdrs())
        assert r.status_code == 404
        c.post(
            "/v1/attest",
            json={
                "operator_id": "op-x",
                "tier": "dc-standard",
                "measured_vm_bundle": "00" * 32,
                "request_vendors": ["nvidia"],
            },
            headers=_hdrs(),
        )
        r = c.get("/v1/reports/op-x", headers=_hdrs())
        assert r.status_code == 200


def test_reports_lru_caps_growth(config: AttestationConfig) -> None:
    app = build_app(config)
    app.state.max_reports = 3
    with TestClient(app) as c:
        for i in range(5):
            r = c.post(
                "/v1/attest",
                json={
                    "operator_id": f"op-{i}",
                    "tier": "dc-standard",
                    "measured_vm_bundle": "00" * 32,
                    "request_vendors": ["nvidia"],
                },
                headers=_hdrs(),
            )
            assert r.status_code == 200, r.text
        assert len(app.state.reports) == 3
        # oldest two should be evicted
        assert "op-0" not in app.state.reports
        assert "op-1" not in app.state.reports
        assert "op-4" in app.state.reports
