"""Mock vendor SDKs.

Each mock SDK has:
- `produce_quote(operator_id, nonce)` — returns a `*Quote` Pydantic object.
- `verify_quote(quote)` — performs minimal sanity checks.

In production these become wrappers over real SDKs:
- NVIDIA: `nv-host-attestation-sdk` (RIM, NVTrust).
- Intel: `tee-quote-verification-library`.
- AMD:  `snphost-attest`.
"""

from __future__ import annotations

import hashlib
import secrets

from mining_types import AmdSevSnpReport, IntelTdxQuote, NvidiaQuote


def _fake_cert(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


class MockNvidiaSdk:
    name = "nvidia"

    def produce_quote(self, operator_id: str, nonce: str) -> NvidiaQuote:
        gpu_uuid = hashlib.sha256(f"gpu::{operator_id}".encode()).hexdigest()
        return NvidiaQuote(
            device_cert=_fake_cert(f"nv-dev::{operator_id}"),
            attestation_cert=_fake_cert(f"nv-att::{operator_id}"),
            measurement=_fake_cert(f"nv-meas::{operator_id}"),
            nonce=nonce,
            gpu_uuid=gpu_uuid,
        )

    def verify_quote(self, quote: NvidiaQuote) -> bool:
        return all([
            len(quote.gpu_uuid) == 64,
            len(quote.measurement) == 64,
            len(quote.device_cert) == 64,
            bool(quote.nonce),
        ])


class MockIntelTdxSdk:
    name = "intel_tdx"

    def produce_quote(self, operator_id: str, nonce: str) -> IntelTdxQuote:
        return IntelTdxQuote(
            quote_blob=_fake_cert(f"tdx-blob::{operator_id}::{nonce}"),
            measurement=_fake_cert(f"tdx-meas::{operator_id}"),
            fmspc="00606A000000",
        )

    def verify_quote(self, quote: IntelTdxQuote) -> bool:
        return bool(quote.quote_blob) and bool(quote.fmspc)


class MockAmdSdk:
    name = "amd_sev_snp"

    def produce_quote(self, operator_id: str, nonce: str) -> AmdSevSnpReport:
        return AmdSevSnpReport(
            report_blob=_fake_cert(f"sev-blob::{operator_id}::{nonce}"),
            measurement=_fake_cert(f"sev-meas::{operator_id}"),
            chip_id=_fake_cert(f"sev-chip::{operator_id}"),
        )

    def verify_quote(self, report: AmdSevSnpReport) -> bool:
        return all([
            len(report.chip_id) == 64,
            len(report.measurement) == 64,
            bool(report.report_blob),
        ])


def fresh_nonce() -> str:
    return secrets.token_hex(16)
