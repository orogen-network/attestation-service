"""Multi-vendor attestation aggregator."""

from attestation_service.app import build_app
from attestation_service.config import AttestationConfig
from attestation_service.vendors import (
    MockAmdSdk,
    MockIntelTdxSdk,
    MockNvidiaSdk,
)

__all__ = [
    "AttestationConfig",
    "MockAmdSdk",
    "MockIntelTdxSdk",
    "MockNvidiaSdk",
    "build_app",
]
