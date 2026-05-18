"""Attestation aggregator configuration.

The `aggregator_private_key_hex` is wrapped in `pydantic.SecretStr` so it
never appears in log lines, `repr()`, or accidental JSON serializations of
the config (HIGH-SVC-009). Retrieve via `.aggregator_private_key()` only
inside signing call-sites.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import SecretStr


def _as_secret(value: str | SecretStr) -> SecretStr:
    return value if isinstance(value, SecretStr) else SecretStr(value)


@dataclass
class AttestationConfig:
    aggregator_id: str
    aggregator_private_key_hex: SecretStr
    required_vendors: tuple[str, ...] = ("nvidia",)
    validity_window_ms: int = 7 * 86400 * 1000
    max_reports: int = 10_000

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "aggregator_private_key_hex",
            _as_secret(self.aggregator_private_key_hex),
        )

    def aggregator_private_key(self) -> str:
        """Return the raw hex private key — only call from a signer."""
        return self.aggregator_private_key_hex.get_secret_value()
