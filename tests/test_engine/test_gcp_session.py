"""Tests for GCP session creation — credential scoping (Task #57).

CI symptom (real, deterministic): GCP-NR9-004 (compute_v1.FirewallsClient)
failed impersonated-credential CI runs with "RefreshError: Unable to acquire
impersonated credentials ... 400 INVALID_ARGUMENT", while checks built on
kms_v1 and google-cloud-storage in the same run succeeded. Investigation
(28.07.2026) verified against the real google-cloud-python transport source
that gapic-generated transports (kms_v1, compute_v1 — byte-identical
__init__ logic in both) only apply default scopes to credentials THEY load
themselves (the `credentials is None` branch); credentials passed in
directly — exactly what GcpSession.client()/the checks' direct
FirewallsClient(credentials=...)/KeyManagementServiceClient(credentials=...)
constructions do — are used completely unscoped. google-cloud-storage is the
one exception: its base Client always re-scopes any passed-in credentials via
with_scopes_if_required(credentials, SCOPE). Unscoped external_account
credentials send `scope: null` in the IAM Credentials generateAccessToken
request body used to mint the impersonated token — a documented required
field — which is a standards-consistent cause of the observed 400.

The fix scopes session.credentials ONCE, in create_gcp_session(), so every
consumer (gapic clients, googleapiclient discovery services, storage.Client)
shares one already-scoped credentials object regardless of that
per-client-library asymmetry.
"""

from typing import Any

import google.auth.credentials
import pytest

from nis2scan.engine.models.config import ProviderConfig
from nis2scan.engine.providers.gcp.session import GCP_DEFAULT_SCOPES, create_gcp_session


class FakeScopedCredentials(google.auth.credentials.Credentials, google.auth.credentials.Scoped):
    """Real (non-Mock) Scoped-credentials double.

    Mirrors the one property of google.auth.external_account.Credentials that
    matters for Task #57: ``requires_scopes`` is True until scopes/default_scopes
    are actually set. Implementing the real ABCs (rather than a MagicMock)
    means this test exercises the genuine
    google.auth.credentials.with_scopes_if_required() contract instead of
    asserting on mocked call arguments — no mock-drift risk if that helper's
    internals ever change.
    """

    def __init__(self, scopes: list[str] | None = None) -> None:
        super().__init__()
        self._scopes = scopes

    @property
    def requires_scopes(self) -> bool:
        return not self._scopes

    def with_scopes(self, scopes: list[str] | None, default_scopes: list[str] | None = None) -> "FakeScopedCredentials":
        return FakeScopedCredentials(scopes=list(scopes or default_scopes or []))

    def refresh(self, request: Any) -> None:  # pragma: no cover - not exercised here
        self.token = "fake-token"


@pytest.fixture
def _fake_default_credentials(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stand in for google.auth.default(): starts from unscoped credentials
    (like a freshly-loaded external_account/WIF credential) and applies the
    REAL with_scopes_if_required() — same as google.auth.default() itself
    does internally — so the only thing under test is whether
    create_gcp_session() passes a non-empty ``scopes`` kwarg through."""
    captured: dict[str, Any] = {}

    def fake_default(*, scopes: list[str] | None = None, **_kwargs: Any) -> tuple[Any, str | None]:
        captured["scopes"] = scopes
        unscoped = FakeScopedCredentials()
        scoped = google.auth.credentials.with_scopes_if_required(unscoped, scopes)
        return scoped, None

    monkeypatch.setattr("google.auth.default", fake_default)
    return captured


def test_create_gcp_session_requests_scopes_from_google_auth_default(
    _fake_default_credentials: dict[str, Any],
) -> None:
    """create_gcp_session() must call google.auth.default(scopes=...) with a
    non-empty scope list (Task #57) — not the bare google.auth.default()."""
    create_gcp_session(ProviderConfig(enabled=True, accounts=["test-project"]))

    assert _fake_default_credentials["scopes"], "google.auth.default() was called without scopes"
    assert "https://www.googleapis.com/auth/cloud-platform" in _fake_default_credentials["scopes"]


def test_create_gcp_session_returns_already_scoped_credentials(
    _fake_default_credentials: dict[str, Any],
) -> None:
    """The credentials object handed back on GcpSession must already be
    scoped (requires_scopes is False) — GAPIC clients built directly as
    ClientClass(credentials=session.credentials) (kms_v1, compute_v1; see
    nr8_kryptographie.py, nr9_zugriffskontrolle.py) do not scope on their own,
    so the session itself is the only place left to guarantee this."""
    session = create_gcp_session(ProviderConfig(enabled=True, accounts=["test-project"]))

    assert isinstance(session.credentials, google.auth.credentials.Scoped)
    assert session.credentials.requires_scopes is False


def test_gcp_default_scopes_constant_is_cloud_platform() -> None:
    """Pin the constant's value: cloud-platform is the broad scope Google
    documents for exactly this "many client libraries share one impersonated
    credential" scenario — narrower scopes (e.g. compute-only) would leave
    kms_v1/storage/discovery-based checks unscoped again."""
    assert GCP_DEFAULT_SCOPES == ["https://www.googleapis.com/auth/cloud-platform"]
