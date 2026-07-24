"""Tests for §30 Nr. 8 — Kryptographie GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr8_kryptographie import (
    CheckCertificateManager,
    CheckCloudSqlSsl,
    CheckCmekEncryption,
    CheckDiskEncryption,
    CheckKmsKeyRotation,
    CheckSslPolicyLoadBalancer,
)

from .conftest import FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckKmsKeyRotation:
    @pytest.fixture
    def kms_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import kms_v1

        client = MagicMock()
        monkeypatch.setattr(kms_v1, "KeyManagementServiceClient", lambda credentials: client)
        return client

    def _key(self, rotation_days: int | None):
        from google.cloud import kms_v1

        return SimpleNamespace(
            name="projects/p/locations/global/keyRings/kr/cryptoKeys/key-1",
            purpose=kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            rotation_period=timedelta(days=rotation_days) if rotation_days else None,
        )

    def _wire(self, kms_client: MagicMock, key) -> None:
        kms_client.list_key_rings.return_value = [SimpleNamespace(name="projects/p/locations/global/keyRings/kr")]
        kms_client.list_crypto_keys.return_value = [key]

    def test_rotated_key_produces_positive_evidence(self, kms_client: MagicMock):
        self._wire(kms_client, self._key(rotation_days=90))

        result = asyncio.run(CheckKmsKeyRotation().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["rotation_period_days"] == 90
        assert not _maengel(result)

    def test_missing_rotation_produces_finding(self, kms_client: MagicMock):
        self._wire(kms_client, self._key(rotation_days=None))

        result = asyncio.run(CheckKmsKeyRotation().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_too_long_rotation_produces_finding(self, kms_client: MagicMock):
        self._wire(kms_client, self._key(rotation_days=730))

        result = asyncio.run(CheckKmsKeyRotation().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckCmekEncryption:
    @pytest.fixture
    def disks_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "DisksClient", lambda credentials: client)
        return client

    def _wire(self, disks_client: MagicMock, disk) -> None:
        scoped = SimpleNamespace(disks=[disk])
        disks_client.aggregated_list.return_value = [("zones/europe-west3-a", scoped)]

    def test_cmek_disk_produces_positive_evidence(self, disks_client: MagicMock):
        disk = SimpleNamespace(
            name="disk-1",
            self_link="",
            disk_encryption_key=SimpleNamespace(kms_key_name="projects/p/locations/global/keyRings/kr/cryptoKeys/k"),
        )
        self._wire(disks_client, disk)

        result = asyncio.run(CheckCmekEncryption().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_google_managed_disk_produces_finding(self, disks_client: MagicMock):
        disk = SimpleNamespace(name="disk-1", self_link="", disk_encryption_key=None)
        self._wire(disks_client, disk)

        result = asyncio.run(CheckCmekEncryption().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_csek_disk_produces_positive_evidence(self, disks_client: MagicMock):
        # B-Nr.8-12: customer-supplied encryption key (no kms_key_name, but
        # sha256 is set) must be recognized as CSEK, not flagged as a defect.
        disk = SimpleNamespace(
            name="disk-1",
            self_link="",
            disk_encryption_key=SimpleNamespace(kms_key_name=None, sha256="abc123=="),
        )
        self._wire(disks_client, disk)

        result = asyncio.run(CheckCmekEncryption().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["encryption"] == "csek"
        assert compliant[0].current_state["cmek"] is False
        assert not _maengel(result)


class TestCheckSslPolicyLoadBalancer:
    @pytest.fixture
    def ssl_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "SslPoliciesClient", lambda credentials: client)
        return client

    def _wire(self, ssl_client: MagicMock, *scoped: tuple[str, list]) -> None:
        ssl_client.aggregated_list.return_value = [
            (scope, SimpleNamespace(ssl_policies=pols)) for scope, pols in scoped
        ]

    def test_tls12_policy_produces_positive_evidence(self, ssl_client: MagicMock):
        self._wire(ssl_client, ("global", [SimpleNamespace(name="pol-1", min_tls_version="TLS_1_2")]))

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["min_tls_version"] == "TLS_1_2"
        assert compliant[0].region == "global"
        assert not _maengel(result)

    def test_tls10_policy_produces_finding(self, ssl_client: MagicMock):
        self._wire(ssl_client, ("global", [SimpleNamespace(name="pol-1", min_tls_version="TLS_1_0")]))

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_unknown_tls_version_produces_no_evidence(self, ssl_client: MagicMock):
        # Fail-safe (ADR-0016): missing min_tls_version yields neither evidence nor defect
        self._wire(ssl_client, ("global", [SimpleNamespace(name="pol-1", min_tls_version="")]))

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        assert not result.findings

    def test_unrecognized_tls_value_produces_checkerror(self, ssl_client: MagicMock):
        # B-Nr.8-13: a non-empty but unrecognized value must not be silently
        # treated as compliant — it is genuinely not bewertbar.
        self._wire(ssl_client, ("global", [SimpleNamespace(name="pol-1", min_tls_version="TLS_1_3_FUTURE")]))

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "UnverifiableState"

    def test_regional_ssl_policy_is_evaluated(self, ssl_client: MagicMock):
        # FIX2: a plain SslPoliciesClient.list() only returns the global
        # scope and silently misses SSL policies attached to regional target
        # proxies. aggregated_list() must cover both scopes.
        self._wire(
            ssl_client,
            ("global", []),
            ("regions/europe-west3", [SimpleNamespace(name="pol-regional", min_tls_version="TLS_1_0")]),
        )

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].region == "europe-west3"
        assert "pol-regional" in maengel[0].resource_id

    def test_global_and_regional_policies_both_evaluated(self, ssl_client: MagicMock):
        self._wire(
            ssl_client,
            ("global", [SimpleNamespace(name="pol-global", min_tls_version="TLS_1_2")]),
            ("regions/europe-west3", [SimpleNamespace(name="pol-regional", min_tls_version="TLS_1_2")]),
        )

        result = asyncio.run(CheckSslPolicyLoadBalancer().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 2
        assert {c.region for c in compliant} == {"global", "europe-west3"}


class TestCheckCloudSqlSsl:
    def _session(self, ip_config: dict) -> FakeGcpSession:
        svc = MagicMock()
        svc.instances.return_value.list.return_value.execute.return_value = {
            "items": [
                {
                    "name": "sql-1",
                    "region": "europe-west3",
                    "settings": {"ipConfiguration": ip_config},
                }
            ]
        }
        return FakeGcpSession(services={"sqladmin": svc})

    def test_require_ssl_produces_positive_evidence(self):
        result = asyncio.run(CheckCloudSqlSsl().execute(self._session({"requireSsl": True})))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_encrypted_only_mode_produces_positive_evidence(self):
        result = asyncio.run(CheckCloudSqlSsl().execute(self._session({"sslMode": "ENCRYPTED_ONLY"})))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_ssl_enforcement_produces_finding(self):
        result = asyncio.run(CheckCloudSqlSsl().execute(self._session({})))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckDiskEncryption:
    @pytest.fixture
    def disks_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "DisksClient", lambda credentials: client)
        return client

    def _wire(self, disks_client: MagicMock, status: str) -> None:
        disk = SimpleNamespace(name="disk-1", self_link="", status=status)
        scoped = SimpleNamespace(disks=[disk])
        disks_client.aggregated_list.return_value = [("zones/europe-west3-a", scoped)]

    def test_ready_disk_produces_positive_evidence(self, disks_client: MagicMock):
        self._wire(disks_client, status="READY")

        result = asyncio.run(CheckDiskEncryption().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_failed_disk_produces_finding(self, disks_client: MagicMock):
        self._wire(disks_client, status="FAILED")

        result = asyncio.run(CheckDiskEncryption().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_creating_disk_produces_low_severity_reservation_finding(self, disks_client: MagicMock):
        # B-Nr.8-15: non-READY states are a LOW-severity reservation, not a
        # HIGH-severity defect claim about missing encryption.
        self._wire(disks_client, status="CREATING")

        result = asyncio.run(CheckDiskEncryption().execute(FakeGcpSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        assert maengel[0].severity.value == "LOW"
        assert maengel[0].title == "Disk-Zustand nicht READY — Verschlüsselungsnachweis nicht verifizierbar"

    def test_missing_disk_status_produces_checkerror(self, disks_client: MagicMock):
        self._wire(disks_client, status="")

        result = asyncio.run(CheckDiskEncryption().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "UnverifiableState"


class TestCheckCertificateManager:
    def _session(self, expire_time: datetime) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.locations.return_value.certificates.return_value
        chain.list.return_value.execute.return_value = {
            "certificates": [
                {
                    "name": "cert-1",
                    "expireTime": expire_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            ]
        }
        return FakeGcpSession(services={"certificatemanager": svc})

    def test_valid_certificate_produces_positive_evidence(self):
        session = self._session(datetime.now(UTC) + timedelta(days=60))

        result = asyncio.run(CheckCertificateManager().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_expired_certificate_produces_finding(self):
        session = self._session(datetime.now(UTC) - timedelta(days=1))

        result = asyncio.run(CheckCertificateManager().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
