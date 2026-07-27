"""Tests for §30 Nr. 4 — Lieferkette GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr4_lieferkette import (
    CheckBinaryAuthorization,
    CheckCrossProjectBindings,
    CheckServiceAccountKeys,
    CheckVpcServiceControlsSupplyChain,
    CheckWorkloadIdentity,
)

from .conftest import PROJECT_ID, FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckCrossProjectBindings:
    def _session(self, external: bool) -> FakeGcpSession:
        member = (
            "serviceAccount:vendor@other-project.iam.gserviceaccount.com"
            if external
            else f"serviceAccount:app@{PROJECT_ID}.iam.gserviceaccount.com"
        )
        svc = MagicMock()
        svc.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [{"role": "roles/editor", "members": [member]}]
        }
        return FakeGcpSession(services={"cloudresourcemanager": svc})

    def test_no_external_bindings_produces_positive_evidence(self):
        result = asyncio.run(CheckCrossProjectBindings().execute(self._session(external=False)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_external_binding_produces_finding(self):
        result = asyncio.run(CheckCrossProjectBindings().execute(self._session(external=True)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def _session_with_member(self, member: str) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [{"role": "roles/editor", "members": [member]}]
        }
        return FakeGcpSession(services={"cloudresourcemanager": svc})

    def test_provider_managed_compute_default_sa_is_not_external(self):
        # Compute Engine default SA (developer.gserviceaccount.com) must never be
        # flagged as a foreign-project relationship (B-Nr.4-14).
        session = self._session_with_member("serviceAccount:12345-compute@developer.gserviceaccount.com")

        result = asyncio.run(CheckCrossProjectBindings().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_foreign_project_iam_service_account_is_external(self):
        # A user-managed SA on a project not in session.project_ids IS external.
        session = self._session_with_member("serviceAccount:x@fremdprojekt.iam.gserviceaccount.com")

        result = asyncio.run(CheckCrossProjectBindings().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_gcp_sa_service_agent_is_not_external(self):
        # Google-managed service agents (service-<nr>@gcp-sa-<service>.iam...) must
        # never be flagged as foreign-project relationships (R-5).
        session = self._session_with_member("serviceAccount:service-12345@gcp-sa-pubsub.iam.gserviceaccount.com")

        result = asyncio.run(CheckCrossProjectBindings().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_external_member_evidence_key_is_pseudonymized_on_extern_export(self):
        # CODE-1 (ADR-0011 deny-list): the raw external member — a service
        # account e-mail — must live under a current_state key ending in
        # _name/_id/_arn/_email, or the EXTERN report profile leaks it verbatim.
        member = "serviceAccount:vendor@other-project.iam.gserviceaccount.com"
        session = self._session_with_member(member)

        result = asyncio.run(CheckCrossProjectBindings().execute(session))
        finding = _maengel(result)[0]

        assert finding.current_state["external_member_email"] == [member]
        assert "external_members_sample" not in finding.current_state

        from nis2scan.engine.models.config import ScanConfig
        from nis2scan.engine.models.result import ScanResult
        from nis2scan.reporting.pseudonymize import pseudonymize_result

        scan_result = ScanResult(scan_id="test", config=ScanConfig(), findings=[finding])
        pseudonymized = pseudonymize_result(scan_result).findings[0]

        pseudonymized_members = pseudonymized.current_state["external_member_email"]
        assert pseudonymized_members != [member]
        assert all(m.startswith("pseu_") for m in pseudonymized_members)
        assert "vendor@other-project" not in str(pseudonymized.current_state)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(external=False)
        service = session.service("cloudresourcemanager", "v1")
        service.projects.return_value.getIamPolicy.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckCrossProjectBindings().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckServiceAccountKeys:
    def _session(self, user_keys: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.serviceAccounts.return_value.list.return_value.execute.return_value = {
            "accounts": [
                {
                    "email": f"app@{PROJECT_ID}.iam.gserviceaccount.com",
                    "name": f"projects/{PROJECT_ID}/serviceAccounts/app",
                }
            ]
        }
        keys = svc.projects.return_value.serviceAccounts.return_value.keys.return_value
        keys.list.return_value.execute.return_value = {"keys": [{"name": f"key-{i}"} for i in range(user_keys)]}
        return FakeGcpSession(services={"iam": svc})

    def test_no_user_keys_produces_positive_evidence(self):
        result = asyncio.run(CheckServiceAccountKeys().execute(self._session(user_keys=0)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_user_keys_produce_finding(self):
        result = asyncio.run(CheckServiceAccountKeys().execute(self._session(user_keys=2)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(user_keys=0)
        service = session.service("iam", "v1")
        service.projects.return_value.serviceAccounts.return_value.list.return_value.execute.side_effect = RuntimeError(
            "boom"
        )

        result = asyncio.run(CheckServiceAccountKeys().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckWorkloadIdentity:
    @pytest.fixture
    def gke_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import container_v1

        client = MagicMock()
        monkeypatch.setattr(container_v1, "ClusterManagerClient", lambda credentials: client)
        return client

    def _cluster(self, wi: bool) -> SimpleNamespace:
        return SimpleNamespace(
            name="cluster-1",
            location="europe-west3",
            workload_identity_config=(SimpleNamespace(workload_pool=f"{PROJECT_ID}.svc.id.goog") if wi else None),
        )

    def test_workload_identity_produces_positive_evidence(self, gke_client: MagicMock):
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster(wi=True)])

        result = asyncio.run(CheckWorkloadIdentity().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_missing_workload_identity_produces_finding(self, gke_client: MagicMock):
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster(wi=False)])

        result = asyncio.run(CheckWorkloadIdentity().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, gke_client: MagicMock):
        gke_client.list_clusters.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckWorkloadIdentity().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckBinaryAuthorization:
    def _session(self, mode: str) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.getPolicy.return_value.execute.return_value = {
            "defaultAdmissionRule": {"evaluationMode": mode}
        }
        return FakeGcpSession(services={"binaryauthorization": svc})

    def test_require_attestation_produces_positive_evidence(self):
        result = asyncio.run(CheckBinaryAuthorization().execute(self._session("REQUIRE_ATTESTATION")))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_always_allow_produces_finding(self):
        result = asyncio.run(CheckBinaryAuthorization().execute(self._session("ALWAYS_ALLOW")))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session("ALWAYS_ALLOW")
        service = session.service("binaryauthorization", "v1")
        service.projects.return_value.getPolicy.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckBinaryAuthorization().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"

    def test_get_policy_name_has_policy_suffix(self):
        # Real-API-verified 27.07.2026 (SDK-Fix-Paket, GCP-NR4-004): the API
        # requires the resource name to match "^projects/[^/]+/policy$" — a bare
        # "projects/<id>" raises a client-side TypeError before any request is
        # sent. See the real-shape guard test below for the pattern itself.
        session = self._session("ALWAYS_ALLOW")
        service = session.service("binaryauthorization", "v1")

        asyncio.run(CheckBinaryAuthorization().execute(session))

        _, kwargs = service.projects.return_value.getPolicy.call_args
        assert kwargs["name"] == f"projects/{PROJECT_ID}/policy"

    def test_real_discovery_doc_requires_policy_suffix_on_name(self):
        # Real-shape guard: builds from the googleapiclient-bundled static
        # discovery document (no network call) and asserts on the actual
        # binaryauthorization v1 parameter pattern for getPolicy.
        import re

        from googleapiclient.discovery import build

        service = build(
            "binaryauthorization", "v1", credentials=MagicMock(), cache_discovery=False, static_discovery=True
        )
        method_doc = service._rootDesc["resources"]["projects"]["methods"]["getPolicy"]
        pattern = method_doc["parameters"]["name"]["pattern"]
        assert re.fullmatch(pattern, f"projects/{PROJECT_ID}/policy")
        assert not re.fullmatch(pattern, f"projects/{PROJECT_ID}")


class TestCheckVpcServiceControlsSupplyChain:
    def _session(self, perimeters: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.accessPolicies.return_value.list.return_value.execute.return_value = {
            "accessPolicies": [{"name": "accessPolicies/1"}]
        }
        svc.accessPolicies.return_value.servicePerimeters.return_value.list.return_value.execute.return_value = {
            "servicePerimeters": [{"name": f"p-{i}"} for i in range(perimeters)]
        }
        return FakeGcpSession(services={"accesscontextmanager": svc})

    def test_perimeter_produces_positive_evidence(self):
        result = asyncio.run(CheckVpcServiceControlsSupplyChain().execute(self._session(perimeters=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_perimeter_produces_finding(self):
        result = asyncio.run(CheckVpcServiceControlsSupplyChain().execute(self._session(perimeters=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(perimeters=0)
        service = session.service("accesscontextmanager", "v1")
        service.accessPolicies.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckVpcServiceControlsSupplyChain().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
