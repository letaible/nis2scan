"""Tests for §30 Nr. 9 — Zugriffskontrolle GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr9_zugriffskontrolle import (
    CheckIamLeastPrivilege,
    CheckIdentityAwareProxy,
    CheckInactivePrincipals,
    CheckOrgConstraints,
    CheckServiceAccountHygiene,
    CheckStorageBucketPublicAccess,
    CheckVpcFirewallRules,
    CheckVpcServiceControls,
)

from .conftest import PROJECT_ID, FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckIamLeastPrivilege:
    def _session(self, bindings: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.getIamPolicy.return_value.execute.return_value = {"bindings": bindings}
        return FakeGcpSession(services={"cloudresourcemanager": svc})

    def test_specific_roles_produce_positive_evidence(self):
        session = self._session([{"role": "roles/viewer", "members": ["user:a@example.com"]}])

        result = asyncio.run(CheckIamLeastPrivilege().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["broad_role_bindings"] == 0
        assert not _maengel(result)

    def test_owner_role_produces_finding(self):
        session = self._session([{"role": "roles/owner", "members": ["user:a@example.com"]}])

        result = asyncio.run(CheckIamLeastPrivilege().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("cloudresourcemanager", "v1")
        service.projects.return_value.getIamPolicy.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckIamLeastPrivilege().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckServiceAccountHygiene:
    def _session(self, keys: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        sa_chain = svc.projects.return_value.serviceAccounts.return_value
        sa_chain.list.return_value.execute.return_value = {
            "accounts": [{"email": f"sa@{PROJECT_ID}.iam.gserviceaccount.com", "name": "projects/p/serviceAccounts/sa"}]
        }
        sa_chain.keys.return_value.list.return_value.execute.return_value = {"keys": keys}
        return FakeGcpSession(services={"iam": svc})

    @staticmethod
    def _key(age_days: int) -> dict:
        created = datetime.now(UTC) - timedelta(days=age_days)
        return {"name": "key-1", "validAfterTime": created.strftime("%Y-%m-%dT%H:%M:%SZ")}

    def test_fresh_key_produces_positive_evidence(self):
        result = asyncio.run(CheckServiceAccountHygiene().execute(self._session([self._key(age_days=10)])))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["key_age_days"] == 10
        assert not _maengel(result)

    def test_keyless_service_account_produces_positive_evidence(self):
        result = asyncio.run(CheckServiceAccountHygiene().execute(self._session([])))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["user_managed_keys"] == 0
        assert not _maengel(result)

    def test_old_key_produces_finding(self):
        result = asyncio.run(CheckServiceAccountHygiene().execute(self._session([self._key(age_days=200)])))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("iam", "v1")
        sa_chain = service.projects.return_value.serviceAccounts.return_value
        sa_chain.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckServiceAccountHygiene().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckIdentityAwareProxy:
    def _session(self, bindings: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.iap_tunnel.return_value
        chain.getIamPolicy.return_value.execute.return_value = {"bindings": bindings}
        return FakeGcpSession(services={"iap": svc})

    def test_iap_bindings_produce_positive_evidence(self):
        session = self._session([{"role": "roles/iap.tunnelResourceAccessor", "members": ["user:a@example.com"]}])

        result = asyncio.run(CheckIdentityAwareProxy().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_iap_bindings_produces_finding(self):
        result = asyncio.run(CheckIdentityAwareProxy().execute(self._session([])))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_all_users_binding_produces_high_finding(self):
        # B-9-9: a public member (allUsers/allAuthenticatedUsers) is its own
        # HIGH Mangel-Finding, not folded into the generic positive evidence.
        session = self._session([{"role": "roles/iap.tunnelResourceAccessor", "members": ["allUsers"]}])

        result = asyncio.run(CheckIdentityAwareProxy().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert maengel[0].title == "IAP-Zugriff öffentlich freigegeben"
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("iap")
        chain = service.projects.return_value.iap_tunnel.return_value
        chain.getIamPolicy.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckIdentityAwareProxy().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckVpcFirewallRules:
    @pytest.fixture
    def firewalls_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "FirewallsClient", lambda credentials: client)
        return client

    def test_restricted_rule_produces_positive_evidence(self, firewalls_client: MagicMock):
        firewalls_client.list.return_value = [
            SimpleNamespace(
                name="fw-internal",
                direction="INGRESS",
                source_ranges=["10.0.0.0/8"],
                allowed=[SimpleNamespace(ports=["22"])],
            )
        ]

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_open_ssh_rule_produces_finding(self, firewalls_client: MagicMock):
        firewalls_client.list.return_value = [
            SimpleNamespace(
                name="fw-open-ssh",
                direction="INGRESS",
                source_ranges=["0.0.0.0/0"],
                allowed=[SimpleNamespace(ports=["22"])],
            )
        ]

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_open_http_rule_produces_positive_evidence(self, firewalls_client: MagicMock):
        firewalls_client.list.return_value = [
            SimpleNamespace(
                name="fw-http",
                direction="INGRESS",
                source_ranges=["0.0.0.0/0"],
                allowed=[SimpleNamespace(ports=["443"])],
            )
        ]

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_disabled_rule_produces_no_finding(self, firewalls_client: MagicMock):
        # B-9-10: disabled rules are skipped entirely — no finding at all.
        firewalls_client.list.return_value = [
            SimpleNamespace(
                name="fw-open-ssh-disabled",
                direction="INGRESS",
                source_ranges=["0.0.0.0/0"],
                allowed=[SimpleNamespace(ports=["22"])],
                disabled=True,
            )
        ]

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert not result.findings

    def test_deny_rule_produces_no_finding(self, firewalls_client: MagicMock):
        # B-9-10: only ALLOW rules are evaluated — deny-only rules are skipped.
        firewalls_client.list.return_value = [
            SimpleNamespace(
                name="fw-deny-all",
                direction="INGRESS",
                source_ranges=["0.0.0.0/0"],
                allowed=[],
                denied=[SimpleNamespace(ports=["22"])],
            )
        ]

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert not result.findings

    def test_api_error_produces_check_error_no_finding(self, firewalls_client: MagicMock):
        firewalls_client.list.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckVpcFirewallRules().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckStorageBucketPublicAccess:
    @pytest.fixture
    def storage_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import storage

        client = MagicMock()
        monkeypatch.setattr(storage, "Client", lambda credentials, project: client)
        return client

    def _bucket(self, members: list[str]):
        policy = SimpleNamespace(bindings=[{"role": "roles/storage.objectViewer", "members": members}])
        return SimpleNamespace(name="bucket-1", location="EU", get_iam_policy=lambda: policy)

    def test_private_bucket_produces_positive_evidence(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(["user:a@example.com"])]

        result = asyncio.run(CheckStorageBucketPublicAccess().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_public_bucket_produces_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(["allUsers"])]

        result = asyncio.run(CheckStorageBucketPublicAccess().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckStorageBucketPublicAccess().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"

    def test_bucket_with_unreadable_iam_policy_produces_error_not_finding(self, storage_client: MagicMock):
        # FIX4 (ADR-0016): a bucket whose IAM policy can't be read is an
        # unknown state, not a silent skip — it must surface as a CheckError
        # (with bucket/project/region context) and must never yield a
        # COMPLIANT finding for that bucket. Other buckets are unaffected.
        def raise_get_iam_policy():
            raise RuntimeError("permission denied")

        broken_bucket = SimpleNamespace(name="broken-bucket", location="EU", get_iam_policy=raise_get_iam_policy)
        storage_client.list_buckets.return_value = [broken_bucket, self._bucket(["user:a@example.com"])]

        result = asyncio.run(CheckStorageBucketPublicAccess().execute(FakeGcpSession()))

        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
        assert "broken-bucket" in result.errors[0].message
        assert result.errors[0].region == "EU"
        assert not any("broken-bucket" in f.resource_id for f in result.findings)
        assert len(_compliant(result)) == 1


class TestCheckOrgConstraints:
    def _session(self, constraints: list[str], enforced: bool = True) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.policies.return_value.list.return_value.execute.return_value = {
            "policies": [
                {
                    "name": f"projects/{PROJECT_ID}/policies/{c}",
                    "spec": {"rules": [{"enforce": enforced}]},
                }
                for c in constraints
            ]
        }
        return FakeGcpSession(services={"orgpolicy": svc})

    def test_access_constraints_produce_positive_evidence(self):
        session = self._session(["iam.allowedPolicyMemberDomains", "compute.requireOsLogin"])

        result = asyncio.run(CheckOrgConstraints().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["access_control_constraints_found"] == 2
        assert not _maengel(result)

    def test_no_access_constraints_produces_finding(self):
        result = asyncio.run(CheckOrgConstraints().execute(self._session(["gcp.resourceLocations"])))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_policy_without_enforcement_produces_no_erzwingt_evidence(self):
        # B-9-12: a policy present but without enforce=true does not count as
        # "erzwungen" — must not produce positive evidence.
        session = self._session(["iam.allowedPolicyMemberDomains"], enforced=False)

        result = asyncio.run(CheckOrgConstraints().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_list_constraint_with_values_counts_as_active(self):
        # List constraints (e.g. iam.allowedPolicyMemberDomains) are enforced via
        # rules[].values / allowAll / denyAll — never via enforce (Nachprüfung Nr. 9).
        svc = MagicMock()
        svc.projects.return_value.policies.return_value.list.return_value.execute.return_value = {
            "policies": [
                {
                    "name": f"projects/{PROJECT_ID}/policies/iam.allowedPolicyMemberDomains",
                    "spec": {"rules": [{"values": {"allowedValues": ["C0example"]}}]},
                }
            ]
        }
        session = FakeGcpSession(services={"orgpolicy": svc})

        result = asyncio.run(CheckOrgConstraints().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["access_control_constraints_found"] == 1
        assert not _maengel(result)

    def test_allow_all_rule_does_not_count_as_enforcement(self):
        # allowAll neutralises a list constraint (equivalent to the default,
        # typically set to override inherited org restrictions) — it must NOT
        # produce positive evidence (Nachprüfung Nr. 9, allowAll-Restpunkt).
        svc = MagicMock()
        svc.projects.return_value.policies.return_value.list.return_value.execute.return_value = {
            "policies": [
                {
                    "name": f"projects/{PROJECT_ID}/policies/iam.allowedPolicyMemberDomains",
                    "spec": {"rules": [{"allowAll": True}]},
                }
            ]
        }
        session = FakeGcpSession(services={"orgpolicy": svc})

        result = asyncio.run(CheckOrgConstraints().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("orgpolicy", "v2")
        service.projects.return_value.policies.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckOrgConstraints().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckInactivePrincipals:
    def _session(self, recommendations: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.locations.return_value.recommenders.return_value
        chain.recommendations.return_value.list.return_value.execute.return_value = {"recommendations": recommendations}
        return FakeGcpSession(services={"recommender": svc})

    def test_no_unused_access_produces_positive_evidence(self):
        result = asyncio.run(CheckInactivePrincipals().execute(self._session([])))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_remove_recommendation_produces_finding(self):
        recs = [{"name": "rec-1", "recommenderSubtype": "REMOVE_ROLE", "description": "unused access"}]

        result = asyncio.run(CheckInactivePrincipals().execute(self._session(recs)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session([])
        service = session.service("recommender")
        chain = service.projects.return_value.locations.return_value.recommenders.return_value
        chain.recommendations.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckInactivePrincipals().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckVpcServiceControls:
    def _session(self, perimeters: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.accessPolicies.return_value.list.return_value.execute.return_value = {
            "accessPolicies": [{"name": "accessPolicies/1"}]
        }
        svc.accessPolicies.return_value.servicePerimeters.return_value.list.return_value.execute.return_value = {
            "servicePerimeters": [{"name": f"perimeter-{i}"} for i in range(perimeters)]
        }
        return FakeGcpSession(services={"accesscontextmanager": svc})

    def test_perimeter_produces_positive_evidence(self):
        result = asyncio.run(CheckVpcServiceControls().execute(self._session(perimeters=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_perimeter_produces_finding(self):
        result = asyncio.run(CheckVpcServiceControls().execute(self._session(perimeters=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = self._session(perimeters=0)
        service = session.service("accesscontextmanager", "v1")
        service.accessPolicies.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckVpcServiceControls().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
