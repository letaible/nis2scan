"""Tests for §30 Nr. 5 — Schwachstellenmanagement GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr5_schwachstellen import (
    CheckArtifactRegistryScanning,
    CheckContainerAnalysis,
    CheckGkeNodeVersions,
    CheckOsConfigPatchManagement,
    CheckWebSecurityScanner,
)

from .conftest import PROJECT_ID, FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckContainerAnalysis:
    def _session(self, occurrences: int) -> tuple[FakeGcpSession, MagicMock]:
        svc = MagicMock()
        svc.projects.return_value.occurrences.return_value.list.return_value.execute.return_value = {
            "occurrences": [{"name": f"occ-{i}"} for i in range(occurrences)]
        }
        return FakeGcpSession(services={"containeranalysis": svc}), svc

    def test_discovery_occurrences_produce_positive_evidence_even_without_vulnerabilities(self):
        # B-Nr.5-14: DISCOVERY occurrences (scans performed) are the correct
        # evidence — not VULNERABILITY occurrences (which depend on findings).
        session, svc = self._session(occurrences=1)

        result = asyncio.run(CheckContainerAnalysis().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

        _, kwargs = svc.projects.return_value.occurrences.return_value.list.call_args
        assert kwargs["filter"] == 'kind="DISCOVERY"'

    def test_no_discovery_occurrences_produces_finding(self):
        session, _ = self._session(occurrences=0)

        result = asyncio.run(CheckContainerAnalysis().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckOsConfigPatchManagement:
    def _session(self, deployments: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.patchDeployments.return_value.list.return_value.execute.return_value = {
            "patchDeployments": [{"name": f"pd-{i}"} for i in range(deployments)]
        }
        return FakeGcpSession(services={"osconfig": svc})

    def test_deployments_produce_positive_evidence(self):
        result = asyncio.run(CheckOsConfigPatchManagement().execute(self._session(deployments=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_deployments_produces_finding(self):
        result = asyncio.run(CheckOsConfigPatchManagement().execute(self._session(deployments=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckWebSecurityScanner:
    def _session(self, configs: int) -> FakeGcpSession:
        svc = MagicMock()
        svc.projects.return_value.scanConfigs.return_value.list.return_value.execute.return_value = {
            "scanConfigs": [{"name": f"sc-{i}"} for i in range(configs)]
        }
        return FakeGcpSession(services={"websecurityscanner": svc})

    def test_configs_produce_positive_evidence(self):
        result = asyncio.run(CheckWebSecurityScanner().execute(self._session(configs=1)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_configs_produces_finding(self):
        result = asyncio.run(CheckWebSecurityScanner().execute(self._session(configs=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckArtifactRegistryScanning:
    def _session(self, repos: int, locations: list[str] | None = None) -> FakeGcpSession:
        # Real-shape mock (SDK-Fix-Paket 27.07.2026, GCP-NR5-004): Artifact
        # Registry does not support the "-" location wildcard (real-API-verified:
        # the server rejects it with 400 "Invalid project name") — locations must
        # be enumerated via projects().locations().list() first, then queried
        # one at a time via projects().locations().repositories().list().
        locations = locations or ["europe-west3"]
        svc = MagicMock()
        svc.projects.return_value.locations.return_value.list.return_value.execute.return_value = {
            "locations": [{"locationId": loc} for loc in locations]
        }
        chain = svc.projects.return_value.locations.return_value.repositories.return_value
        chain.list.return_value.execute.return_value = {"repositories": [{"name": f"repo-{i}"} for i in range(repos)]}
        return FakeGcpSession(services={"artifactregistry": svc})

    def test_repositories_produce_positive_evidence(self):
        result = asyncio.run(CheckArtifactRegistryScanning().execute(self._session(repos=2)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_repositories_produces_finding(self):
        result = asyncio.run(CheckArtifactRegistryScanning().execute(self._session(repos=0)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_repositories_are_queried_per_enumerated_location_not_wildcard(self):
        session = self._session(repos=0, locations=["europe-west3", "us-central1"])
        service = session.service("artifactregistry")
        chain = service.projects.return_value.locations.return_value.repositories.return_value

        asyncio.run(CheckArtifactRegistryScanning().execute(session))

        parents = [call.kwargs["parent"] for call in chain.list.call_args_list]
        assert f"projects/{PROJECT_ID}/locations/europe-west3" in parents
        assert f"projects/{PROJECT_ID}/locations/us-central1" in parents
        assert not any(p.endswith("/locations/-") for p in parents)

    def test_one_failing_location_does_not_discard_other_locations_evidence(self):
        # ADR-0016 fail-safe: a failure listing repositories in one of the ~45
        # Artifact Registry locations must become its own CheckError (with
        # region context) and must not wipe out repositories already found in
        # other locations.
        session = self._session(repos=0, locations=["broken-region", "europe-west3"])
        service = session.service("artifactregistry")
        chain = service.projects.return_value.locations.return_value.repositories.return_value

        def list_repositories(**kwargs):
            execute_mock = MagicMock()
            if kwargs.get("parent", "").endswith("broken-region"):
                execute_mock.execute.side_effect = RuntimeError("boom")
            else:
                execute_mock.execute.return_value = {"repositories": [{"name": "repo-1"}]}
            return execute_mock

        chain.list.side_effect = list_repositories

        result = asyncio.run(CheckArtifactRegistryScanning().execute(session))

        assert len(_compliant(result)) == 1
        region_errors = [e for e in result.errors if e.region == "broken-region"]
        assert len(region_errors) == 1
        assert region_errors[0].error_type == "RuntimeError"


class TestCheckGkeNodeVersions:
    @pytest.fixture
    def gke_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import container_v1

        client = MagicMock()
        monkeypatch.setattr(container_v1, "ClusterManagerClient", lambda credentials: client)
        return client

    def _cluster(self, master: str, node: str) -> SimpleNamespace:
        return SimpleNamespace(
            name="cluster-1",
            location="europe-west3",
            current_master_version=master,
            current_node_version=node,
        )

    def test_current_node_version_produces_positive_evidence(self, gke_client: MagicMock):
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster("1.29.1", "1.29.1")])

        result = asyncio.run(CheckGkeNodeVersions().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_outdated_node_version_produces_finding(self, gke_client: MagicMock):
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster("1.29.1", "1.28.3")])

        result = asyncio.run(CheckGkeNodeVersions().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_double_digit_patch_version_compared_numerically_not_lexicographically(self, gke_client: MagicMock):
        # B-Nr.5-18: "1.28.9" < "1.28.15" numerically, but lexicographic string
        # comparison would wrongly rank "1.28.9" as newer (since "9" > "1").
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster("1.28.15", "1.28.9")])

        result = asyncio.run(CheckGkeNodeVersions().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_unparseable_version_produces_check_error(self, gke_client: MagicMock):
        gke_client.list_clusters.return_value = SimpleNamespace(clusters=[self._cluster("1.29.1", "not-a-version")])

        result = asyncio.run(CheckGkeNodeVersions().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
