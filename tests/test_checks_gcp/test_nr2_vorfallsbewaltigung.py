"""Tests for §30 Nr. 2 — Vorfallsbewältigung GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr2_vorfallsbewaltigung import (
    CheckLogBasedAlerts,
    CheckLoggingSinks,
    CheckMonitoringAlertPolicies,
    CheckNotificationChannels,
    CheckSccNotifications,
)

from .conftest import FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


@pytest.fixture
def scc_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    from google.cloud import securitycenter_v1

    client = MagicMock()
    monkeypatch.setattr(securitycenter_v1, "SecurityCenterClient", lambda credentials: client)
    return client


@pytest.fixture
def monitoring_clients(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    from google.cloud import monitoring_v3

    client = MagicMock()
    monkeypatch.setattr(monitoring_v3, "AlertPolicyServiceClient", lambda credentials: client)
    monkeypatch.setattr(monitoring_v3, "NotificationChannelServiceClient", lambda credentials: client)
    return client


@pytest.fixture
def logging_clients(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    # SDK-Pin-Verifikation 27.07.2026: `google.cloud.logging_v2` never re-exported
    # these clients at its top level (the old mock patched a name that only existed
    # in the mock, never in the SDK — that's why the check errored for every
    # customer while the test stayed green). The real classes live in the
    # `services.metrics_service_v2` / `services.config_service_v2` submodules.
    from google.cloud.logging_v2.services import config_service_v2, metrics_service_v2

    client = MagicMock()
    monkeypatch.setattr(metrics_service_v2, "MetricsServiceV2Client", lambda credentials: client)
    monkeypatch.setattr(config_service_v2, "ConfigServiceV2Client", lambda credentials: client)
    return client


class TestCheckSccNotifications:
    def test_configs_produce_positive_evidence(self, scc_client: MagicMock):
        scc_client.list_notification_configs.return_value = [SimpleNamespace(name="cfg-1")]

        result = asyncio.run(CheckSccNotifications().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_configs_produces_finding(self, scc_client: MagicMock):
        scc_client.list_notification_configs.return_value = []

        result = asyncio.run(CheckSccNotifications().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, scc_client: MagicMock):
        scc_client.list_notification_configs.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckSccNotifications().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckMonitoringAlertPolicies:
    def test_policies_produce_positive_evidence(self, monitoring_clients: MagicMock):
        monitoring_clients.list_alert_policies.return_value = [SimpleNamespace(name="p-1")]

        result = asyncio.run(CheckMonitoringAlertPolicies().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_policies_produces_finding(self, monitoring_clients: MagicMock):
        monitoring_clients.list_alert_policies.return_value = []

        result = asyncio.run(CheckMonitoringAlertPolicies().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, monitoring_clients: MagicMock):
        monitoring_clients.list_alert_policies.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckMonitoringAlertPolicies().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckNotificationChannels:
    def test_channels_produce_positive_evidence(self, monitoring_clients: MagicMock):
        monitoring_clients.list_notification_channels.return_value = [SimpleNamespace(name="ch-1")]

        result = asyncio.run(CheckNotificationChannels().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_channels_produces_finding(self, monitoring_clients: MagicMock):
        monitoring_clients.list_notification_channels.return_value = []

        result = asyncio.run(CheckNotificationChannels().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, monitoring_clients: MagicMock):
        monitoring_clients.list_notification_channels.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckNotificationChannels().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


def test_real_sdk_logging_v2_never_reexports_service_clients_at_top_level():
    # Regression guard for mock drift (SDK-Pin-Verifikation 27.07.2026, covers
    # GCP-NR2-004 and GCP-NR2-005): `google.cloud.logging_v2.MetricsServiceV2Client`
    # / `.ConfigServiceV2Client` never existed in any installed version — the
    # previous code imported them from there and errored on every real scan, while
    # the unit test mock patched that same nonexistent path with `raising=False`
    # and stayed green. The real classes only live in the `services.*` submodules.
    from google.cloud import logging_v2
    from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
    from google.cloud.logging_v2.services.metrics_service_v2 import MetricsServiceV2Client

    assert not hasattr(logging_v2, "MetricsServiceV2Client")
    assert not hasattr(logging_v2, "ConfigServiceV2Client")
    assert MetricsServiceV2Client.__name__ == "MetricsServiceV2Client"
    assert ConfigServiceV2Client.__name__ == "ConfigServiceV2Client"


class TestCheckLogBasedAlerts:
    def test_metrics_produce_positive_evidence(self, logging_clients: MagicMock):
        logging_clients.list_log_metrics.return_value = [SimpleNamespace(name="m-1")]

        result = asyncio.run(CheckLogBasedAlerts().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_metrics_produces_finding(self, logging_clients: MagicMock):
        logging_clients.list_log_metrics.return_value = []

        result = asyncio.run(CheckLogBasedAlerts().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, logging_clients: MagicMock):
        logging_clients.list_log_metrics.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckLogBasedAlerts().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckLoggingSinks:
    def test_only_builtin_sinks_produce_finding(self, logging_clients: MagicMock):
        """Every GCP project has the built-in _Required/_Default sinks — they must not count."""
        logging_clients.list_sinks.return_value = [
            SimpleNamespace(name="_Required", destination="logging.googleapis.com/projects/p/buckets/_Required"),
            SimpleNamespace(name="_Default", destination="logging.googleapis.com/projects/p/buckets/_Default"),
        ]

        result = asyncio.run(CheckLoggingSinks().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, logging_clients: MagicMock):
        logging_clients.list_sinks.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckLoggingSinks().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"

    def test_custom_sink_with_export_destination_produces_positive_evidence(self, logging_clients: MagicMock):
        logging_clients.list_sinks.return_value = [
            SimpleNamespace(name="_Required", destination="logging.googleapis.com/projects/p/buckets/_Required"),
            SimpleNamespace(name="_Default", destination="logging.googleapis.com/projects/p/buckets/_Default"),
            SimpleNamespace(name="export-sink", destination="storage.googleapis.com/my-export-bucket"),
        ]

        result = asyncio.run(CheckLoggingSinks().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_export_sinks"] == 1
        assert compliant[0].current_state["log_sinks_total"] == 3
        assert not _maengel(result)

    def test_custom_sink_with_other_destination_produces_finding(self, logging_clients: MagicMock):
        """A custom sink whose destination is not storage/bigquery/pubsub still counts as a Mangel."""
        logging_clients.list_sinks.return_value = [
            SimpleNamespace(name="custom-sink", destination="logging.googleapis.com/projects/p/buckets/custom"),
        ]

        result = asyncio.run(CheckLoggingSinks().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
