"""Unit tests for the organizations client module."""

import pytest
import requests
import responses

from src.organizations_client import filter_by_region, get_managed_organizations

ENDPOINT = "https://us.api.insight.rapid7.com/account/api/1/managed-organizations"


class TestGetManagedOrganizations:
    """Tests for get_managed_organizations()."""

    @responses.activate
    def test_single_page_returns_all_orgs(self):
        responses.add(
            responses.GET,
            ENDPOINT,
            json={
                "data": [
                    {"id": "org-1", "name": "Acme Co", "region": "us"},
                    {"id": "org-2", "name": "Beta LLC", "region": "us"},
                ],
                "metadata": {"index": 0, "size": 20, "total_data": 2, "total_pages": 1},
            },
            status=200,
        )

        result = get_managed_organizations("key", "us", "parent-org-id")

        assert len(result) == 2
        assert result[0]["name"] == "Acme Co"
        assert len(responses.calls) == 1

    @responses.activate
    def test_multi_page_aggregates_all_pages(self):
        responses.add(
            responses.GET,
            ENDPOINT,
            json={
                "data": [{"id": "org-1", "name": "A", "region": "us"}],
                "metadata": {"index": 0, "size": 1, "total_data": 2, "total_pages": 2},
            },
            status=200,
        )
        responses.add(
            responses.GET,
            ENDPOINT,
            json={
                "data": [{"id": "org-2", "name": "B", "region": "us"}],
                "metadata": {"index": 1, "size": 1, "total_data": 2, "total_pages": 2},
            },
            status=200,
        )

        result = get_managed_organizations("key", "us", "parent-org-id", page_size=1)

        assert len(result) == 2
        assert [o["id"] for o in result] == ["org-1", "org-2"]
        assert len(responses.calls) == 2
        assert "index=0" in responses.calls[0].request.url
        assert "index=1" in responses.calls[1].request.url

    @responses.activate
    def test_bare_list_response_handled_defensively(self):
        responses.add(
            responses.GET,
            ENDPOINT,
            json=[{"id": "org-1", "name": "A", "region": "us"}],
            status=200,
        )

        result = get_managed_organizations("key", "us", "parent-org-id")

        assert result == [{"id": "org-1", "name": "A", "region": "us"}]
        assert len(responses.calls) == 1  # no further pagination attempted

    def test_invalid_region_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid region"):
            get_managed_organizations("key", "not-a-region", "parent-org-id")

    @responses.activate
    def test_401_raises_http_error(self):
        responses.add(responses.GET, ENDPOINT, json={"error": "Unauthorized"}, status=401)
        with pytest.raises(requests.HTTPError):
            get_managed_organizations("key", "us", "parent-org-id")

    @responses.activate
    def test_403_raises_http_error(self):
        responses.add(responses.GET, ENDPOINT, json={"error": "Forbidden"}, status=403)
        with pytest.raises(requests.HTTPError):
            get_managed_organizations("key", "us", "parent-org-id")

    @responses.activate
    def test_network_error_raises_request_exception(self):
        responses.add(
            responses.GET, ENDPOINT, body=requests.exceptions.ConnectionError("failed")
        )
        with pytest.raises(requests.exceptions.ConnectionError):
            get_managed_organizations("key", "us", "parent-org-id")

    @responses.activate
    def test_empty_result_returns_empty_list(self):
        responses.add(
            responses.GET,
            ENDPOINT,
            json={"data": [], "metadata": {"index": 0, "size": 20, "total_data": 0, "total_pages": 0}},
            status=200,
        )

        result = get_managed_organizations("key", "us", "parent-org-id")

        assert result == []
        assert len(responses.calls) == 1

    @responses.activate
    def test_headers_are_set_correctly(self):
        responses.add(
            responses.GET,
            ENDPOINT,
            json={"data": [], "metadata": {"total_pages": 1}},
            status=200,
        )

        get_managed_organizations("my-key", "us", "my-parent-org")

        req = responses.calls[0].request
        assert req.headers["X-Api-Key"] == "my-key"
        assert req.headers["R7-Organization-Id"] == "my-parent-org"
        assert req.headers["User-Agent"] == "r7:bulk-export-mcp"


class TestFilterByRegion:
    """Tests for filter_by_region()."""

    ORGS = [
        {"id": "org-1", "name": "A", "region": "eu"},
        {"id": "org-2", "name": "B", "region": "us"},
        {"id": "org-3", "name": "C", "region": "EU"},
        {"id": "org-4", "name": "D"},
    ]

    def test_filters_case_insensitively(self):
        result = filter_by_region(self.ORGS, "eu")
        assert [o["id"] for o in result] == ["org-1", "org-3"]

    def test_no_match_returns_empty_list(self):
        assert filter_by_region(self.ORGS, "ap") == []

    def test_missing_region_field_excluded(self):
        result = filter_by_region(self.ORGS, "us")
        assert [o["id"] for o in result] == ["org-2"]
