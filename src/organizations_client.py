"""
Organizations Client Module

This module lists Rapid7-managed organizations (tenants) visible to a
Multi-Tenant parent account, via the Insight Account API's Get Managed
Organizations endpoint (GET /api/1/managed-organizations). It exists so
organization_id values can be discovered live instead of via an out-of-band
tenants.json file.
"""

from typing import Any, Dict, List

import requests

from .config import REGION_ENDPOINTS, USER_AGENT

DEFAULT_PAGE_SIZE = 20
_MAX_PAGES = 500  # safety cap in case pagination metadata is ever unreliable


def get_managed_organizations(
    api_key: str,
    region: str,
    parent_organization_id: str,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> List[Dict[str, Any]]:
    """Fetch the full, aggregated list of Rapid7-managed organizations.

    Calls GET /api/1/managed-organizations on the Insight Account API,
    auto-paginating with size/index query params until every page has been
    retrieved (using metadata.total_pages), and returns the combined list.
    No page params are exposed to callers — this always returns everything.

    Args:
        api_key: Multi-Tenant Admin/User API key (RAPID7_MULTI_TENANT_API_KEY).
        region: Rapid7 region code (e.g. "us", "eu"); validated against
            config.REGION_ENDPOINTS' keys. Note: only the keys are reused
            here — the Account API lives at a different host path
            (/account/api/1/...) than the export API's GraphQL endpoints.
        parent_organization_id: The calling parent/primary account's OWN
            organization id, sent as R7-Organization-Id. This is distinct
            from any managed tenant's id being listed.
        page_size: Page size per request (Rapid7 default is 20).

    Returns:
        List of dicts with "id", "name", "region", and optionally
        "external_id" — one per managed organization.

    Raises:
        ValueError: If region is not a recognized region code.
        requests.HTTPError: If any page request returns a non-2xx status.
        requests.RequestException: If any network request fails.
    """
    if region not in REGION_ENDPOINTS:
        valid_regions = ", ".join(sorted(REGION_ENDPOINTS.keys()))
        raise ValueError(f"Invalid region: {region}. Valid regions are: {valid_regions}")

    url = f"https://{region}.api.insight.rapid7.com/account/api/1/managed-organizations"
    headers = {
        "X-Api-Key": api_key,
        "R7-Organization-Id": parent_organization_id,
        "User-Agent": USER_AGENT,
    }

    organizations: List[Dict[str, Any]] = []
    index = 0

    while True:
        response = requests.get(
            url,
            headers=headers,
            params={"size": page_size, "index": index},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        # Defensive: the OpenAPI spec documents a bare ManagedOrganization
        # (singular) as the response schema, but every other paginated GET
        # in this API family (e.g. getOrganizations) uses
        # {"data": [...], "metadata": {...}}. Handle both shapes.
        if isinstance(payload, list):
            organizations.extend(payload)
            break

        page_items = payload.get("data", [])
        organizations.extend(page_items)

        metadata = payload.get("metadata") or {}
        total_pages = metadata.get("total_pages")

        index += 1
        if total_pages is not None:
            if index >= total_pages:
                break
        elif not page_items or len(page_items) < page_size:
            break  # no trustworthy metadata — short/empty page means done

        if index >= _MAX_PAGES:
            break

    return organizations


def filter_by_region(organizations: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    """Filter a managed-organizations list down to a single region (case-insensitive).

    Args:
        organizations: Result of get_managed_organizations().
        region: Region code to keep (e.g. "eu"). Organizations with no
            "region" field, or a different one, are dropped.

    Returns:
        The subset of organizations whose "region" matches (case-insensitive).
    """
    region_lower = region.lower()
    return [o for o in organizations if str(o.get("region", "")).lower() == region_lower]
