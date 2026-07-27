"""Configuration module for Rapid7 Vulnerability Export.

This module handles loading and validating configuration from environment variables.
"""

import os
from typing import Dict, Optional

USER_AGENT = "r7:bulk-export-mcp"


# Region to endpoint mapping as specified in the design document
REGION_ENDPOINTS = {
    "us": "https://us.api.insight.rapid7.com/export/graphql",
    "us2": "https://us2.api.insight.rapid7.com/export/graphql",
    "us3": "https://us3.api.insight.rapid7.com/export/graphql",
    "eu": "https://eu.api.insight.rapid7.com/export/graphql",
    "ca": "https://ca.api.insight.rapid7.com/export/graphql",
    "au": "https://au.api.insight.rapid7.com/export/graphql",
    "ap": "https://ap.api.insight.rapid7.com/export/graphql",
}


def load_config(organization_id: Optional[str] = None) -> Dict[str, str]:
    """Load and validate configuration from environment variables.

    Reads the RAPID7_REGION environment variable and picks which API key to
    use based on whether an organization_id was requested:

    - organization_id omitted: RAPID7_API_KEY (a regular, single-tenant key).
    - organization_id provided: RAPID7_MULTI_TENANT_API_KEY (a Rapid7
      Multi-Tenant Admin/User key, which requires the R7-Organization-Id
      header on every request and has no default-org fallback of its own).

    Args:
        organization_id: Optional Rapid7 customer/tenant org ID to scope this
            request to. When provided, selects the multi-tenant key and is
            carried through in the returned dict for callers to send as the
            R7-Organization-Id header.

    Returns:
        dict: Configuration dictionary containing:
            - api_key (str): The API key for authentication
            - region (str): The region identifier
            - endpoint (str): The full API endpoint URL
            - organization_id (str): The requested org ID, or "" if omitted

    Raises:
        ValueError: If the relevant API key env var is not set
        ValueError: If region is not in the valid list
    """
    # Read region from environment (default to 'us')
    region = os.environ.get("RAPID7_REGION", "us")

    # Validate region and get endpoint
    if region not in REGION_ENDPOINTS:
        valid_regions = ", ".join(sorted(REGION_ENDPOINTS.keys()))
        raise ValueError(f"Invalid region: {region}. Valid regions are: {valid_regions}")

    endpoint = REGION_ENDPOINTS[region]

    if organization_id:
        api_key = os.environ.get("RAPID7_MULTI_TENANT_API_KEY")
        if not api_key:
            raise ValueError(
                "RAPID7_MULTI_TENANT_API_KEY environment variable is not set "
                "(required when organization_id is provided)"
            )
    else:
        api_key = os.environ.get("RAPID7_API_KEY")
        if not api_key:
            raise ValueError("RAPID7_API_KEY environment variable is not set")

    return {
        "api_key": api_key,
        "region": region,
        "endpoint": endpoint,
        "organization_id": organization_id or "",
    }
