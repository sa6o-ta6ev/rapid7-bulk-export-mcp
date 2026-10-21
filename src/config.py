"""Configuration module for Rapid7 Vulnerability Export.

This module handles loading and validating configuration from environment variables.
"""

import os
import platform
import subprocess  # nosec B404
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


def _get_key_from_keychain(service_name: str) -> Optional[str]:
    """Retrieve a password from macOS Keychain.

    Uses the `security find-generic-password` command to look up a stored
    credential by service name. Only available on macOS.

    Args:
        service_name: The service name used when storing the credential.

    Returns:
        The password string if found, None otherwise.
    """
    if platform.system() != "Darwin":
        return None

    try:
        result = subprocess.run(  # nosec B603 B607
            ["security", "find-generic-password", "-s", service_name, "-w"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        value = result.stdout.strip()
        return value if value else None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


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

    On macOS, if RAPID7_API_KEY is not found in the environment (single-tenant
    mode only — organization_id omitted), falls back to reading from the
    macOS Keychain. Store credentials with:

        security add-generic-password -s RAPID7_API_KEY -a rapid7 -w <your-key>

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

        # Fall back to macOS Keychain if not in environment
        if not api_key:
            api_key = _get_key_from_keychain("RAPID7_API_KEY")

        if not api_key:
            raise ValueError(
                "RAPID7_API_KEY not found. Set the environment variable or, on macOS, "
                "store it in Keychain: "
                "security add-generic-password -s RAPID7_API_KEY -a rapid7 -w <your-key>"
            )

    return {
        "api_key": api_key,
        "region": region,
        "endpoint": endpoint,
        "organization_id": organization_id or "",
    }


def load_parent_organization_config() -> Dict[str, str]:
    """Load config for calling Rapid7 APIs as the parent/primary account.

    Used only by organizations_client.get_managed_organizations(). This is
    architecturally distinct from load_config(): that function scopes a
    request to a *target* tenant via an R7-Organization-Id header carrying
    the tenant's own id, whereas this one authenticates *as* the parent
    account itself — whose org id has no self-lookup/whoami endpoint in the
    Rapid7 API, so it must come from configuration.

    Reads:
        RAPID7_MULTI_TENANT_API_KEY: required.
        RAPID7_REGION: optional, defaults to "us", validated against
            REGION_ENDPOINTS (same valid set as load_config uses).
        RAPID7_PARENT_ORG_ID: required — the primary/parent
            account's own organization id (NOT a managed tenant's id).

    Returns:
        dict: {"api_key": str, "region": str, "parent_organization_id": str}

    Raises:
        ValueError: If RAPID7_MULTI_TENANT_API_KEY or
            RAPID7_PARENT_ORG_ID is unset, or region is invalid.
    """
    region = os.environ.get("RAPID7_REGION", "us")
    if region not in REGION_ENDPOINTS:
        valid_regions = ", ".join(sorted(REGION_ENDPOINTS.keys()))
        raise ValueError(f"Invalid region: {region}. Valid regions are: {valid_regions}")

    api_key = os.environ.get("RAPID7_MULTI_TENANT_API_KEY")
    if not api_key:
        raise ValueError(
            "RAPID7_MULTI_TENANT_API_KEY environment variable is not set (required to list managed organizations)"
        )

    parent_organization_id = os.environ.get("RAPID7_PARENT_ORG_ID")
    if not parent_organization_id:
        raise ValueError(
            "RAPID7_PARENT_ORG_ID environment variable is not set "
            "(this is your primary/parent account's own organization id, "
            "not a managed tenant's id)"
        )

    return {
        "api_key": api_key,
        "region": region,
        "parent_organization_id": parent_organization_id,
    }
