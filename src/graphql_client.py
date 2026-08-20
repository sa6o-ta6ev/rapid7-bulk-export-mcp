"""
GraphQL Client Module

This module handles GraphQL communication with the Rapid7 Bulk Export API.
It provides functionality to send GraphQL queries and mutations with proper
authentication and error handling.
"""

import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from .config import USER_AGENT

logger = logging.getLogger("graphql_client")

# Transient failures (gateway/server hiccups, rate limiting, network blips) are retried
# with exponential backoff. Non-transient errors (4xx, GraphQL-level errors) are not --
# retrying those would just waste time.
RETRYABLE_STATUS_CODES = {429, 502, 503, 504}
GRAPHQL_MAX_ATTEMPTS = int(os.environ.get("RAPID7_GRAPHQL_MAX_ATTEMPTS", "4"))
GRAPHQL_RETRY_BACKOFF_SECONDS = float(os.environ.get("RAPID7_GRAPHQL_RETRY_BACKOFF_SECONDS", "5"))


def send_graphql_request(
    endpoint: str,
    api_key: str,
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a GraphQL request to the Rapid7 API.

    This function sends a POST request to the specified GraphQL endpoint with
    the provided query and optional variables. It handles authentication via
    the X-Api-Key header and validates the response for both HTTP and GraphQL
    errors.

    Args:
        endpoint: The GraphQL API endpoint URL
        api_key: The API key for authentication
        query: The GraphQL query or mutation string
        variables: Optional dictionary of GraphQL variables
        organization_id: Optional Rapid7 customer/tenant org ID. When
            provided, sent as the R7-Organization-Id header so a Multi-Tenant
            Admin/User API key can target a specific managed tenant.

    Returns:
        The parsed JSON response as a dictionary

    Raises:
        requests.HTTPError: If the HTTP response status code is not 200
        ValueError: If the response contains GraphQL errors
        requests.RequestException: If the network request fails

    Example:
        >>> query = "query { vulnerabilityExport(id: $id) { status } }"
        >>> variables = {"id": "export-123"}
        >>> response = send_graphql_request(endpoint, api_key, query, variables)
    """
    # Set required headers
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if organization_id:
        headers["R7-Organization-Id"] = organization_id

    # Build request body
    body: Dict[str, Any] = {"query": query}
    if variables is not None:
        body["variables"] = variables

    # Send POST request, retrying transient gateway/network errors with backoff
    for attempt in range(1, GRAPHQL_MAX_ATTEMPTS + 1):
        try:
            response = requests.post(endpoint, headers=headers, json=body, timeout=30)
            response.raise_for_status()
            break
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code in RETRYABLE_STATUS_CODES and attempt < GRAPHQL_MAX_ATTEMPTS:
                pass
            else:
                raise
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            if attempt >= GRAPHQL_MAX_ATTEMPTS:
                raise

        sleep_seconds = GRAPHQL_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
        logger.warning(
            "GraphQL request to %s failed (attempt %d/%d), retrying in %.0fs",
            endpoint, attempt, GRAPHQL_MAX_ATTEMPTS, sleep_seconds,
        )
        time.sleep(sleep_seconds)

    # Parse JSON response
    response_data = response.json()

    # Check for GraphQL errors
    if "errors" in response_data:
        error_messages = [error.get("message", str(error)) for error in response_data["errors"]]
        raise ValueError(f"GraphQL errors: {'; '.join(error_messages)}")

    return response_data
