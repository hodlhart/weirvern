"""The console's server-side call to the mTLS gateway, with the install service credential.

WHY THE CONSOLE DOES NOT TALK TO THE WEIRLING. A weirling is an outbound-only client: the hub
cannot open a connection to it. So an install is a request the gateway holds in memory (five
minutes, never a table) and the target unit picks up on its next authenticated poll. The console
only ever speaks to the gateway, over the cluster network, and only with the single-scope
credential mounted into its pod.

THE PASSWORD IS FORWARDED, NOT KEPT. It travels in this request body to the gateway, which
hands it to the weirling once. Nothing here logs a body, and `requests` does not echo one.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests


class GatewayUnavailable(Exception):
    """The gateway cannot be reached, or the service credential is not mounted."""


def _base(settings) -> str:
    base = str(getattr(settings, "gateway_url", "") or "").strip().rstrip("/")
    if not base:
        raise GatewayUnavailable(
            "the install service is not configured on this console (WEIRVERN_GATEWAY_URL is unset)")
    return base


def _call(settings, method: str, path: str, payload: dict[str, Any] | None = None
          ) -> tuple[int, dict[str, Any]]:
    token = str(getattr(settings, "scan_install_token", "") or "")
    if not token:
        raise GatewayUnavailable(
            "the install service credential is not mounted into this console "
            "(WEIRVERN_SCAN_INSTALL_TOKEN is unset)")
    ca = str(getattr(settings, "gateway_ca", "") or "").strip() or True
    try:
        response = requests.request(
            method, _base(settings) + path, json=payload, timeout=15, verify=ca,
            headers={"X-Weirvern-Scan-Install": token, "Accept": "application/json"},
        )
    except requests.RequestException as exc:
        raise GatewayUnavailable(f"the gateway could not be reached: {exc}") from exc
    try:
        body = response.json()
    except ValueError:
        body = {"ok": False, "error": f"the gateway answered {response.status_code} without JSON"}
    return response.status_code, body if isinstance(body, dict) else {"ok": False}


def install_create(settings, *, host_id: str, family: str, version: str, reason: str,
                   actor: str, sudo_password: str | None = None
                   ) -> tuple[int, dict[str, Any]]:
    payload: dict[str, Any] = {
        "host_id": host_id, "distro_family": family, "distro_version": version,
        "reason": reason, "actor": actor,
    }
    if sudo_password:
        payload["sudo_password"] = sudo_password
    return _call(settings, "POST", "/v1/scan/install", payload)


def install_status(settings, request_id: str) -> tuple[int, dict[str, Any]]:
    return _call(settings, "GET", f"/v1/scan/install/{quote(str(request_id or ''), safe='')}")
