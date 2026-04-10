"""UniFi Cloud API helpers for fetching security events."""

import os
import requests

UNIFI_API_URL = "https://api.ui.com"
DEFAULT_SITE_ID = "65e9d7477c472e0db9364385"


def get_headers():
    api_key = os.environ.get("UNIFI_API_KEY", "")
    if not api_key:
        raise ValueError("UNIFI_API_KEY environment variable not set")
    return {"X-API-KEY": api_key, "Accept": "application/json"}


def get_site_id():
    return os.environ.get("UNIFI_SITE_ID", DEFAULT_SITE_ID)


def fetch_security_events(site_id=None, since_ms=None, limit=500):
    """Fetch security/network events from UniFi Cloud API.
    
    Args:
        site_id: Site ID (default from env or constant)
        since_ms: Epoch timestamp in milliseconds to filter from
        limit: Max events to fetch
    
    Returns:
        list of event dicts from UniFi API
    """
    site_id = site_id or get_site_id()
    headers = get_headers()
    
    url = f"{UNIFI_API_URL}/ea/sites/{site_id}/events"
    params = {"_limit": limit}
    if since_ms:
        params["_start"] = since_ms
    
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_firewall_events(site_id=None, since_ms=None, limit=500):
    """Fetch firewall/routing events."""
    site_id = site_id or get_site_id()
    headers = get_headers()
    
    url = f"{UNIFI_API_URL}/ea/sites/{site_id}/firewall-policies"
    params = {"_limit": limit}
    if since_ms:
        params["_start"] = since_ms
    
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_active_clients(site_id=None):
    """Fetch currently connected clients."""
    site_id = site_id or get_site_id()
    headers = get_headers()
    
    url = f"{UNIFI_API_URL}/ea/sites/{site_id}/clients/active"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()
