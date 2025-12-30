"""IPFS fetching and gateway utilities."""

import base64
from collections.abc import Iterable

from vaults_economics.cache import cache_key, get_cached, set_cached


def build_gateway_url(gateway: str, cid: str) -> str:
    """Build IPFS gateway URL from base gateway and CID."""
    gw = gateway.rstrip("/")
    # Accept:
    # - https://ipfs.io/ipfs/
    # - https://ipfs.io/ipfs
    # - https://ipfs.io
    if gw.endswith("/ipfs"):
        return f"{gw}/{cid}"
    if "/ipfs/" in gw:
        return f"{gw.rstrip('/')}/{cid}"
    return f"{gw}/ipfs/{cid}"


def fetch_ipfs_bytes(cid: str, gateways: Iterable[str], *, timeout_s: int, use_cache: bool = True) -> bytes:
    """Fetch IPFS content by CID, with optional caching."""
    # Check cache first
    if use_cache:
        key = cache_key("ipfs", cid)
        cached = get_cached(key)
        if cached is not None:
            # Cache stores base64-encoded bytes
            try:
                return base64.b64decode(cached["content"])
            except Exception:  # pylint: disable=broad-exception-caught
                # If cache is corrupted, continue to fetch
                pass

    try:
        import requests
    except ImportError as ex:  # pragma: no cover
        raise RuntimeError("Missing dependency. Run: uv sync") from ex

    last_err: Exception | None = None
    for gw in gateways:
        url = build_gateway_url(gw, cid)
        try:
            resp = requests.get(url, timeout=timeout_s)
            resp.raise_for_status()
            content = resp.content
            # Cache the result
            if use_cache:
                key = cache_key("ipfs", cid)
                set_cached(key, {"content": base64.b64encode(content).decode("ascii")})
            return content
        except Exception as ex:  # pylint: disable=broad-exception-caught
            last_err = ex
    raise RuntimeError(f"Failed to fetch CID {cid} from all configured gateways") from last_err
