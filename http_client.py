"""Async HTTP client — httpx wrapper. Replaces baseClass.Browser."""

from __future__ import annotations

import httpx
from typing import Optional


DEFAULT_AGENT = "fimap.googlecode.com"


class HTTPClient:
    """Wraps ``httpx.AsyncClient`` with fimap-specific defaults.

    * SSL verification ON by default (``verify=True``).
    * Per-request timeout (NO global ``socket.setdefaulttimeout``).
    * Proxy support via ``httpx`` proxy config.
    """

    def __init__(
        self,
        user_agent: str = DEFAULT_AGENT,
        proxy: Optional[str] = None,
        timeout: float = 30.0,
        verify: bool = True,
        additional_headers: Optional[dict] = None,
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.verify = verify
        self.proxy = proxy

        self._headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-us,en;q=0.5",
        }
        if additional_headers:
            self._headers.update(additional_headers)

        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            proxy_url = self.proxy if self.proxy else None
            self._client = httpx.AsyncClient(
                verify=self.verify,
                timeout=httpx.Timeout(self.timeout),
                proxy=proxy_url,
                headers=self._headers,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def reset(self) -> None:
        """Force client recreation — use before asyncio.run() with new event loops."""
        if self._client is not None:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._client.aclose())
            except RuntimeError:
                pass  # No running loop, client is stale anyway
            self._client = None

    async def get(
        self,
        url: str,
        additional_headers: Optional[dict] = None,
    ) -> tuple[Optional[str], Optional[list]]:
        """GET request. Returns ``(body, headers)`` or ``(None, None)`` on error."""
        client = await self._get_client()
        headers = dict(self._headers)
        if additional_headers:
            headers.update(additional_headers)
        try:
            resp = await client.get(url, headers=headers)
            body = resp.text
            hdrs = [(k, v) for k, v in resp.headers.items()]
            return body, hdrs
        except Exception:
            return None, None

    async def post(
        self,
        url: str,
        data: Optional[str] = None,
        additional_headers: Optional[dict] = None,
    ) -> tuple[Optional[str], Optional[list]]:
        """POST request. Returns ``(body, headers)`` or ``(None, None)`` on error."""
        client = await self._get_client()
        headers = dict(self._headers)
        if additional_headers:
            headers.update(additional_headers)
        try:
            resp = await client.post(url, content=data or "", headers=headers)
            body = resp.text
            hdrs = [(k, v) for k, v in resp.headers.items()]
            return body, hdrs
        except Exception:
            return None, None

    async def get_with_headers(
        self,
        url: str,
        agent: Optional[str] = None,
        additional_headers: Optional[dict] = None,
    ) -> tuple[Optional[str], Optional[list]]:
        """GET that returns (body, headers) tuple. Same as get() but with legacy interface."""
        return await self.get(url, additional_headers)
