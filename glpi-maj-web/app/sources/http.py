from __future__ import annotations

import time

import httpx

from app.sources.catalog import USER_AGENT


def make_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(30.0), follow_redirects=True, trust_env=True, headers={"User-Agent": USER_AGENT})


def get_with_retries(
    client: httpx.Client,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    attempts: int = 3,
    sleep=time.sleep,
) -> httpx.Response:
    delay = 1.0
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            response = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt + 1 == attempts:
                raise
            sleep(delay)
            delay *= 2
            continue
        if response.status_code in {502, 503, 504} and attempt + 1 < attempts:
            sleep(delay)
            delay *= 2
            continue
        return response
    if last_error:
        raise last_error
    raise RuntimeError(f"Échec de la requête {url}")
