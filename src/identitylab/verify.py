from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from identitylab.config import HubConfig, load_config


@dataclass(frozen=True)
class UrlCheck:
    label: str
    url: str
    status_code: int | None
    ok: bool
    error: str | None = None


def verify_urls(config: HubConfig | None = None, timeout: float = 12.0) -> list[UrlCheck]:
    cfg = config or load_config()
    checks: list[UrlCheck] = []
    for lab in cfg.labs:
        checks.append(_check_url(f"{lab.short_name} repo", lab.repo_url, timeout))
        checks.append(_check_url(f"{lab.short_name} demo", lab.demo_url, timeout))
        checks.append(_check_url(f"{lab.short_name} docs", lab.docs_url, timeout))
    return checks


def checks_passed(checks: list[UrlCheck]) -> bool:
    return all(check.ok for check in checks)


def _check_url(label: str, url: str, timeout: float) -> UrlCheck:
    request = Request(url, method="GET", headers={"User-Agent": "identitylab/0.1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = response.status
    except HTTPError as exc:
        return UrlCheck(label, url, exc.code, False, str(exc))
    except URLError as exc:
        return UrlCheck(label, url, None, False, str(exc.reason))
    return UrlCheck(label, url, status_code, 200 <= status_code < 400)
