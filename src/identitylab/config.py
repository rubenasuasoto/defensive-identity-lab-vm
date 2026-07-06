from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from identitylab.paths import LABS_CONFIG


@dataclass(frozen=True)
class Lab:
    slug: str
    name: str
    short_name: str
    layer: str
    summary: str
    repo_url: str
    release_url: str
    demo_url: str
    docs_url: str
    primary_walkthrough: str
    detections: list[str]
    local_path: str
    local_validate_command: str
    local_demo_command: str


@dataclass(frozen=True)
class HubConfig:
    generated_site: str
    hub_docs_url: str
    scope_warning: str
    end_to_end_walkthrough: list[dict[str, Any]]
    labs: list[Lab]


def load_config(path: Path = LABS_CONFIG) -> HubConfig:
    data = json.loads(path.read_text(encoding="utf-8"))
    labs = [Lab(**lab) for lab in data["labs"]]
    return HubConfig(
        generated_site=data["generated_site"],
        hub_docs_url=data["hub_docs_url"],
        scope_warning=data["scope_warning"],
        end_to_end_walkthrough=data["end_to_end_walkthrough"],
        labs=labs,
    )
