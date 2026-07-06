from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from identitylab.config import HubConfig, load_config
from identitylab.paths import ROOT


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    generated_at: str
    host: dict[str, str]
    checks: list[ReadinessCheck]


def build_readiness_report(config: HubConfig | None = None) -> ReadinessReport:
    cfg = config or load_config()
    checks: list[ReadinessCheck] = [
        _check_python(),
        _check_command("git", "Git CLI is required to clone and inspect the labs."),
        _check_command("uv", "uv is required to install dependencies and run lab CLIs."),
        _check_command("wsl", "WSL is optional for a lightweight local lab workspace."),
        _check_disk_space(ROOT.drive or str(ROOT.anchor), minimum_gb=20),
    ]
    checks.extend(_check_local_labs(cfg))
    return ReadinessReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        host={
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        checks=checks,
    )


def report_passed(report: ReadinessReport) -> bool:
    return all(check.status != "fail" for check in report.checks)


def write_evidence(output_dir: Path, report: ReadinessReport | None = None) -> tuple[Path, Path]:
    readiness = report or build_readiness_report()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "identity-lab-vm-readiness.json"
    md_path = output_dir / "identity-lab-vm-readiness.md"
    json_path.write_text(
        json.dumps(_report_to_dict(readiness), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    md_path.write_text(format_readiness_markdown(readiness), encoding="utf-8", newline="\n")
    return json_path, md_path


def format_readiness_markdown(report: ReadinessReport) -> str:
    lines = [
        "# Identity lab VM readiness",
        "",
        f"Generated at: `{report.generated_at}`",
        "",
        "## Host",
        "",
    ]
    for key, value in report.host.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Checks", ""])
    for check in report.checks:
        lines.append(f"- {check.status.upper()}: {check.name} - {check.detail}")
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "Synthetic lab only. No production logs, credentials, tenants, tokens, malware,",
            "offensive simulations or host-changing actions.",
            "",
        ]
    )
    return "\n".join(lines)


def _report_to_dict(report: ReadinessReport) -> dict[str, object]:
    return {
        "generated_at": report.generated_at,
        "host": report.host,
        "checks": [asdict(check) for check in report.checks],
    }


def _check_python() -> ReadinessCheck:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return ReadinessCheck("Python 3.12+", "pass", f"Python {version}")


def _check_command(command: str, purpose: str) -> ReadinessCheck:
    found = shutil.which(command)
    if found:
        return ReadinessCheck(f"{command} available", "pass", found)
    status = "warn" if command == "wsl" else "fail"
    return ReadinessCheck(f"{command} available", status, purpose)


def _check_disk_space(path: str, minimum_gb: int) -> ReadinessCheck:
    usage = shutil.disk_usage(path)
    free_gb = usage.free / (1024**3)
    if free_gb >= minimum_gb:
        return ReadinessCheck("Free disk space", "pass", f"{free_gb:.1f} GB free")
    return ReadinessCheck(
        "Free disk space",
        "warn",
        f"{free_gb:.1f} GB free; {minimum_gb} GB recommended",
    )


def _check_local_labs(config: HubConfig) -> list[ReadinessCheck]:
    checks: list[ReadinessCheck] = []
    for lab in config.labs:
        path = (ROOT / lab.local_path).resolve()
        if not path.exists():
            checks.append(
                ReadinessCheck(f"{lab.short_name} local clone", "warn", f"Missing {path}")
            )
            continue
        if not (path / ".git").exists():
            checks.append(
                ReadinessCheck(f"{lab.short_name} local clone", "warn", f"No .git in {path}")
            )
            continue
        checks.append(ReadinessCheck(f"{lab.short_name} local clone", "pass", str(path)))
        demo = path / "reports" / "latest" / "demo.html"
        status = "pass" if demo.exists() else "warn"
        detail = str(demo) if demo.exists() else f"Run {lab.local_demo_command}"
        checks.append(ReadinessCheck(f"{lab.short_name} local demo", status, detail))
    return checks
