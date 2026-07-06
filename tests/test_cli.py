from pathlib import Path

from identitylab import cli
from identitylab.verify import UrlCheck
from identitylab.vm import ReadinessCheck, ReadinessReport


def test_build_site_command_prints_output(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "build_site", lambda: Path("site/index.html"))

    result = cli.main(["build-site"])

    assert result == 0
    output = capsys.readouterr().out
    assert "Built site\\index.html" in output or "Built site/index.html" in output


def test_verify_command_returns_zero_when_checks_pass(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "verify_urls",
        lambda: [UrlCheck("demo", "https://example.test", 200, True)],
    )

    result = cli.main(["verify"])

    assert result == 0
    assert "OK" in capsys.readouterr().out


def test_verify_command_returns_one_when_a_check_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "verify_urls",
        lambda: [UrlCheck("demo", "https://example.test", 404, False)],
    )

    assert cli.main(["verify"]) == 1


def test_all_command_builds_and_verifies(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "build_site", lambda: calls.append("build") or Path("site/index.html"))
    monkeypatch.setattr(
        cli,
        "verify_urls",
        lambda: calls.append("verify")
        or [UrlCheck("demo", "https://example.test", 200, True)],
    )

    assert cli.main(["all"]) == 0
    assert calls == ["build", "verify"]


def test_vm_check_command_reports_readiness(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "build_readiness_report",
        lambda: ReadinessReport(
            generated_at="2026-07-06T00:00:00+00:00",
            host={"system": "Windows"},
            checks=[ReadinessCheck("Python", "pass", "Python 3.12")],
        ),
    )

    assert cli.main(["vm-check"]) == 0
    assert "Identity lab VM readiness" in capsys.readouterr().out
