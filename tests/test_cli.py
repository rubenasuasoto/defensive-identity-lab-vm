from pathlib import Path

from identitylab import cli
from identitylab.verify import UrlCheck


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
