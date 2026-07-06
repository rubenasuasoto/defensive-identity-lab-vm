from pathlib import Path

from identitylab.vm import (
    ReadinessCheck,
    ReadinessReport,
    format_readiness_markdown,
    write_evidence,
)


def test_format_readiness_markdown_contains_scope() -> None:
    report = ReadinessReport(
        generated_at="2026-07-06T00:00:00+00:00",
        host={"system": "Windows"},
        checks=[ReadinessCheck("Python", "pass", "Python 3.12")],
    )

    markdown = format_readiness_markdown(report)

    assert "Identity lab VM readiness" in markdown
    assert "Synthetic lab only" in markdown
    assert "PASS: Python" in markdown


def test_write_evidence_creates_json_and_markdown(tmp_path: Path) -> None:
    report = ReadinessReport(
        generated_at="2026-07-06T00:00:00+00:00",
        host={"system": "Windows"},
        checks=[ReadinessCheck("Python", "pass", "Python 3.12")],
    )

    json_path, md_path = write_evidence(tmp_path, report)

    assert json_path.exists()
    assert md_path.exists()
    assert "Python" in json_path.read_text(encoding="utf-8")
    assert "Python" in md_path.read_text(encoding="utf-8")
