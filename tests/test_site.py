from pathlib import Path

from identitylab.site import build_site


def test_build_site_generates_index(tmp_path: Path) -> None:
    output = build_site(tmp_path / "index.html")

    assert output.exists()
    html = output.read_text(encoding="utf-8")
    assert "Defensive Identity Lab Hub" in html
    assert "Windows Authentication Detection Lab" in html
    assert "Microsoft Entra Detection Lab" in html
    assert "Microsoft Sentinel KQL Detection Lab" in html
    assert "https://2dam-7.gitbook.io/defensive-lab/" in html
    assert "releases/tag/v0.1.0" in html
    assert "SENT-006-POS" in html


def test_site_has_no_external_runtime_surfaces(tmp_path: Path) -> None:
    html = build_site(tmp_path / "index.html").read_text(encoding="utf-8").lower()

    forbidden = [
        "<script src",
        "<form",
        "fetch(",
        "type=\"file\"",
        "upload",
        "cdn.",
    ]
    for token in forbidden:
        assert token not in html
