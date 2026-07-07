from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_live_lab_task_scripts_exist() -> None:
    for relative_path in [
        "scripts/install-live-lab-task.ps1",
        "scripts/uninstall-live-lab-task.ps1",
        "scripts/open-live-lab.ps1",
        "scripts/run-live-lab-task.ps1",
    ]:
        assert (ROOT / relative_path).is_file()


def test_live_lab_docs_cover_persistence() -> None:
    live_doc = (ROOT / "docs/LIVE_LAB.md").read_text(encoding="utf-8")
    portable_doc = (ROOT / "docs/PORTABLE_SETUP.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Analyst Workbench" in live_doc
    assert "install-live-lab-task.ps1" in live_doc
    assert "uninstall-live-lab-task.ps1" in portable_doc
    assert "install-live-lab-task.ps1" in readme


def test_runtime_artifacts_are_ignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "runtime/" in gitignore
    assert "live_lab.sqlite" in gitignore
