from identitylab.config import load_config


def test_labs_json_contains_expected_labs() -> None:
    config = load_config()

    assert [lab.slug for lab in config.labs] == [
        "windows-authentication-detection-lab",
        "microsoft-entra-detection-lab",
        "microsoft-sentinel-kql-detection-lab",
    ]


def test_each_lab_has_required_public_fields() -> None:
    config = load_config()

    assert config.hub_docs_url == "https://2dam-7.gitbook.io/defensive-lab/"
    for lab in config.labs:
        assert lab.repo_url.startswith("https://github.com/rubenasuasoto/")
        assert lab.release_url.startswith("https://github.com/rubenasuasoto/")
        assert lab.release_url.endswith("/releases/tag/v0.1.0")
        assert lab.demo_url.startswith("https://rubenasuasoto.github.io/")
        assert lab.docs_url.startswith("https://2dam-7.gitbook.io/")
        assert lab.primary_walkthrough
        assert lab.detections


def test_expected_walkthrough_ids_are_present() -> None:
    config = load_config()

    scenarios = {step["scenario"] for step in config.end_to_end_walkthrough}

    assert {"AUTH-003-POS", "ENTRA-003-POS", "SENT-006-POS"} <= scenarios
