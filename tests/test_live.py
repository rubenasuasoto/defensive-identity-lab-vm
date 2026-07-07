from identitylab.live import (
    evidence_markdown,
    get_scenario,
    render_live_app,
    scenario_index,
    scenario_to_dict,
)


def test_live_scenarios_include_integrated_incident() -> None:
    scenarios = scenario_index()

    assert {scenario["scenario_id"] for scenario in scenarios} >= {
        "SENT-006-POS",
        "ENTRA-003-POS",
        "AUTH-003-POS",
    }


def test_integrated_scenario_has_events_and_alert() -> None:
    scenario = get_scenario("SENT-006-POS")

    assert scenario is not None
    payload = scenario_to_dict(scenario)
    assert payload["primary_detection"] == "SENT-006"
    assert len(payload["events"]) >= 3
    assert any(step["status"] == "alert" for step in payload["detection_steps"])


def test_live_app_is_local_and_self_contained() -> None:
    html = render_live_app().lower()

    assert "identity detection live lab" in html
    assert "fetch('/api/scenarios')" in html
    assert "<script src" not in html
    assert "<form" not in html
    assert "type=\"file\"" not in html
    assert "https://" not in html
    assert "http://" not in html


def test_evidence_markdown_contains_scope() -> None:
    scenario = get_scenario("SENT-006-POS")

    assert scenario is not None
    markdown = evidence_markdown(scenario)
    assert "Live lab evidence: SENT-006-POS" in markdown
    assert "Synthetic lab only" in markdown
