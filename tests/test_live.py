from pathlib import Path

from identitylab.live import (
    add_analyst_note,
    evidence_markdown,
    get_scenario,
    live_state,
    render_live_app,
    reset_run,
    scenario_index,
    scenario_to_dict,
    tick_run,
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


def test_live_store_generates_incident_from_event_logic(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"

    state = reset_run("SENT-006-POS", db_path)
    assert state["event_count"] == 0
    assert state["incident"] is None

    state = tick_run("SENT-006-POS", db_path)
    assert state["evaluation"]["status"] == "Observing"
    assert state["incident"] is None

    tick_run("SENT-006-POS", db_path)
    tick_run("SENT-006-POS", db_path)
    state = tick_run("SENT-006-POS", db_path)

    assert state["complete"] is True
    assert state["evaluation"]["status"] == "Alert"
    assert state["incident"]["detection"] == "SENT-006"
    assert state["incident"]["status"] == "New"


def test_analyst_note_updates_incident_status(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    reset_run("AUTH-003-POS", db_path)
    tick_run("AUTH-003-POS", db_path)
    tick_run("AUTH-003-POS", db_path)
    state = tick_run("AUTH-003-POS", db_path)

    incident = state["incident"]
    assert incident is not None
    result = add_analyst_note(int(incident["id"]), "Escalated", "Review workstation.", db_path)
    updated = live_state("AUTH-003-POS", db_path)

    assert result["status"] == "Escalated"
    assert updated["incident"]["status"] == "Escalated"
    assert updated["analyst_notes"][0]["note"] == "Review workstation."
