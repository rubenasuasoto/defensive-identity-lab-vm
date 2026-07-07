from pathlib import Path

from identitylab.live import (
    add_analyst_note,
    evidence_markdown,
    get_scenario,
    incident_detail,
    incident_evidence_markdown,
    incident_queue,
    live_state,
    render_live_app,
    reset_run,
    reset_runtime,
    scenario_index,
    scenario_to_dict,
    tick_run,
    update_incident_action,
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
    assert "incident queue" in html
    assert "incident detail" in html
    assert "entities" in html
    assert "rule evaluation" in html
    assert "reset runtime state" in html
    assert "fetch('/api/scenarios')" in html
    assert "/api/state?scenario=" in html
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


def test_incident_queue_detail_and_action_are_persistent(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    reset_run("SENT-006-POS", db_path)
    for _ in range(4):
        tick_run("SENT-006-POS", db_path)

    queue = incident_queue(db_path)
    assert len(queue) == 1
    assert queue[0]["detection"] == "SENT-006"
    incident_id = int(queue[0]["id"])

    detail = incident_detail(incident_id, db_path)
    assert detail is not None
    assert detail["incident"]["status"] == "New"
    assert detail["entities"]["accounts"]
    assert detail["entities"]["ips"]
    assert detail["evaluation"]["status"] == "Alert"
    assert len(detail["events"]) == 4

    updated = update_incident_action(
        incident_id,
        "Suspicious",
        "Cloud and endpoint activity match.",
        db_path,
    )
    assert updated["status"] == "Suspicious"

    detail = incident_detail(incident_id, db_path)
    assert detail is not None
    assert detail["notes"][0]["note"] == "Cloud and endpoint activity match."
    assert incident_queue(db_path)[0]["note_count"] == 1


def test_incident_export_contains_notes_entities_and_scope(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    reset_run("AUTH-003-POS", db_path)
    for _ in range(3):
        tick_run("AUTH-003-POS", db_path)

    incident_id = int(incident_queue(db_path)[0]["id"])
    update_incident_action(incident_id, "Closed", "Synthetic escalation reviewed.", db_path)
    markdown = incident_evidence_markdown(incident_id, db_path)

    assert "Incident evidence" in markdown
    assert "Synthetic escalation reviewed." in markdown
    assert "## Entities" in markdown
    assert "Synthetic lab only" in markdown


def test_reset_runtime_clears_events_incidents_and_notes(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    reset_run("ENTRA-003-POS", db_path)
    for _ in range(3):
        tick_run("ENTRA-003-POS", db_path)

    incident_id = int(incident_queue(db_path)[0]["id"])
    update_incident_action(incident_id, "Benign", "Known test user.", db_path)

    result = reset_runtime(db_path)

    assert result["reset"] is True
    assert incident_queue(db_path) == []
    assert live_state("ENTRA-003-POS", db_path)["event_count"] == 0
