from pathlib import Path

from identitylab.live import (
    add_analyst_note,
    case_evidence_markdown,
    case_index,
    close_case_run,
    evidence_markdown,
    get_scenario,
    incident_detail,
    incident_evidence_markdown,
    incident_queue,
    live_state,
    render_live_app,
    request_training_hint,
    reset_run,
    reset_runtime,
    save_instructor_review,
    scenario_index,
    scenario_to_dict,
    set_training_guide_step,
    start_case_run,
    start_training_run,
    submit_training_answer,
    tick_case_run,
    tick_run,
    training_evidence_markdown,
    training_index,
    training_run_detail,
    update_case_task,
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
    assert "case run" in html
    assert "guided training" in html
    assert "workbench views" in html
    assert 'data-view-panel="overview"' in html
    assert 'data-view-panel="incidents"' in html
    assert "guided case investigation" in html
    assert "learning objectives" in html
    assert "learning path" in html
    assert "evidence desk" in html
    assert "navigate the synthetic evidence without leaving guided training" in html
    assert "data-training-evidence" in html
    assert "step.flow_id.endswith('-exercise')" in html
    assert "step.flow_id.endswith('-check')" in html
    assert "reveal next event" in html
    assert "facilitator notes" in html
    assert "training outcome" in html
    assert "hint" in html
    assert "feedback" in html
    assert "analyst tasks" in html
    assert "close case" in html
    assert "fetch('/api/scenarios')" in html
    assert "fetch('/api/cases')" in html
    assert "fetch('/api/training')" in html
    assert "/api/training/${state.activetraining.run.id}/answer" in html
    assert "/api/training/${state.activetraining.run.id}/guide" in html
    assert "data-training-checkpoint" not in html
    assert "data-training-task" not in html
    assert "/api/state?scenario=" in html
    assert "<script src" not in html
    assert "<form" not in html
    assert 'type="file"' not in html
    assert "https://" not in html
    assert "http://" not in html
    guide = html[html.index("function rendertrainingguide") :]
    assert guide.index("$('training-step-content').innerhtml = content;") < guide.index(
        "trainingevidencepanel(payload);"
    )


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


def test_case_run_generates_realistic_soc_case(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"

    index = case_index(db_path)
    assert index["cases"][0]["case_id"] == "CASE-001"

    state = start_case_run("CASE-001", db_path)
    assert state["run"]["status"] == "Running"
    assert state["event_count"] == 0
    assert len(state["tasks"]) == 5

    for _ in range(8):
        state = tick_case_run(int(state["run"]["id"]), db_path)

    assert state["complete"] is True
    assert state["counts"]["benign"] >= 3
    assert state["counts"]["signal"] >= 4
    assert state["incident"]["detection"] == "SENT-006"
    assert state["evaluation"]["status"] == "Alert"


def test_case_tasks_close_and_export(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    state = start_case_run("CASE-001", db_path)
    run_id = int(state["run"]["id"])
    for _ in range(8):
        tick_case_run(run_id, db_path)

    state = update_case_task(run_id, "review-correlation", True, db_path)
    assert any(
        task["task_id"] == "review-correlation" and task["completed"] for task in state["tasks"]
    )

    state = close_case_run(run_id, "Escalated", "Synthetic case ready for review.", db_path)
    assert state["run"]["status"] == "Closed"
    assert state["run"]["decision"] == "Escalated"
    assert state["incident"]["status"] == "Escalated"

    markdown = case_evidence_markdown(run_id, db_path)
    assert "Case evidence: CASE-001" in markdown
    assert "Synthetic case ready for review." in markdown
    assert "Analyst tasks" in markdown


def test_reset_runtime_clears_case_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    state = start_case_run("CASE-001", db_path)
    tick_case_run(int(state["run"]["id"]), db_path)

    reset_runtime(db_path)

    assert case_index(db_path)["runs"] == []


def test_training_run_guides_case_workflow(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"

    index = training_index(db_path)
    assert index["modules"][0]["module_id"] == "TRAIN-001"

    state = start_training_run("TRAIN-001", db_path)
    training_run_id = int(state["run"]["id"])
    case_run_id = int(state["case_run"]["run"]["id"])

    assert state["module"]["case_id"] == "CASE-001"
    assert state["module"]["instructor_brief"]
    assert len(state["module"]["assessment"]) == 3
    assert len(state["module"]["learning_flow"]) == 11
    assert state["module"]["learning_flow"][1]["flow_id"] == "timeline-exercise"
    assert state["module"]["learning_flow"][2]["flow_id"] == "timeline-check"
    assert len(state["questions"]) == 4
    assert state["run"]["status"] == "In progress"
    assert len(state["checkpoints"]) == 5
    assert state["feedback"].startswith("Keep investigating")
    assert state["guide"]["current_step"] == 0
    assert state["guide"]["current"]["flow_id"] == "briefing"
    assert state["instructor"]["mode"] == "Guided Training"
    assert state["instructor"]["version"] == "0.9.0"
    assert state["instructor"]["score"] == 0

    state = set_training_guide_step(training_run_id, 3, db_path)
    assert state["guide"]["current_step"] == 1
    assert state["guide"]["current"]["flow_id"] == "timeline-exercise"

    for _ in range(4):
        tick_case_run(case_run_id, db_path)

    state = set_training_guide_step(training_run_id, 2, db_path)
    assert state["guide"]["current"]["flow_id"] == "timeline-check"

    state = submit_training_answer(
        training_run_id,
        "identify-benign",
        "risky-sign-in",
        db_path,
    )
    first_answer = next(
        answer for answer in state["answers"] if answer["question_id"] == "identify-benign"
    )
    assert first_answer["correct"] is False
    assert first_answer["attempts"] == 1

    state = submit_training_answer(
        training_run_id,
        "identify-benign",
        "service-failure",
        db_path,
    )
    assert any(
        checkpoint["checkpoint_id"] == "observe-noise" and checkpoint["completed"]
        for checkpoint in state["checkpoints"]
    )

    state = set_training_guide_step(training_run_id, 4, db_path)
    assert state["guide"]["current"]["flow_id"] == "entities-check"
    state = submit_training_answer(
        training_run_id,
        "correlate-entities",
        "alex-shared-ip",
        db_path,
    )
    state = set_training_guide_step(training_run_id, 5, db_path)
    assert state["guide"]["current"]["flow_id"] == "rule-exercise"

    for _ in range(4):
        tick_case_run(case_run_id, db_path)
    state = set_training_guide_step(training_run_id, 6, db_path)
    assert state["guide"]["current"]["flow_id"] == "rule-check"
    state = submit_training_answer(
        training_run_id,
        "explain-rule",
        "correlated-sequence",
        db_path,
    )
    state = set_training_guide_step(training_run_id, 8, db_path)
    assert state["guide"]["current"]["flow_id"] == "triage-check"
    state = submit_training_answer(
        training_run_id,
        "choose-triage",
        "document-correlation",
        db_path,
    )

    state = request_training_hint(training_run_id, db_path)
    assert state["latest_hint"]
    assert len(state["hints"]) == 1
    assert state["instructor"]["hints_used"] == 1

    close_case_run(case_run_id, "Suspicious", "Correlated identity activity.", db_path)

    state = training_run_detail(training_run_id, db_path)
    assert state["run"]["status"] == "Completed"
    assert "Good call" in state["feedback"]
    assert state["instructor"]["score"] >= 4
    assert state["instructor"]["readiness"] in {
        "Developing",
        "Ready for independent review",
    }

    markdown = training_evidence_markdown(training_run_id, db_path)
    assert "Training evidence: TRAIN-001" in markdown
    assert "Guided step:" in markdown
    assert "Learner decisions" in markdown
    assert "Training assessment" in markdown
    assert "Learning objectives" in markdown
    assert "Correlated identity activity" in markdown or "Good call" in markdown


def test_second_training_module_uses_entra_mfa_case(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"

    index = training_index(db_path)
    assert {module["module_id"] for module in index["modules"]} == {
        "TRAIN-001",
        "TRAIN-002",
    }

    state = start_training_run("TRAIN-002", db_path)
    training_run_id = int(state["run"]["id"])
    case_run_id = int(state["case_run"]["run"]["id"])

    assert state["module"]["case_id"] == "CASE-002"
    assert state["case_run"]["case"]["primary_detection"] == "ENTRA-003"
    assert "MFA denials" in state["module"]["facilitator_notes"]

    for _ in range(5):
        state = tick_case_run(case_run_id, db_path)

    assert state["evaluation"]["status"] == "Alert"
    assert state["incident"]["detection"] == "ENTRA-003"
    assert training_run_detail(training_run_id, db_path)["case_run"]["complete"] is True


def test_training_feedback_corrects_benign_close(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    state = start_training_run("TRAIN-001", db_path)
    training_run_id = int(state["run"]["id"])
    case_run_id = int(state["case_run"]["run"]["id"])

    close_case_run(case_run_id, "Benign", "Looks normal.", db_path)
    state = training_run_detail(training_run_id, db_path)

    assert state["run"]["status"] == "Completed"
    assert "Review needed" in state["feedback"]
    assert state["instructor"]["readiness"] == "Needs corrective review"


def test_instructor_review_is_persistent(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite"
    state = start_training_run("TRAIN-001", db_path)
    training_run_id = int(state["run"]["id"])

    state = save_instructor_review(
        training_run_id,
        "Developing",
        "Good timeline review; needs a clearer decision note.",
        db_path,
    )

    assert state["review"]["rating"] == "Developing"
    assert state["review"]["observation"] == (
        "Good timeline review; needs a clearer decision note."
    )
    assert training_run_detail(training_run_id, db_path)["review"]["rating"] == "Developing"
    assert "Facilitator review" in training_evidence_markdown(training_run_id, db_path)
