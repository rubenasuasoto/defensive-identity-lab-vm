from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from identitylab.paths import LIVE_DB

SCOPE_WARNING = (
    "Synthetic lab only. No production logs, credentials, tenants, tokens, malware, "
    "offensive simulations or host-changing actions."
)


@dataclass(frozen=True)
class LiveScenario:
    scenario_id: str
    title: str
    summary: str
    severity: str
    primary_detection: str
    expected_result: str
    analyst_goal: str
    events: list[dict[str, object]]
    detection_steps: list[dict[str, object]]


SCENARIOS: list[LiveScenario] = [
    LiveScenario(
        scenario_id="SENT-006-POS",
        title="Cross-source identity incident",
        summary=(
            "A risky Entra sign-in is followed by repeated Windows failures and a successful "
            "Windows logon for the same account and source IP."
        ),
        severity="High",
        primary_detection="SENT-006",
        expected_result="Alert",
        analyst_goal="Correlate cloud identity and endpoint authentication signals.",
        events=[
            {
                "offset": 0,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "alex.morgan@example.test",
                "ip": "203.0.113.42",
                "host": "-",
                "result": "success",
                "detail": "High-risk sign-in to Azure Portal not blocked by Conditional Access.",
            },
            {
                "offset": 4,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "failure",
                "detail": "Windows event 4625 failed logon.",
            },
            {
                "offset": 8,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "failure",
                "detail": "Windows event 4625 failed logon.",
            },
            {
                "offset": 13,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "success",
                "detail": "Windows event 4624 successful logon.",
            },
        ],
        detection_steps=[
            {
                "after_event": 1,
                "status": "observe",
                "message": "Cloud risk context observed for the account and IP.",
            },
            {
                "after_event": 3,
                "status": "observe",
                "message": "Endpoint authentication failures establish local activity.",
            },
            {
                "after_event": 4,
                "status": "alert",
                "message": "SENT-006 alert: Entra and Windows signals correlate within window.",
            },
        ],
    ),
    LiveScenario(
        scenario_id="ENTRA-003-POS",
        title="MFA denied repeatedly followed by success",
        summary="Synthetic sign-in sequence with repeated MFA denials followed by a success.",
        severity="Medium",
        primary_detection="ENTRA-003",
        expected_result="Alert",
        analyst_goal="Review whether the success is expected after multiple MFA denials.",
        events=[
            {
                "offset": 0,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "jamie.lee@example.test",
                "ip": "198.51.100.17",
                "host": "-",
                "result": "mfa_denied",
                "detail": "MFA denied by user.",
            },
            {
                "offset": 5,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "jamie.lee@example.test",
                "ip": "198.51.100.17",
                "host": "-",
                "result": "mfa_denied",
                "detail": "Second MFA denial from same source.",
            },
            {
                "offset": 11,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "jamie.lee@example.test",
                "ip": "198.51.100.17",
                "host": "-",
                "result": "success",
                "detail": "Successful interactive sign-in after denials.",
            },
        ],
        detection_steps=[
            {"after_event": 2, "status": "observe", "message": "MFA denial pattern is forming."},
            {
                "after_event": 3,
                "status": "alert",
                "message": "ENTRA-003 alert: denied MFA sequence followed by success.",
            },
        ],
    ),
    LiveScenario(
        scenario_id="AUTH-003-POS",
        title="Windows success after repeated failures",
        summary="Repeated Windows failures followed by a successful logon from the same source.",
        severity="Medium",
        primary_detection="AUTH-003",
        expected_result="Alert",
        analyst_goal="Confirm whether the success after failures is expected for the account.",
        events=[
            {
                "offset": 0,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "maria.rivera",
                "ip": "192.0.2.55",
                "host": "WKST-017",
                "result": "failure",
                "detail": "Event 4625 failed logon.",
            },
            {
                "offset": 3,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "maria.rivera",
                "ip": "192.0.2.55",
                "host": "WKST-017",
                "result": "failure",
                "detail": "Event 4625 failed logon.",
            },
            {
                "offset": 7,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "maria.rivera",
                "ip": "192.0.2.55",
                "host": "WKST-017",
                "result": "success",
                "detail": "Event 4624 successful logon.",
            },
        ],
        detection_steps=[
            {"after_event": 2, "status": "observe", "message": "Repeated failures observed."},
            {
                "after_event": 3,
                "status": "alert",
                "message": "AUTH-003 alert: successful logon after repeated failures.",
            },
        ],
    ),
]


def scenario_index() -> list[dict[str, str]]:
    return [
        {
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "severity": scenario.severity,
            "primary_detection": scenario.primary_detection,
        }
        for scenario in SCENARIOS
    ]


def get_scenario(scenario_id: str) -> LiveScenario | None:
    return next((scenario for scenario in SCENARIOS if scenario.scenario_id == scenario_id), None)


def scenario_to_dict(scenario: LiveScenario) -> dict[str, object]:
    return {
        "scenario_id": scenario.scenario_id,
        "title": scenario.title,
        "summary": scenario.summary,
        "severity": scenario.severity,
        "primary_detection": scenario.primary_detection,
        "expected_result": scenario.expected_result,
        "analyst_goal": scenario.analyst_goal,
        "scope_warning": SCOPE_WARNING,
        "events": scenario.events,
        "detection_steps": scenario.detection_steps,
    }


def init_store(db_path: Path = LIVE_DB) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS run_state (
                scenario_id TEXT PRIMARY KEY,
                next_index INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                emitted_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL,
                detection TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                account TEXT NOT NULL,
                ip TEXT NOT NULL,
                host TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def reset_run(scenario_id: str, db_path: Path = LIVE_DB) -> dict[str, object]:
    scenario = _require_scenario(scenario_id)
    init_store(db_path)
    now = _now()
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM events WHERE scenario_id = ?", (scenario_id,))
        connection.execute("DELETE FROM incidents WHERE scenario_id = ?", (scenario_id,))
        connection.execute(
            """
            INSERT INTO run_state (scenario_id, next_index, started_at, updated_at)
            VALUES (?, 0, ?, ?)
            ON CONFLICT(scenario_id) DO UPDATE SET
              next_index = 0,
              started_at = excluded.started_at,
              updated_at = excluded.updated_at
            """,
            (scenario_id, now, now),
        )
    return live_state(scenario.scenario_id, db_path)


def tick_run(scenario_id: str, db_path: Path = LIVE_DB) -> dict[str, object]:
    scenario = _require_scenario(scenario_id)
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        state = connection.execute(
            "SELECT next_index FROM run_state WHERE scenario_id = ?",
            (scenario_id,),
        ).fetchone()
        if state is None:
            reset_run(scenario_id, db_path)
            next_index = 0
        else:
            next_index = int(state[0])
        if next_index >= len(scenario.events):
            return live_state(scenario_id, db_path)

        event = dict(scenario.events[next_index])
        event["sequence"] = next_index + 1
        event["emitted_at"] = _now()
        connection.execute(
            """
            INSERT INTO events (scenario_id, sequence, emitted_at, payload)
            VALUES (?, ?, ?, ?)
            """,
            (scenario_id, next_index + 1, event["emitted_at"], json.dumps(event)),
        )
        connection.execute(
            "UPDATE run_state SET next_index = ?, updated_at = ? WHERE scenario_id = ?",
            (next_index + 1, _now(), scenario_id),
        )
    _evaluate_and_store_incident(scenario, db_path)
    return live_state(scenario_id, db_path)


def live_state(scenario_id: str, db_path: Path = LIVE_DB) -> dict[str, object]:
    scenario = _require_scenario(scenario_id)
    init_store(db_path)
    events = _load_events(scenario_id, db_path)
    incident = _load_incident(scenario_id, db_path)
    evaluation = evaluate_detection(scenario, events)
    return {
        "scenario": scenario_to_dict(scenario),
        "events": events,
        "event_count": len(events),
        "complete": len(events) >= len(scenario.events),
        "next_event": len(events) + 1 if len(events) < len(scenario.events) else None,
        "evaluation": evaluation,
        "incident": incident,
        "analyst_notes": _load_notes(incident["id"], db_path) if incident else [],
        "scope_warning": SCOPE_WARNING,
    }


def add_analyst_note(
    incident_id: int,
    status: str,
    note: str,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    clean_status = status.strip() or "Investigating"
    clean_note = note.strip() or "No analyst note provided."
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO analyst_notes (incident_id, status, note, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (incident_id, clean_status, clean_note, _now()),
        )
        connection.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (clean_status, incident_id),
        )
    return {"incident_id": incident_id, "status": clean_status, "note": clean_note}


def evaluate_detection(
    scenario: LiveScenario,
    events: list[dict[str, object]],
) -> dict[str, object]:
    if scenario.primary_detection == "SENT-006":
        return _evaluate_sent_006(events)
    if scenario.primary_detection == "ENTRA-003":
        return _evaluate_entra_003(events)
    if scenario.primary_detection == "AUTH-003":
        return _evaluate_auth_003(events)
    return {
        "status": "Observing",
        "reason": "No local evaluator is implemented for this detection.",
        "matched_fields": [],
    }


def evidence_markdown(
    scenario: LiveScenario,
    state: dict[str, object] | None = None,
) -> str:
    state = state or live_state(scenario.scenario_id)
    events = state.get("events") or scenario.events
    incident = state.get("incident")
    evaluation = state.get("evaluation", {})
    lines = [
        f"# Live lab evidence: {scenario.scenario_id}",
        "",
        f"- Title: {scenario.title}",
        f"- Primary detection: {scenario.primary_detection}",
        f"- Severity: {scenario.severity}",
        f"- Expected result: {scenario.expected_result}",
        f"- Observed status: {evaluation.get('status', 'Unknown')}",
        f"- Analyst goal: {scenario.analyst_goal}",
        "",
        "## Events",
        "",
    ]
    for event in events:
        lines.append(
            "- "
            f"t+{event['offset']}s {event['table']} {event['account']} "
            f"{event['ip']} {event['result']} - {event['detail']}"
        )
    lines.extend(["", "## Detection evaluation", ""])
    lines.append(f"- Status: {evaluation.get('status', 'Unknown')}")
    lines.append(f"- Reason: {evaluation.get('reason', 'No reason recorded')}")
    for field in evaluation.get("matched_fields", []):
        lines.append(f"- Match: {field}")
    if incident:
        lines.extend(["", "## Incident", ""])
        lines.append(f"- ID: {incident['id']}")
        lines.append(f"- Status: {incident['status']}")
        lines.append(f"- Account: {incident['account']}")
        lines.append(f"- IP: {incident['ip']}")
        lines.append(f"- Host: {incident['host']}")
    lines.extend(["", "## Scope", "", SCOPE_WARNING, ""])
    return "\n".join(lines)


def _evaluate_and_store_incident(scenario: LiveScenario, db_path: Path) -> None:
    state = live_state(scenario.scenario_id, db_path)
    evaluation = state["evaluation"]
    if evaluation["status"] != "Alert" or state["incident"]:
        return
    matched = evaluation.get("matched_entities", {})
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO incidents (
              scenario_id, detection, severity, status, account, ip, host, reason, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scenario.scenario_id,
                scenario.primary_detection,
                scenario.severity,
                "New",
                matched.get("account", "-"),
                matched.get("ip", "-"),
                matched.get("host", "-"),
                str(evaluation["reason"]),
                _now(),
            ),
        )


def _evaluate_sent_006(events: list[dict[str, object]]) -> dict[str, object]:
    risky = [
        event
        for event in events
        if event["table"] == "SigninLogs" and event["result"] == "success"
    ]
    failures = [event for event in events if _is_windows_result(event, "failure")]
    successes = [event for event in events if _is_windows_result(event, "success")]
    for cloud in risky:
        for success in successes:
            account_match = _account_key(cloud["account"]) == _account_key(success["account"])
            ip_match = cloud["ip"] == success["ip"]
            related_failures = [
                failure
                for failure in failures
                if _account_key(failure["account"]) == _account_key(success["account"])
                and failure["ip"] == success["ip"]
            ]
            if account_match and ip_match and len(related_failures) >= 2:
                return _alert_evaluation(
                    "Cloud risk, repeated Windows failures and Windows success matched.",
                    cloud,
                    success,
                    ["account", "ip", "SigninLogs", "SecurityEvent"],
                )
    if risky and failures:
        return _observing_evaluation(
            "Cloud risk and endpoint failures observed; waiting for matching success.",
            ["SigninLogs", "SecurityEvent", "account", "ip"],
        )
    if risky:
        return _observing_evaluation(
            "Cloud risk observed; waiting for endpoint activity.",
            ["SigninLogs", "account", "ip"],
        )
    return _observing_evaluation("Waiting for risky cloud identity event.", [])


def _evaluate_entra_003(events: list[dict[str, object]]) -> dict[str, object]:
    denials = [
        event
        for event in events
        if event["table"] == "SigninLogs" and event["result"] == "mfa_denied"
    ]
    successes = [
        event
        for event in events
        if event["table"] == "SigninLogs" and event["result"] == "success"
    ]
    for success in successes:
        related_denials = [
            denial
            for denial in denials
            if denial["account"] == success["account"] and denial["ip"] == success["ip"]
        ]
        if len(related_denials) >= 2:
            return _alert_evaluation(
                "Repeated MFA denials followed by success for same account and IP.",
                related_denials[0],
                success,
                ["account", "ip", "mfa_denied", "success"],
            )
    if len(denials) >= 2:
        return _observing_evaluation(
            "Repeated MFA denials observed; waiting for success.",
            ["account", "ip", "mfa_denied"],
        )
    return _observing_evaluation("Waiting for repeated MFA denial pattern.", [])


def _evaluate_auth_003(events: list[dict[str, object]]) -> dict[str, object]:
    failures = [event for event in events if _is_windows_result(event, "failure")]
    successes = [event for event in events if _is_windows_result(event, "success")]
    for success in successes:
        related_failures = [
            failure
            for failure in failures
            if failure["account"] == success["account"] and failure["ip"] == success["ip"]
        ]
        if len(related_failures) >= 2:
            return _alert_evaluation(
                "Repeated Windows failures followed by success for same account and IP.",
                related_failures[0],
                success,
                ["account", "ip", "host", "4625", "4624"],
            )
    if len(failures) >= 2:
        return _observing_evaluation(
            "Repeated Windows failures observed; waiting for successful logon.",
            ["account", "ip", "4625"],
        )
    return _observing_evaluation("Waiting for repeated Windows failures.", [])


def _alert_evaluation(
    reason: str,
    first: dict[str, object],
    last: dict[str, object],
    matched_fields: list[str],
) -> dict[str, object]:
    return {
        "status": "Alert",
        "reason": reason,
        "matched_fields": matched_fields,
        "matched_entities": {
            "account": str(last["account"]),
            "ip": str(last["ip"]),
            "host": str(last["host"]),
            "first_table": str(first["table"]),
            "last_table": str(last["table"]),
        },
    }


def _observing_evaluation(reason: str, matched_fields: list[str]) -> dict[str, object]:
    return {
        "status": "Observing",
        "reason": reason,
        "matched_fields": matched_fields,
        "matched_entities": {},
    }


def _is_windows_result(event: dict[str, object], result: str) -> bool:
    return event["table"] == "SecurityEvent" and event["result"] == result


def _account_key(value: object) -> str:
    text = str(value).lower()
    return text.split("@", maxsplit=1)[0]


def _load_events(scenario_id: str, db_path: Path) -> list[dict[str, object]]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT payload FROM events
            WHERE scenario_id = ?
            ORDER BY sequence
            """,
            (scenario_id,),
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def _load_incident(scenario_id: str, db_path: Path) -> dict[str, object] | None:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, detection, severity, status, account, ip, host, reason, created_at
            FROM incidents
            WHERE scenario_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (scenario_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "detection": row[1],
        "severity": row[2],
        "status": row[3],
        "account": row[4],
        "ip": row[5],
        "host": row[6],
        "reason": row[7],
        "created_at": row[8],
    }


def _load_notes(incident_id: int, db_path: Path) -> list[dict[str, object]]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, status, note, created_at
            FROM analyst_notes
            WHERE incident_id = ?
            ORDER BY id
            """,
            (incident_id,),
        ).fetchall()
    return [
        {"id": row[0], "status": row[1], "note": row[2], "created_at": row[3]}
        for row in rows
    ]


def _require_scenario(scenario_id: str) -> LiveScenario:
    scenario = get_scenario(scenario_id)
    if scenario is None:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    return scenario


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def render_live_app() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Detection Live Lab</title>
  <style>
    :root {{
      --bg: #f3f6fb;
      --ink: #182233;
      --muted: #5b6778;
      --panel: #ffffff;
      --line: #d7e0eb;
      --accent: #0d6efd;
      --alert: #b42318;
      --ok: #137333;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--ink);
    }}
    header {{
      background: #101828;
      color: white;
      padding: 24px;
    }}
    main {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 20px;
      display: grid;
      gap: 16px;
    }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ font-size: 2rem; }}
    h2 {{ font-size: 1.2rem; }}
    p {{ margin: 8px 0 0; color: var(--muted); }}
    button, select {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      background: white;
      color: var(--ink);
      font-weight: 700;
    }}
    button.primary {{ background: var(--accent); color: white; border-color: var(--accent); }}
    .warning {{
      border: 1px solid #e9c86a;
      background: #fff6dd;
      padding: 12px;
      font-weight: 700;
    }}
    .toolbar, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .toolbar {{
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }}
    input, textarea {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      width: 100%;
      font: inherit;
    }}
    textarea {{ min-height: 84px; }}
    .grid {{
      display: grid;
      grid-template-columns: 1.35fr .65fr;
      gap: 16px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #f8fbff;
    }}
    .metric strong {{ display: block; font-size: 1.4rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: .92rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 9px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); }}
    .timeline {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 8px;
    }}
    .timeline li {{
      border-left: 4px solid var(--accent);
      background: #f8fbff;
      padding: 10px;
    }}
    .timeline li.alert {{ border-left-color: var(--alert); }}
    .pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      border: 1px solid var(--line);
      background: white;
      font-size: .82rem;
      font-weight: 700;
    }}
    .alert-text {{ color: var(--alert); font-weight: 700; }}
    .ok-text {{ color: var(--ok); font-weight: 700; }}
    .note-form {{ display: grid; gap: 8px; margin-top: 12px; }}
    @media (max-width: 900px) {{
      .grid, .cards {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Identity Detection Live Lab</h1>
    <p>Local synthetic replay for identity detection engineering.</p>
  </header>
  <main>
    <div class="warning">{SCOPE_WARNING}</div>
    <section class="toolbar">
      <label for="scenario">Scenario</label>
      <select id="scenario"></select>
      <label for="speed">Speed</label>
      <select id="speed">
        <option value="1200">1x</option>
        <option value="650">2x</option>
        <option value="120">Instant</option>
      </select>
      <button id="start" class="primary">Start</button>
      <button id="pause">Pause</button>
      <button id="reset">Reset</button>
      <button id="export-json">Export JSON</button>
      <button id="export-md">Export MD</button>
    </section>
    <section class="cards">
      <div class="metric"><span>Detection</span><strong id="detection">-</strong></div>
      <div class="metric"><span>Severity</span><strong id="severity">-</strong></div>
      <div class="metric"><span>Expected</span><strong id="expected">-</strong></div>
      <div class="metric"><span>Status</span><strong id="status">Ready</strong></div>
    </section>
    <section class="panel">
      <h2>Rule evaluation</h2>
      <p id="rule-reason">Waiting for synthetic events.</p>
      <p id="matched-fields"></p>
    </section>
    <section class="grid">
      <div class="panel">
        <h2>Event stream</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th><th>Table</th><th>Account</th><th>IP</th><th>Host</th><th>Result</th><th>Detail</th>
            </tr>
          </thead>
          <tbody id="events"></tbody>
        </table>
      </div>
      <div class="panel">
        <h2>Incident timeline</h2>
        <p id="summary"></p>
        <ul id="timeline" class="timeline"></ul>
        <div class="note-form">
          <h3>Analyst action</h3>
          <select id="analyst-status">
            <option>Investigating</option>
            <option>Benign</option>
            <option>Suspicious</option>
            <option>Escalated</option>
          </select>
          <textarea id="analyst-note" placeholder="Analyst note"></textarea>
          <button id="save-note">Save note</button>
          <p id="note-status"></p>
        </div>
      </div>
    </section>
  </main>
  <script>
    const state = {{
      scenarios: [],
      scenario: null,
      timer: null,
      incident: null
    }};

    const $ = (id) => document.getElementById(id);

    async function loadScenarios() {{
      const response = await fetch('/api/scenarios');
      state.scenarios = await response.json();
      $('scenario').innerHTML = state.scenarios
        .map((item) => {{
          const label = `${{item.scenario_id}} - ${{item.title}}`;
          return `<option value="${{item.scenario_id}}">${{label}}</option>`;
        }})
        .join('');
      await loadScenario(state.scenarios[0].scenario_id);
    }}

    async function loadScenario(id) {{
      const response = await fetch(`/api/scenarios/${{id}}`);
      state.scenario = await response.json();
      await reset();
    }}

    async function reset() {{
      clearInterval(state.timer);
      state.timer = null;
      state.incident = null;
      const response = await fetch(`/api/reset?scenario=${{state.scenario.scenario_id}}`, {{
        method: 'POST'
      }});
      const payload = await response.json();
      $('summary').textContent = state.scenario.summary;
      $('detection').textContent = state.scenario.primary_detection;
      $('severity').textContent = state.scenario.severity;
      $('expected').textContent = state.scenario.expected_result;
      $('note-status').textContent = '';
      renderState(payload);
    }}

    function start() {{
      if (!state.scenario || state.timer) return;
      $('status').textContent = 'Running';
      state.timer = setInterval(tick, Number($('speed').value));
      tick();
    }}

    function pause() {{
      if (state.timer) {{
        clearInterval(state.timer);
        state.timer = null;
        $('status').textContent = 'Paused';
      }}
    }}

    async function tick() {{
      const response = await fetch(`/api/tick?scenario=${{state.scenario.scenario_id}}`, {{
        method: 'POST'
      }});
      const payload = await response.json();
      renderState(payload);
      if (payload.complete) {{
        clearInterval(state.timer);
        state.timer = null;
      }}
    }}

    function renderState(payload) {{
      state.incident = payload.incident;
      $('events').innerHTML = payload.events.map((event) => `
        <tr>
          <td>t+${{event.offset}}s</td>
          <td><span class="pill">${{event.table}}</span></td>
          <td>${{event.account}}</td>
          <td>${{event.ip}}</td>
          <td>${{event.host}}</td>
          <td>${{event.result}}</td>
          <td>${{event.detail}}</td>
        </tr>
      `).join('');
      $('rule-reason').textContent = payload.evaluation.reason;
      $('matched-fields').textContent = payload.evaluation.matched_fields.join(' | ');
      if (payload.incident) {{
        $('status').textContent = 'Alert';
      }} else if (payload.complete) {{
        $('status').textContent = 'Complete';
      }} else if (payload.event_count > 0) {{
        $('status').textContent = 'Observing';
      }} else {{
        $('status').textContent = 'Ready';
      }}
      renderTimeline(payload);
    }}

    function renderTimeline(payload) {{
      const items = [];
      payload.events.forEach((event) => {{
        items.push({{
          status: 'event',
          message: `${{event.table}}: ${{event.detail}}`
        }});
      }});
      if (payload.incident) {{
        items.push({{
          status: 'alert',
          message: `Incident #${{payload.incident.id}}: ${{payload.incident.reason}}`
        }});
      }}
      $('timeline').innerHTML = items.map((item) => {{
        const className = item.status === 'alert' ? 'alert' : '';
        const textClass = item.status === 'alert' ? 'alert-text' : 'ok-text';
        const label = item.status === 'alert' ? 'ALERT' : 'EVENT';
        return `<li class="${{className}}">` +
          `<strong class="${{textClass}}">${{label}}</strong>` +
          `<p>${{item.message}}</p></li>`;
      }}).join('');
    }}

    async function exportEvidence(format) {{
      const id = state.scenario.scenario_id;
      const response = await fetch(`/api/evidence?scenario=${{id}}&format=${{format}}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${{id}}-live-evidence.${{format}}`;
      link.click();
      URL.revokeObjectURL(url);
    }}

    async function saveNote() {{
      if (!state.incident) {{
        $('note-status').textContent = 'Run a scenario until an incident is created.';
        return;
      }}
      const response = await fetch('/api/analyst-note', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{
          incident_id: state.incident.id,
          status: $('analyst-status').value,
          note: $('analyst-note').value
        }})
      }});
      const payload = await response.json();
      $('note-status').textContent = `Saved: ${{payload.status}}`;
    }}

    $('scenario').addEventListener('change', (event) => loadScenario(event.target.value));
    $('start').addEventListener('click', start);
    $('pause').addEventListener('click', pause);
    $('reset').addEventListener('click', reset);
    $('export-json').addEventListener('click', () => exportEvidence('json'));
    $('export-md').addEventListener('click', () => exportEvidence('md'));
    $('save-note').addEventListener('click', saveNote);
    loadScenarios();
  </script>
</body>
</html>
"""


def serve_live(host: str = "127.0.0.1", port: int = 8090) -> int:
    server = ThreadingHTTPServer((host, port), LiveRequestHandler)
    print(f"Serving Identity Detection Live Lab at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        server.server_close()
    return 0


class LiveRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_text(render_live_app(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/scenarios":
            self._send_json(scenario_index())
            return
        if parsed.path.startswith("/api/scenarios/"):
            scenario_id = parsed.path.rsplit("/", maxsplit=1)[-1]
            scenario = get_scenario(scenario_id)
            if scenario is None:
                self._send_json({"error": "scenario not found"}, status=404)
                return
            self._send_json(scenario_to_dict(scenario))
            return
        if parsed.path == "/api/evidence":
            params = parse_qs(parsed.query)
            scenario_id = params.get("scenario", ["SENT-006-POS"])[0]
            output_format = params.get("format", ["json"])[0]
            scenario = get_scenario(scenario_id)
            if scenario is None:
                self._send_json({"error": "scenario not found"}, status=404)
                return
            if output_format == "md":
                self._send_text(
                    evidence_markdown(scenario, live_state(scenario_id)),
                    "text/markdown; charset=utf-8",
                )
                return
            self._send_json(live_state(scenario_id))
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        scenario_id = params.get("scenario", ["SENT-006-POS"])[0]
        try:
            if parsed.path == "/api/reset":
                self._send_json(reset_run(scenario_id))
                return
            if parsed.path == "/api/tick":
                self._send_json(tick_run(scenario_id))
                return
            if parsed.path == "/api/analyst-note":
                payload = self._read_json_body()
                result = add_analyst_note(
                    int(payload.get("incident_id", 0)),
                    str(payload.get("status", "Investigating")),
                    str(payload.get("note", "")),
                )
                self._send_json(result)
                return
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=404)
            return
        self._send_json({"error": "not found"}, status=404)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, payload: str, content_type: str, status: int = 200) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))
