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
ALLOWED_INCIDENT_STATUSES = {
    "New",
    "Investigating",
    "Benign",
    "Suspicious",
    "Escalated",
    "Closed",
}
ALLOWED_INSTRUCTOR_RATINGS = {
    "Needs guided practice",
    "Developing",
    "Ready for independent review",
}


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


@dataclass(frozen=True)
class SocCase:
    case_id: str
    title: str
    summary: str
    primary_detection: str
    severity: str
    events: list[dict[str, object]]
    tasks: list[dict[str, str]]


@dataclass(frozen=True)
class TrainingModule:
    module_id: str
    title: str
    audience: str
    case_id: str
    summary: str
    instructor_brief: str
    objectives: list[str]
    guided_steps: list[dict[str, str]]
    hints: list[str]
    expected_decisions: list[str]
    assessment: list[dict[str, object]]
    learning_flow: list[dict[str, str]]
    questions: list[dict[str, object]]


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


SOC_CASES: list[SocCase] = [
    SocCase(
        case_id="CASE-001",
        title="Cross-source identity investigation",
        summary=(
            "A guided SOC case with benign identity noise, unrelated endpoint activity and "
            "one cross-source identity incident for the analyst to close."
        ),
        primary_detection="SENT-006",
        severity="High",
        events=[
            {
                "offset": 0,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "nora.patel@example.test",
                "ip": "198.51.100.31",
                "host": "-",
                "result": "success",
                "severity": "Informational",
                "classification": "benign",
                "detail": "Expected browser sign-in from a known source.",
            },
            {
                "offset": 4,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "svc-backup",
                "ip": "192.0.2.20",
                "host": "SRV-BACKUP-01",
                "result": "failure",
                "severity": "Low",
                "classification": "benign",
                "detail": "Single failed service logon outside the correlated account.",
            },
            {
                "offset": 9,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "alex.morgan@example.test",
                "ip": "203.0.113.42",
                "host": "-",
                "result": "success",
                "severity": "High",
                "classification": "signal",
                "detail": "High-risk sign-in to Azure Portal not blocked by Conditional Access.",
            },
            {
                "offset": 13,
                "table": "AuditLogs",
                "source": "Entra",
                "account": "helpdesk.admin@example.test",
                "ip": "198.51.100.44",
                "host": "-",
                "result": "success",
                "severity": "Low",
                "classification": "benign",
                "detail": "Expected group membership update from helpdesk workflow.",
            },
            {
                "offset": 18,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "failure",
                "severity": "Medium",
                "classification": "signal",
                "detail": "Windows event 4625 failed logon.",
            },
            {
                "offset": 22,
                "table": "SigninLogs",
                "source": "Entra",
                "account": "jamie.lee@example.test",
                "ip": "198.51.100.17",
                "host": "-",
                "result": "mfa_denied",
                "severity": "Low",
                "classification": "benign",
                "detail": "Single MFA denial without follow-up success in this case window.",
            },
            {
                "offset": 27,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "failure",
                "severity": "Medium",
                "classification": "signal",
                "detail": "Second Windows event 4625 failed logon.",
            },
            {
                "offset": 34,
                "table": "SecurityEvent",
                "source": "Windows",
                "account": "alex.morgan",
                "ip": "203.0.113.42",
                "host": "WKST-042",
                "result": "success",
                "severity": "High",
                "classification": "signal",
                "detail": "Windows event 4624 successful logon after cloud risk and failures.",
            },
        ],
        tasks=[
            {
                "task_id": "review-account",
                "label": "Review account identity and expected owner.",
            },
            {"task_id": "review-ip", "label": "Check source IP across cloud and endpoint."},
            {"task_id": "review-host", "label": "Review impacted workstation context."},
            {"task_id": "review-mfa", "label": "Check MFA and Conditional Access context."},
            {"task_id": "review-correlation", "label": "Confirm Entra and Windows correlation."},
        ],
    )
]


TRAINING_MODULES: list[TrainingModule] = [
    TrainingModule(
        module_id="TRAIN-001",
        title="Investigating a cross-source identity incident",
        audience="Beginner SOC analysts",
        case_id="CASE-001",
        summary=(
            "Guided lesson for separating benign identity noise from a correlated "
            "Entra and Windows authentication incident."
        ),
        instructor_brief=(
            "Use this module to coach the learner through evidence triage, entity "
            "correlation and a defensible case closure. The instructor view scores "
            "progress, task completion, alert evidence and final decision."
        ),
        objectives=[
            "Identify benign noise before escalating an alert.",
            "Correlate account, IP and host across Entra and Windows events.",
            "Use entities and rule evaluation to explain why the incident alerted.",
            "Write an analyst note and close the case with a defensible decision.",
        ],
        guided_steps=[
            {
                "step_id": "observe-noise",
                "label": "Correctly identify unrelated benign activity.",
            },
            {
                "step_id": "find-signal",
                "label": "Correctly correlate the shared account and IP.",
            },
            {
                "step_id": "review-rule",
                "label": "Correctly explain the alert condition.",
            },
            {
                "step_id": "complete-tasks",
                "label": "Choose the appropriate triage action.",
            },
            {
                "step_id": "close-case",
                "label": "Close the case as Suspicious or Escalated with a note.",
            },
        ],
        hints=[
            (
                "Start by comparing classification values: benign events add context, "
                "signal events drive the alert."
            ),
            (
                "The strongest correlation uses the same account key and source IP "
                "across SigninLogs and SecurityEvent."
            ),
            (
                "A good closing note should mention cloud risk, repeated endpoint "
                "failures and the later success."
            ),
        ],
        expected_decisions=["Suspicious", "Escalated"],
        assessment=[
            {
                "name": "Analyst decisions",
                "max_points": 6,
                "description": "Learner makes defensible decisions from the evidence.",
            },
            {
                "name": "Evidence recognition",
                "max_points": 2,
                "description": "Learner reaches the alert and reviews the incident evidence.",
            },
            {
                "name": "Final decision",
                "max_points": 2,
                "description": "Learner closes as Suspicious or Escalated with a note.",
            },
        ],
        learning_flow=[
            {
                "flow_id": "briefing",
                "title": "Case briefing",
                "instruction": (
                    "You are reviewing a synthetic identity case. Your goal is to separate "
                    "benign activity from evidence that needs analyst attention."
                ),
            },
            {
                "flow_id": "timeline",
                "title": "Observe the timeline",
                "instruction": (
                    "Reveal the events one at a time. Identify at least one event that adds "
                    "context but does not by itself justify escalation."
                ),
            },
            {
                "flow_id": "entities",
                "title": "Correlate the entities",
                "instruction": (
                    "Review the account, IP address and host. Look for the values shared by "
                    "the cloud and endpoint events."
                ),
            },
            {
                "flow_id": "rule",
                "title": "Understand the alert",
                "instruction": (
                    "Continue the timeline until the local evaluator reaches Alert, then read "
                    "which fields and entities made the correlation meaningful."
                ),
            },
            {
                "flow_id": "triage",
                "title": "Complete the triage",
                "instruction": (
                    "Choose the next defensible analyst action from the evidence. Record the "
                    "account, source IP, host, MFA context and cross-source correlation "
                    "before you decide."
                ),
            },
            {
                "flow_id": "close",
                "title": "Close the case",
                "instruction": (
                    "Write a short decision note that explains the correlated evidence, then "
                    "close the synthetic case as Suspicious or Escalated."
                ),
            },
            {
                "flow_id": "outcome",
                "title": "Review the outcome",
                "instruction": (
                    "Review your feedback and assessment. Facilitator notes remain unavailable "
                    "until the case has been closed."
                ),
            },
        ],
        questions=[
            {
                "question_id": "identify-benign",
                "flow_id": "timeline",
                "checkpoint_id": "observe-noise",
                "minimum_events": 4,
                "prompt": (
                    "Which revealed event is unrelated benign context for this "
                    "investigation?"
                ),
                "options": [
                    {
                        "value": "service-failure",
                        "label": "t+4 SecurityEvent: single svc-backup failure from 192.0.2.20.",
                    },
                    {
                        "value": "risky-sign-in",
                        "label": "t+9 SigninLogs: high-risk sign-in for alex.morgan.",
                    },
                    {
                        "value": "group-update",
                        "label": "t+13 AuditLogs: expected helpdesk group update.",
                    },
                ],
                "correct_answer": "service-failure",
                "feedback_correct": (
                    "Correct. The service account is unrelated to the shared account "
                    "and IP correlation."
                ),
                "feedback_retry": (
                    "Not yet. Compare each event with the account and IP that later "
                    "form the incident."
                ),
            },
            {
                "question_id": "correlate-entities",
                "flow_id": "entities",
                "checkpoint_id": "find-signal",
                "minimum_events": 4,
                "prompt": "Which account and IP pair connects the cloud and Windows evidence?",
                "options": [
                    {
                        "value": "alex-shared-ip",
                        "label": "alex.morgan and 203.0.113.42",
                    },
                    {
                        "value": "nora-known-ip",
                        "label": "nora.patel and 198.51.100.31",
                    },
                    {
                        "value": "helpdesk-ip",
                        "label": "helpdesk.admin and 198.51.100.44",
                    },
                ],
                "correct_answer": "alex-shared-ip",
                "feedback_correct": (
                    "Correct. The account key and source IP are the cross-source pivot "
                    "for this case."
                ),
                "feedback_retry": (
                    "Not yet. Focus on the values that appear in both Entra and "
                    "SecurityEvent records."
                ),
            },
            {
                "question_id": "explain-rule",
                "flow_id": "rule",
                "checkpoint_id": "review-rule",
                "requires_alert": True,
                "prompt": "Which sequence explains why SENT-006 alerts?",
                "options": [
                    {
                        "value": "correlated-sequence",
                        "label": (
                            "High-risk Entra sign-in, repeated Windows failures, then a "
                            "Windows success for the shared identity and IP."
                        ),
                    },
                    {
                        "value": "single-event",
                        "label": (
                            "Any single failed Windows logon is sufficient for a "
                            "cross-source incident."
                        ),
                    },
                    {
                        "value": "benign-noise",
                        "label": "The unrelated service failure is the main cause of the alert.",
                    },
                ],
                "correct_answer": "correlated-sequence",
                "feedback_correct": (
                    "Correct. The alert depends on the ordered, cross-source correlation "
                    "rather than one isolated event."
                ),
                "feedback_retry": (
                    "Not yet. Wait for Alert, then compare the evaluator reason with "
                    "the event sequence."
                ),
            },
            {
                "question_id": "choose-triage",
                "flow_id": "triage",
                "checkpoint_id": "complete-tasks",
                "prompt": (
                    "What is the best next analyst action before closing this synthetic "
                    "case?"
                ),
                "options": [
                    {
                        "value": "document-correlation",
                        "label": (
                            "Document the account, shared IP, host and cloud risk context, "
                            "then make a reasoned decision."
                        ),
                    },
                    {
                        "value": "mark-all-benign",
                        "label": (
                            "Mark every timeline event benign because some are expected "
                            "activity."
                        ),
                    },
                    {
                        "value": "change-host",
                        "label": "Make a change to the workstation before recording the evidence.",
                    },
                ],
                "correct_answer": "document-correlation",
                "feedback_correct": (
                    "Correct. Evidence-led documentation comes before a defensible "
                    "decision in this local lab."
                ),
                "feedback_retry": (
                    "Not yet. Separate the benign context from the correlated evidence "
                    "and preserve that reasoning in the case note."
                ),
            },
        ],
    )
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


def case_index(db_path: Path = LIVE_DB) -> dict[str, object]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, case_id, run_key, status, decision, started_at, closed_at
            FROM case_runs
            ORDER BY id DESC
            """
        ).fetchall()
    return {
        "cases": [case_to_dict(case) for case in SOC_CASES],
        "runs": [
            {
                "id": row[0],
                "case_id": row[1],
                "run_key": row[2],
                "status": row[3],
                "decision": row[4],
                "started_at": row[5],
                "closed_at": row[6],
            }
            for row in rows
        ],
        "scope_warning": SCOPE_WARNING,
    }


def get_case(case_id: str) -> SocCase | None:
    return next((case for case in SOC_CASES if case.case_id == case_id), None)


def training_index(db_path: Path = LIVE_DB) -> dict[str, object]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, module_id, case_run_id, status, feedback, started_at, completed_at
            FROM training_runs
            ORDER BY id DESC
            """
        ).fetchall()
    return {
        "modules": [training_to_dict(module) for module in TRAINING_MODULES],
        "runs": [
            {
                "id": row[0],
                "module_id": row[1],
                "case_run_id": row[2],
                "status": row[3],
                "feedback": row[4],
                "started_at": row[5],
                "completed_at": row[6],
            }
            for row in rows
        ],
        "scope_warning": SCOPE_WARNING,
    }


def get_training_module(module_id: str) -> TrainingModule | None:
    return next(
        (module for module in TRAINING_MODULES if module.module_id == module_id),
        None,
    )


def case_to_dict(case: SocCase) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "title": case.title,
        "summary": case.summary,
        "primary_detection": case.primary_detection,
        "severity": case.severity,
        "event_total": len(case.events),
        "tasks": case.tasks,
        "scope_warning": SCOPE_WARNING,
    }


def training_to_dict(module: TrainingModule) -> dict[str, object]:
    return {
        "module_id": module.module_id,
        "title": module.title,
        "audience": module.audience,
        "case_id": module.case_id,
        "summary": module.summary,
        "instructor_brief": module.instructor_brief,
        "objectives": module.objectives,
        "guided_steps": module.guided_steps,
        "hints": module.hints,
        "expected_decisions": module.expected_decisions,
        "assessment": module.assessment,
        "learning_flow": module.learning_flow,
        "scope_warning": SCOPE_WARNING,
    }


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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS case_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                run_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                decision TEXT NOT NULL,
                decision_note TEXT NOT NULL,
                started_at TEXT NOT NULL,
                closed_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS case_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_run_id INTEGER NOT NULL,
                task_id TEXT NOT NULL,
                label TEXT NOT NULL,
                completed INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(case_run_id, task_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_id TEXT NOT NULL,
                case_run_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                feedback TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                training_run_id INTEGER NOT NULL,
                checkpoint_id TEXT NOT NULL,
                label TEXT NOT NULL,
                completed INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(training_run_id, checkpoint_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_hints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                training_run_id INTEGER NOT NULL,
                hint_index INTEGER NOT NULL,
                hint TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_progress (
                training_run_id INTEGER PRIMARY KEY,
                current_step INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_answers (
                training_run_id INTEGER NOT NULL,
                question_id TEXT NOT NULL,
                answer TEXT NOT NULL,
                correct INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (training_run_id, question_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS instructor_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                training_run_id INTEGER NOT NULL UNIQUE,
                rating TEXT NOT NULL,
                observation TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def reset_run(scenario_id: str, db_path: Path = LIVE_DB) -> dict[str, object]:
    scenario = _require_scenario(scenario_id)
    init_store(db_path)
    now = _now()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            DELETE FROM analyst_notes
            WHERE incident_id IN (
              SELECT id FROM incidents WHERE scenario_id = ?
            )
            """,
            (scenario_id,),
        )
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
    detail = update_incident_action(incident_id, status, note, db_path)
    return {"incident_id": incident_id, "status": detail["status"], "note": note.strip()}


def incident_queue(db_path: Path = LIVE_DB) -> list[dict[str, object]]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
              i.id, i.scenario_id, i.detection, i.severity, i.status, i.account, i.ip,
              i.host, i.reason, i.created_at,
              COUNT(DISTINCT e.id) AS event_count,
              COUNT(DISTINCT n.id) AS note_count
            FROM incidents i
            LEFT JOIN events e ON e.scenario_id = i.scenario_id
            LEFT JOIN analyst_notes n ON n.incident_id = i.id
            GROUP BY
              i.id, i.scenario_id, i.detection, i.severity, i.status, i.account, i.ip,
              i.host, i.reason, i.created_at
            ORDER BY i.id DESC
            """
        ).fetchall()
    return [
        {
            "id": row[0],
            "scenario_id": row[1],
            "detection": row[2],
            "severity": row[3],
            "status": row[4],
            "account": row[5],
            "ip": row[6],
            "host": row[7],
            "reason": row[8],
            "created_at": row[9],
            "event_count": row[10],
            "note_count": row[11],
        }
        for row in rows
    ]


def incident_detail(incident_id: int, db_path: Path = LIVE_DB) -> dict[str, object] | None:
    init_store(db_path)
    incident = _load_incident_by_id(incident_id, db_path)
    if incident is None:
        return None
    scenario_id = str(incident["scenario_id"])
    scenario = get_scenario(scenario_id)
    case_run = _load_case_run_by_key(scenario_id, db_path)
    events = _load_events(scenario_id, db_path)
    if scenario is not None:
        scenario_payload = scenario_to_dict(scenario)
        evaluation = evaluate_detection(scenario, events)
    elif case_run is not None:
        case = _require_case(str(case_run["case_id"]))
        scenario_payload = {
            "scenario_id": scenario_id,
            "title": case.title,
            "summary": case.summary,
            "severity": case.severity,
            "primary_detection": case.primary_detection,
            "expected_result": "Alert",
            "analyst_goal": "Close the synthetic SOC case with evidence.",
            "scope_warning": SCOPE_WARNING,
            "events": case.events,
            "detection_steps": [],
        }
        evaluation = evaluate_case_detection(case, events)
    else:
        raise ValueError(f"Unknown incident source: {scenario_id}")
    return {
        "incident": incident,
        "scenario": scenario_payload,
        "events": events,
        "entities": incident_entities(incident, events),
        "evaluation": evaluation,
        "notes": _load_notes(incident_id, db_path),
        "scope_warning": SCOPE_WARNING,
    }


def incident_entities(
    incident: dict[str, object],
    events: list[dict[str, object]],
) -> dict[str, list[str]]:
    def unique(field: str) -> list[str]:
        values = {
            str(event.get(field, "-")) for event in events if str(event.get(field, "-")) != "-"
        }
        return sorted(values)

    account = str(incident.get("account", "-"))
    ip = str(incident.get("ip", "-"))
    host = str(incident.get("host", "-"))
    return {
        "accounts": sorted({account, *unique("account")} - {"-"}),
        "ips": sorted({ip, *unique("ip")} - {"-"}),
        "hosts": sorted({host, *unique("host")} - {"-"}),
        "sources": unique("source"),
        "tables": unique("table"),
    }


def update_incident_action(
    incident_id: int,
    status: str,
    note: str,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    clean_status = status.strip() or "Investigating"
    if clean_status not in ALLOWED_INCIDENT_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_INCIDENT_STATUSES))
        raise ValueError(f"Invalid incident status: {clean_status}. Allowed: {allowed}")
    clean_note = note.strip()
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown incident: {incident_id}")
        connection.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (clean_status, incident_id),
        )
        if clean_note:
            connection.execute(
                """
                INSERT INTO analyst_notes (incident_id, status, note, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (incident_id, clean_status, clean_note, _now()),
            )
    detail = incident_detail(incident_id, db_path)
    if detail is None:
        raise ValueError(f"Unknown incident: {incident_id}")
    return detail["incident"]


def reset_runtime(db_path: Path = LIVE_DB) -> dict[str, object]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        counts = {
            "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "notes": connection.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0],
            "run_state": connection.execute("SELECT COUNT(*) FROM run_state").fetchone()[0],
            "case_runs": connection.execute("SELECT COUNT(*) FROM case_runs").fetchone()[0],
            "case_tasks": connection.execute("SELECT COUNT(*) FROM case_tasks").fetchone()[0],
            "training_runs": connection.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0],
            "training_checkpoints": connection.execute(
                "SELECT COUNT(*) FROM training_checkpoints"
            ).fetchone()[0],
            "training_hints": connection.execute("SELECT COUNT(*) FROM training_hints").fetchone()[
                0
            ],
            "training_progress": connection.execute(
                "SELECT COUNT(*) FROM training_progress"
            ).fetchone()[0],
            "training_answers": connection.execute(
                "SELECT COUNT(*) FROM training_answers"
            ).fetchone()[0],
            "instructor_reviews": connection.execute(
                "SELECT COUNT(*) FROM instructor_reviews"
            ).fetchone()[0],
        }
        connection.execute("DELETE FROM instructor_reviews")
        connection.execute("DELETE FROM training_answers")
        connection.execute("DELETE FROM training_progress")
        connection.execute("DELETE FROM training_hints")
        connection.execute("DELETE FROM training_checkpoints")
        connection.execute("DELETE FROM training_runs")
        connection.execute("DELETE FROM case_tasks")
        connection.execute("DELETE FROM case_runs")
        connection.execute("DELETE FROM analyst_notes")
        connection.execute("DELETE FROM incidents")
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM run_state")
    return {"reset": True, "deleted": counts, "scope_warning": SCOPE_WARNING}


def start_case_run(case_id: str = "CASE-001", db_path: Path = LIVE_DB) -> dict[str, object]:
    case = _require_case(case_id)
    init_store(db_path)
    now = _now()
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO case_runs (
              case_id, run_key, status, decision, decision_note, started_at, closed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (case.case_id, "pending", "Running", "", "", now, ""),
        )
        run_id = int(cursor.lastrowid)
        run_key = f"{case.case_id}-RUN-{run_id}"
        connection.execute(
            "UPDATE case_runs SET run_key = ? WHERE id = ?",
            (run_key, run_id),
        )
        connection.execute(
            """
            INSERT INTO run_state (scenario_id, next_index, started_at, updated_at)
            VALUES (?, 0, ?, ?)
            """,
            (run_key, now, now),
        )
        for task in case.tasks:
            connection.execute(
                """
                INSERT INTO case_tasks (case_run_id, task_id, label, completed, updated_at)
                VALUES (?, ?, ?, 0, ?)
                """,
                (run_id, task["task_id"], task["label"], now),
            )
    return case_run_detail(run_id, db_path)


def tick_case_run(case_run_id: int, db_path: Path = LIVE_DB) -> dict[str, object]:
    row = _load_case_run(case_run_id, db_path)
    if row is None:
        raise ValueError(f"Unknown case run: {case_run_id}")
    if row["status"] == "Closed":
        return case_run_detail(case_run_id, db_path)
    case = _require_case(str(row["case_id"]))
    run_key = str(row["run_key"])
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        state = connection.execute(
            "SELECT next_index FROM run_state WHERE scenario_id = ?",
            (run_key,),
        ).fetchone()
        next_index = int(state[0]) if state else 0
        if next_index >= len(case.events):
            return case_run_detail(case_run_id, db_path)
        event = dict(case.events[next_index])
        event["sequence"] = next_index + 1
        event["emitted_at"] = _now()
        event["case_run_id"] = case_run_id
        event["case_id"] = case.case_id
        connection.execute(
            """
            INSERT INTO events (scenario_id, sequence, emitted_at, payload)
            VALUES (?, ?, ?, ?)
            """,
            (run_key, next_index + 1, event["emitted_at"], json.dumps(event)),
        )
        connection.execute(
            """
            INSERT INTO run_state (scenario_id, next_index, started_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scenario_id) DO UPDATE SET
              next_index = excluded.next_index,
              updated_at = excluded.updated_at
            """,
            (run_key, next_index + 1, row["started_at"], _now()),
        )
    _evaluate_and_store_case_incident(case, case_run_id, db_path)
    return case_run_detail(case_run_id, db_path)


def case_run_detail(case_run_id: int, db_path: Path = LIVE_DB) -> dict[str, object]:
    row = _load_case_run(case_run_id, db_path)
    if row is None:
        raise ValueError(f"Unknown case run: {case_run_id}")
    case = _require_case(str(row["case_id"]))
    run_key = str(row["run_key"])
    events = _load_events(run_key, db_path)
    incident = _load_incident(run_key, db_path)
    evaluation = evaluate_case_detection(case, events)
    tasks = _load_case_tasks(case_run_id, db_path)
    return {
        "run": row,
        "case": case_to_dict(case),
        "events": events,
        "event_count": len(events),
        "complete": len(events) >= len(case.events),
        "next_event": len(events) + 1 if len(events) < len(case.events) else None,
        "counts": _case_event_counts(events),
        "incident": incident,
        "entities": incident_entities(incident or {}, events),
        "evaluation": evaluation,
        "tasks": tasks,
        "scope_warning": SCOPE_WARNING,
    }


def update_case_task(
    case_run_id: int,
    task_id: str,
    completed: bool,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE case_tasks
            SET completed = ?, updated_at = ?
            WHERE case_run_id = ? AND task_id = ?
            """,
            (1 if completed else 0, _now(), case_run_id, task_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Unknown case task: {task_id}")
    return case_run_detail(case_run_id, db_path)


def close_case_run(
    case_run_id: int,
    decision: str,
    note: str,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    clean_decision = decision.strip() or "Closed"
    if clean_decision not in {"Benign", "Suspicious", "Escalated", "Closed"}:
        raise ValueError(f"Invalid case decision: {clean_decision}")
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE case_runs
            SET status = 'Closed', decision = ?, decision_note = ?, closed_at = ?
            WHERE id = ?
            """,
            (clean_decision, note.strip(), _now(), case_run_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Unknown case run: {case_run_id}")
    detail = case_run_detail(case_run_id, db_path)
    incident = detail["incident"]
    if incident:
        update_incident_action(int(incident["id"]), clean_decision, note, db_path)
        detail = case_run_detail(case_run_id, db_path)
    _complete_training_for_case(case_run_id, db_path)
    return detail


def start_training_run(
    module_id: str = "TRAIN-001",
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    module = _require_training_module(module_id)
    case_detail = start_case_run(module.case_id, db_path)
    now = _now()
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO training_runs (
              module_id, case_run_id, status, feedback, started_at, completed_at
            )
            VALUES (?, ?, 'In progress', '', ?, '')
            """,
            (module.module_id, case_detail["run"]["id"], now),
        )
        training_run_id = int(cursor.lastrowid)
        for step in module.guided_steps:
            connection.execute(
                """
                INSERT INTO training_checkpoints (
                  training_run_id, checkpoint_id, label, completed, updated_at
                )
                VALUES (?, ?, ?, 0, ?)
                """,
                (training_run_id, step["step_id"], step["label"], now),
            )
        connection.execute(
            """
            INSERT INTO training_progress (training_run_id, current_step, updated_at)
            VALUES (?, 0, ?)
            """,
            (training_run_id, now),
        )
    return training_run_detail(training_run_id, db_path)


def training_run_detail(
    training_run_id: int,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    row = _load_training_run(training_run_id, db_path)
    if row is None:
        raise ValueError(f"Unknown training run: {training_run_id}")
    module = _require_training_module(str(row["module_id"]))
    case_detail = case_run_detail(int(row["case_run_id"]), db_path)
    checkpoints = _load_training_checkpoints(training_run_id, db_path)
    answers = _load_training_answers(training_run_id, db_path)
    hints = _load_training_hints(training_run_id, db_path)
    guide = _training_guide(
        module,
        _load_training_progress(training_run_id, db_path),
        checkpoints,
        case_detail,
    )
    return {
        "run": row,
        "module": training_to_dict(module),
        "case_run": case_detail,
        "checkpoints": checkpoints,
        "questions": _training_questions_for_detail(module, answers),
        "answers": answers,
        "hints": hints,
        "guide": guide,
        "feedback": _training_feedback(row, case_detail, module),
        "instructor": _training_instructor_summary(
            row,
            case_detail,
            module,
            checkpoints,
            answers,
            hints,
        ),
        "review": _load_instructor_review(training_run_id, db_path),
        "scope_warning": SCOPE_WARNING,
    }


def save_instructor_review(
    training_run_id: int,
    rating: str,
    observation: str,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    if _load_training_run(training_run_id, db_path) is None:
        raise ValueError(f"Unknown training run: {training_run_id}")
    clean_rating = rating.strip() or "Developing"
    if clean_rating not in ALLOWED_INSTRUCTOR_RATINGS:
        raise ValueError(f"Invalid instructor rating: {clean_rating}")
    clean_observation = observation.strip()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO instructor_reviews (
              training_run_id, rating, observation, updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(training_run_id) DO UPDATE SET
              rating = excluded.rating,
              observation = excluded.observation,
              updated_at = excluded.updated_at
            """,
            (training_run_id, clean_rating, clean_observation, _now()),
        )
    return training_run_detail(training_run_id, db_path)


def set_training_guide_step(
    training_run_id: int,
    step_index: int,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    run = _load_training_run(training_run_id, db_path)
    if run is None:
        raise ValueError(f"Unknown training run: {training_run_id}")
    module = _require_training_module(str(run["module_id"]))
    case_detail = case_run_detail(int(run["case_run_id"]), db_path)
    checkpoints = _load_training_checkpoints(training_run_id, db_path)
    maximum_step = _maximum_training_step(module, checkpoints, case_detail)
    clean_index = max(0, min(step_index, maximum_step))
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO training_progress (training_run_id, current_step, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(training_run_id) DO UPDATE SET
              current_step = excluded.current_step,
              updated_at = excluded.updated_at
            """,
            (training_run_id, clean_index, _now()),
        )
    return training_run_detail(training_run_id, db_path)


def submit_training_answer(
    training_run_id: int,
    question_id: str,
    answer: str,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    run = _load_training_run(training_run_id, db_path)
    if run is None:
        raise ValueError(f"Unknown training run: {training_run_id}")
    module = _require_training_module(str(run["module_id"]))
    question = _training_question(module, question_id)
    if question is None:
        raise ValueError(f"Unknown training question: {question_id}")
    question_step = next(
        index
        for index, step in enumerate(module.learning_flow)
        if step["flow_id"] == question["flow_id"]
    )
    if _load_training_progress(training_run_id, db_path) < question_step:
        raise ValueError("Continue to the relevant guided screen before answering.")
    case_detail = case_run_detail(int(run["case_run_id"]), db_path)
    minimum_events = int(question.get("minimum_events", 0))
    if case_detail["event_count"] < minimum_events:
        raise ValueError("Reveal more timeline events before answering this question.")
    if question.get("requires_alert") and case_detail["evaluation"]["status"] != "Alert":
        raise ValueError("Reach the Alert state before answering this question.")
    clean_answer = answer.strip()
    options = question["options"]
    if clean_answer not in {str(option["value"]) for option in options}:
        raise ValueError("Answer must be one of the available options.")
    correct = clean_answer == question["correct_answer"]
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        previous = connection.execute(
            """
            SELECT attempts FROM training_answers
            WHERE training_run_id = ? AND question_id = ?
            """,
            (training_run_id, question_id),
        ).fetchone()
        attempts = int(previous[0]) + 1 if previous is not None else 1
        connection.execute(
            """
            INSERT INTO training_answers (
              training_run_id, question_id, answer, correct, attempts, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(training_run_id, question_id) DO UPDATE SET
              answer = excluded.answer,
              correct = excluded.correct,
              attempts = excluded.attempts,
              updated_at = excluded.updated_at
            """,
            (training_run_id, question_id, clean_answer, 1 if correct else 0, attempts, _now()),
        )
        if correct:
            connection.execute(
                """
                UPDATE training_checkpoints
                SET completed = 1, updated_at = ?
                WHERE training_run_id = ? AND checkpoint_id = ?
                """,
                (str(_now()), training_run_id, str(question["checkpoint_id"])),
            )
    return training_run_detail(training_run_id, db_path)


def update_training_checkpoint(
    training_run_id: int,
    checkpoint_id: str,
    completed: bool,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE training_checkpoints
            SET completed = ?, updated_at = ?
            WHERE training_run_id = ? AND checkpoint_id = ?
            """,
            (1 if completed else 0, _now(), training_run_id, checkpoint_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Unknown training checkpoint: {checkpoint_id}")
    return training_run_detail(training_run_id, db_path)


def request_training_hint(
    training_run_id: int,
    db_path: Path = LIVE_DB,
) -> dict[str, object]:
    row = _load_training_run(training_run_id, db_path)
    if row is None:
        raise ValueError(f"Unknown training run: {training_run_id}")
    module = _require_training_module(str(row["module_id"]))
    previous_hints = _load_training_hints(training_run_id, db_path)
    hint_index = min(len(previous_hints), len(module.hints) - 1)
    hint = module.hints[hint_index]
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO training_hints (training_run_id, hint_index, hint, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (training_run_id, hint_index, hint, _now()),
        )
    detail = training_run_detail(training_run_id, db_path)
    detail["latest_hint"] = hint
    return detail


def training_evidence_markdown(
    training_run_id: int,
    db_path: Path = LIVE_DB,
) -> str:
    detail = training_run_detail(training_run_id, db_path)
    module = detail["module"]
    run = detail["run"]
    case_detail = detail["case_run"]
    lines = [
        f"# Training evidence: {module['module_id']} run {run['id']}",
        "",
        f"- Title: {module['title']}",
        f"- Audience: {module['audience']}",
        f"- Status: {run['status']}",
        f"- Feedback: {detail['feedback']}",
        f"- Training score: {detail['instructor']['score']} / {detail['instructor']['max_score']}",
        f"- Training readiness: {detail['instructor']['readiness']}",
        (
            f"- Guided step: {detail['guide']['current_step'] + 1} / "
            f"{detail['guide']['total_steps']} ({detail['guide']['current']['title']})"
        ),
        "",
        "## Learning objectives",
        "",
    ]
    for objective in module["objectives"]:
        lines.append(f"- {objective}")
    lines.extend(["", "## Learner decisions", ""])
    for question in detail["questions"]:
        status = "correct" if question["correct"] else "open"
        if question["answered"] and not question["correct"]:
            status = "retry needed"
        lines.append(f"- [{status}] {question['prompt']} (attempts: {question['attempts']})")
    lines.extend(["", "## Hints used", ""])
    if detail["hints"]:
        for hint in detail["hints"]:
            lines.append(f"- {hint['hint']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Training assessment", ""])
    for criterion in detail["instructor"]["criteria"]:
        lines.append(
            f"- {criterion['name']}: {criterion['points']} / "
            f"{criterion['max_points']} - {criterion['status']}"
        )
    lines.append(f"- Recommendation: {detail['instructor']['recommendation']}")
    if detail["review"]:
        lines.extend(["", "## Facilitator review", ""])
        lines.append(f"- Rating: {detail['review']['rating']}")
        lines.append(f"- Observation: {detail['review']['observation'] or '-'}")
    lines.extend(["", "## Case summary", ""])
    lines.append(f"- Case: {case_detail['case']['case_id']}")
    lines.append(f"- Events: {case_detail['event_count']}")
    lines.append(f"- Decision: {case_detail['run']['decision'] or '-'}")
    if case_detail["incident"]:
        lines.append(f"- Incident: {case_detail['incident']['detection']}")
        lines.append(f"- Incident status: {case_detail['incident']['status']}")
    lines.extend(["", "## Scope", "", SCOPE_WARNING, ""])
    return "\n".join(lines)


def evaluate_case_detection(
    case: SocCase,
    events: list[dict[str, object]],
) -> dict[str, object]:
    if case.primary_detection == "SENT-006":
        return _evaluate_sent_006(events)
    return {
        "status": "Observing",
        "reason": "No local evaluator is implemented for this case.",
        "matched_fields": [],
        "matched_entities": {},
    }


def case_evidence_markdown(case_run_id: int, db_path: Path = LIVE_DB) -> str:
    detail = case_run_detail(case_run_id, db_path)
    run = detail["run"]
    case = detail["case"]
    evaluation = detail["evaluation"]
    lines = [
        f"# Case evidence: {case['case_id']} run {run['id']}",
        "",
        f"- Title: {case['title']}",
        f"- Status: {run['status']}",
        f"- Decision: {run['decision'] or '-'}",
        f"- Primary detection: {case['primary_detection']}",
        f"- Observed status: {evaluation.get('status', 'Unknown')}",
        "",
        "## Event counts",
        "",
    ]
    for key, value in detail["counts"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Timeline", ""])
    for event in detail["events"]:
        lines.append(
            "- "
            f"t+{event['offset']}s [{event.get('classification', '-')}] "
            f"{event['table']} {event['account']} {event['ip']} "
            f"{event['result']} - {event['detail']}"
        )
    lines.extend(["", "## Analyst tasks", ""])
    for task in detail["tasks"]:
        status = "done" if task["completed"] else "open"
        lines.append(f"- [{status}] {task['label']}")
    if detail["incident"]:
        incident = detail["incident"]
        lines.extend(["", "## Incident", ""])
        lines.append(f"- ID: {incident['id']}")
        lines.append(f"- Status: {incident['status']}")
        lines.append(f"- Reason: {incident['reason']}")
    if run["decision_note"]:
        lines.extend(["", "## Decision note", "", str(run["decision_note"])])
    lines.extend(["", "## Scope", "", SCOPE_WARNING, ""])
    return "\n".join(lines)


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
        notes = state.get("analyst_notes") or []
        if notes:
            lines.extend(["", "## Analyst notes", ""])
            for item in notes:
                lines.append(f"- {item['created_at']} [{item['status']}]: {item['note']}")
    lines.extend(["", "## Scope", "", SCOPE_WARNING, ""])
    return "\n".join(lines)


def incident_evidence_markdown(
    incident_id: int,
    db_path: Path = LIVE_DB,
) -> str:
    detail = incident_detail(incident_id, db_path)
    if detail is None:
        raise ValueError(f"Unknown incident: {incident_id}")
    scenario_id = str(detail["incident"]["scenario_id"])
    scenario = get_scenario(scenario_id)
    state = {
        "events": detail["events"],
        "incident": detail["incident"],
        "evaluation": detail["evaluation"],
        "analyst_notes": detail["notes"],
    }
    lines = [f"# Incident evidence: {incident_id}", ""]
    if scenario is not None:
        lines.append(evidence_markdown(scenario, state))
    else:
        source = detail["scenario"]
        lines.extend(
            [
                f"## Source: {source['scenario_id']}",
                "",
                f"- Title: {source['title']}",
                f"- Primary detection: {source['primary_detection']}",
                f"- Observed status: {detail['evaluation'].get('status', 'Unknown')}",
                "",
                "## Events",
                "",
            ]
        )
        for event in detail["events"]:
            lines.append(
                "- "
                f"t+{event['offset']}s {event['table']} {event['account']} "
                f"{event['ip']} {event['result']} - {event['detail']}"
            )
    lines.extend(["", "## Entities", ""])
    for group, values in detail["entities"].items():
        value = ", ".join(values) if values else "-"
        lines.append(f"- {group}: {value}")
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


def _evaluate_and_store_case_incident(
    case: SocCase,
    case_run_id: int,
    db_path: Path,
) -> None:
    detail = case_run_detail(case_run_id, db_path)
    evaluation = detail["evaluation"]
    if evaluation["status"] != "Alert" or detail["incident"]:
        return
    matched = evaluation.get("matched_entities", {})
    run_key = str(detail["run"]["run_key"])
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO incidents (
              scenario_id, detection, severity, status, account, ip, host, reason, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_key,
                case.primary_detection,
                case.severity,
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
        event for event in events if event["table"] == "SigninLogs" and event["result"] == "success"
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
        event for event in events if event["table"] == "SigninLogs" and event["result"] == "success"
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
            SELECT
              id, scenario_id, detection, severity, status, account, ip, host, reason,
              created_at
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
        "scenario_id": row[1],
        "detection": row[2],
        "severity": row[3],
        "status": row[4],
        "account": row[5],
        "ip": row[6],
        "host": row[7],
        "reason": row[8],
        "created_at": row[9],
    }


def _load_incident_by_id(incident_id: int, db_path: Path) -> dict[str, object] | None:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT
              id, scenario_id, detection, severity, status, account, ip, host, reason,
              created_at
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "scenario_id": row[1],
        "detection": row[2],
        "severity": row[3],
        "status": row[4],
        "account": row[5],
        "ip": row[6],
        "host": row[7],
        "reason": row[8],
        "created_at": row[9],
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
    return [{"id": row[0], "status": row[1], "note": row[2], "created_at": row[3]} for row in rows]


def _load_case_run(case_run_id: int, db_path: Path) -> dict[str, object] | None:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, case_id, run_key, status, decision, decision_note, started_at, closed_at
            FROM case_runs
            WHERE id = ?
            """,
            (case_run_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "case_id": row[1],
        "run_key": row[2],
        "status": row[3],
        "decision": row[4],
        "decision_note": row[5],
        "started_at": row[6],
        "closed_at": row[7],
    }


def _load_case_run_by_key(run_key: str, db_path: Path) -> dict[str, object] | None:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, case_id, run_key, status, decision, decision_note, started_at, closed_at
            FROM case_runs
            WHERE run_key = ?
            """,
            (run_key,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "case_id": row[1],
        "run_key": row[2],
        "status": row[3],
        "decision": row[4],
        "decision_note": row[5],
        "started_at": row[6],
        "closed_at": row[7],
    }


def _load_case_tasks(case_run_id: int, db_path: Path) -> list[dict[str, object]]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT task_id, label, completed, updated_at
            FROM case_tasks
            WHERE case_run_id = ?
            ORDER BY id
            """,
            (case_run_id,),
        ).fetchall()
    return [
        {
            "task_id": row[0],
            "label": row[1],
            "completed": bool(row[2]),
            "updated_at": row[3],
        }
        for row in rows
    ]


def _load_training_run(training_run_id: int, db_path: Path) -> dict[str, object] | None:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, module_id, case_run_id, status, feedback, started_at, completed_at
            FROM training_runs
            WHERE id = ?
            """,
            (training_run_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "module_id": row[1],
        "case_run_id": row[2],
        "status": row[3],
        "feedback": row[4],
        "started_at": row[5],
        "completed_at": row[6],
    }


def _load_training_checkpoints(
    training_run_id: int,
    db_path: Path,
) -> list[dict[str, object]]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT checkpoint_id, label, completed, updated_at
            FROM training_checkpoints
            WHERE training_run_id = ?
            ORDER BY id
            """,
            (training_run_id,),
        ).fetchall()
    return [
        {
            "checkpoint_id": row[0],
            "label": row[1],
            "completed": bool(row[2]),
            "updated_at": row[3],
        }
        for row in rows
    ]


def _load_training_answers(
    training_run_id: int,
    db_path: Path,
) -> list[dict[str, object]]:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT question_id, answer, correct, attempts, updated_at
            FROM training_answers
            WHERE training_run_id = ?
            ORDER BY question_id
            """,
            (training_run_id,),
        ).fetchall()
    return [
        {
            "question_id": row[0],
            "answer": row[1],
            "correct": bool(row[2]),
            "attempts": row[3],
            "updated_at": row[4],
        }
        for row in rows
    ]


def _training_question(
    module: TrainingModule,
    question_id: str,
) -> dict[str, object] | None:
    return next(
        (question for question in module.questions if question["question_id"] == question_id),
        None,
    )


def _training_questions_for_detail(
    module: TrainingModule,
    answers: list[dict[str, object]],
) -> list[dict[str, object]]:
    answers_by_id = {str(answer["question_id"]): answer for answer in answers}
    questions: list[dict[str, object]] = []
    for question in module.questions:
        answer = answers_by_id.get(str(question["question_id"]))
        questions.append(
            {
                "question_id": question["question_id"],
                "flow_id": question["flow_id"],
                "prompt": question["prompt"],
                "options": question["options"],
                "minimum_events": question.get("minimum_events", 0),
                "requires_alert": bool(question.get("requires_alert", False)),
                "answered": answer is not None,
                "correct": bool(answer and answer["correct"]),
                "attempts": int(answer["attempts"]) if answer else 0,
                "feedback": (
                    question["feedback_correct"]
                    if answer and answer["correct"]
                    else question["feedback_retry"]
                    if answer
                    else ""
                ),
            }
        )
    return questions


def _load_training_hints(
    training_run_id: int,
    db_path: Path,
) -> list[dict[str, object]]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, hint_index, hint, created_at
            FROM training_hints
            WHERE training_run_id = ?
            ORDER BY id
            """,
            (training_run_id,),
        ).fetchall()
    return [
        {
            "id": row[0],
            "hint_index": row[1],
            "hint": row[2],
            "created_at": row[3],
        }
        for row in rows
    ]


def _load_training_progress(training_run_id: int, db_path: Path) -> int:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT current_step FROM training_progress
            WHERE training_run_id = ?
            """,
            (training_run_id,),
        ).fetchone()
    return int(row[0]) if row is not None else 0


def _training_guide(
    module: TrainingModule,
    current_step: int,
    checkpoints: list[dict[str, object]],
    case_detail: dict[str, object],
) -> dict[str, object]:
    steps = module.learning_flow
    maximum_step = _maximum_training_step(module, checkpoints, case_detail)
    clean_index = max(0, min(current_step, maximum_step))
    return {
        "current_step": clean_index,
        "total_steps": len(steps),
        "maximum_step": maximum_step,
        "current": steps[clean_index],
        "steps": [
            {
                **step,
                "position": index + 1,
                "state": (
                    "current"
                    if index == clean_index
                    else "complete"
                    if index < clean_index
                    else "locked"
                    if index > maximum_step
                    else "upcoming"
                ),
            }
            for index, step in enumerate(steps)
        ],
    }


def _maximum_training_step(
    module: TrainingModule,
    checkpoints: list[dict[str, object]],
    case_detail: dict[str, object],
) -> int:
    completed = {
        str(checkpoint["checkpoint_id"]) for checkpoint in checkpoints if checkpoint["completed"]
    }
    maximum_step = 1
    for index, question in enumerate(module.questions, start=1):
        if str(question["checkpoint_id"]) not in completed:
            return min(maximum_step, len(module.learning_flow) - 1)
        maximum_step = index + 1
    if case_detail["run"]["status"] == "Closed":
        maximum_step = len(module.learning_flow) - 1
    return min(maximum_step, len(module.learning_flow) - 1)


def _load_instructor_review(
    training_run_id: int,
    db_path: Path,
) -> dict[str, object] | None:
    init_store(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT rating, observation, updated_at
            FROM instructor_reviews
            WHERE training_run_id = ?
            """,
            (training_run_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "training_run_id": training_run_id,
        "rating": row[0],
        "observation": row[1],
        "updated_at": row[2],
    }


def _complete_training_for_case(case_run_id: int, db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id
            FROM training_runs
            WHERE case_run_id = ? AND status != 'Completed'
            """,
            (case_run_id,),
        ).fetchall()
    for row in rows:
        training_run_id = int(row[0])
        detail = training_run_detail(training_run_id, db_path)
        module = _require_training_module(str(detail["run"]["module_id"]))
        case_detail = detail["case_run"]
        decision = str(case_detail["run"].get("decision") or "")
        note = str(case_detail["run"].get("decision_note") or "").strip()
        feedback = _training_feedback(detail["run"], case_detail, module)
        with sqlite3.connect(db_path) as connection:
            if decision in module.expected_decisions and note:
                connection.execute(
                    """
                    UPDATE training_checkpoints
                    SET completed = 1, updated_at = ?
                    WHERE training_run_id = ? AND checkpoint_id = 'close-case'
                    """,
                    (_now(), training_run_id),
                )
            connection.execute(
                """
                UPDATE training_runs
                SET status = 'Completed', feedback = ?, completed_at = ?
                WHERE id = ?
                """,
                (feedback, _now(), training_run_id),
            )


def _training_instructor_summary(
    run: dict[str, object],
    case_detail: dict[str, object],
    module: TrainingModule,
    checkpoints: list[dict[str, object]],
    answers: list[dict[str, object]],
    hints: list[dict[str, object]],
) -> dict[str, object]:
    question_total = len(module.questions)
    question_done = sum(1 for answer in answers if answer["correct"])
    event_total = int(case_detail["case"]["event_total"])
    event_count = int(case_detail["event_count"])
    incident = case_detail["incident"]
    decision = str(case_detail["run"].get("decision") or "")
    expected = decision in module.expected_decisions

    decision_reasoning_points = _fractional_points(question_done, question_total, 6)
    evidence_points = 0
    if event_count >= event_total:
        evidence_points += 1
    if incident:
        evidence_points += 1
    if expected:
        decision_points = 2
    elif decision:
        decision_points = 1
    else:
        decision_points = 0

    score = round(decision_reasoning_points + evidence_points + decision_points, 1)
    if score >= 8 and expected:
        readiness = "Ready for independent review"
        recommendation = "Debrief the decision note, then move to an unguided scenario."
    elif decision == "Benign":
        readiness = "Needs corrective review"
        recommendation = "Review why benign noise does not cancel the correlated alert evidence."
    elif score >= 5 or expected:
        readiness = "Developing"
        recommendation = "Continue coaching on the unanswered evidence decisions."
    else:
        readiness = "Needs guided practice"
        recommendation = "Continue the guided training path and complete each evidence step."

    criteria = [
        {
            "name": "Analyst decisions",
            "points": decision_reasoning_points,
            "max_points": 6,
            "status": f"{question_done}/{question_total} correct",
        },
        {
            "name": "Evidence recognition",
            "points": evidence_points,
            "max_points": 2,
            "status": (
                "Alert reviewed" if incident else f"{event_count}/{event_total} events emitted"
            ),
        },
        {
            "name": "Final decision",
            "points": decision_points,
            "max_points": 2,
            "status": decision or "Open",
        },
    ]
    return {
        "mode": "Guided Training",
        "version": "0.8.0",
        "score": score,
        "max_score": 10,
        "readiness": readiness,
        "recommendation": recommendation,
        "expected_decisions": module.expected_decisions,
        "hints_used": len(hints),
        "run_status": run["status"],
        "criteria": criteria,
    }


def _fractional_points(done: int, total: int, max_points: int) -> float:
    if total <= 0:
        return 0
    return round((done / total) * max_points, 1)


def _training_feedback(
    run: dict[str, object],
    case_detail: dict[str, object],
    module: TrainingModule,
) -> str:
    if run.get("feedback"):
        return str(run["feedback"])
    decision = str(case_detail["run"].get("decision") or "")
    if not decision:
        return (
            "Keep investigating: review the timeline, entities and rule evaluation before closing."
        )
    if decision in module.expected_decisions:
        return "Good call: the decision matches the correlated identity evidence in this lesson."
    if decision == "Benign":
        return (
            "Review needed: benign noise exists, but the correlated Entra risk and Windows "
            "success after failures should not be closed as benign."
        )
    return (
        "The case is closed, but compare your decision with the expected suspicious "
        "or escalated outcome."
    )


def _case_event_counts(events: list[dict[str, object]]) -> dict[str, int]:
    return {
        "total": len(events),
        "benign": sum(1 for event in events if event.get("classification") == "benign"),
        "signal": sum(1 for event in events if event.get("classification") == "signal"),
        "high": sum(1 for event in events if event.get("severity") == "High"),
        "medium": sum(1 for event in events if event.get("severity") == "Medium"),
        "low": sum(1 for event in events if event.get("severity") == "Low"),
    }


def _require_scenario(scenario_id: str) -> LiveScenario:
    scenario = get_scenario(scenario_id)
    if scenario is None:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    return scenario


def _require_case(case_id: str) -> SocCase:
    case = get_case(case_id)
    if case is None:
        raise ValueError(f"Unknown case: {case_id}")
    return case


def _require_training_module(module_id: str) -> TrainingModule:
    module = get_training_module(module_id)
    if module is None:
        raise ValueError(f"Unknown training module: {module_id}")
    return module


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def render_live_app() -> str:
    return _render_workbench_app()


def _render_workbench_app() -> str:
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Detection Live Lab</title>
  <style>
    :root {
      --bg: #f3f6fb;
      --ink: #182233;
      --muted: #5b6778;
      --panel: #ffffff;
      --line: #d7e0eb;
      --accent: #0d6efd;
      --alert: #b42318;
      --ok: #137333;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      background: #101828;
      color: white;
      padding: 24px;
    }
    main {
      max-width: 1420px;
      margin: 0 auto;
      padding: 20px;
      display: grid;
      gap: 16px;
    }
    h1, h2, h3 { margin: 0; }
    h1 { font-size: 2rem; }
    h2 { font-size: 1.15rem; }
    h3 { font-size: 1rem; margin-top: 12px; }
    p { margin: 8px 0 0; color: var(--muted); }
    button, select, input {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      background: white;
      color: var(--ink);
      font-weight: 700;
    }
    button.primary { background: var(--accent); color: white; border-color: var(--accent); }
    textarea {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      width: 100%;
      min-height: 86px;
      font: inherit;
    }
    .warning {
      border: 1px solid #e9c86a;
      background: #fff6dd;
      padding: 12px;
      font-weight: 700;
    }
    .toolbar, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }
    .toolbar {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .view-nav {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      border-bottom: 1px solid var(--line);
      padding-bottom: 12px;
    }
    .view-tab {
      background: #eef4fb;
      color: var(--ink);
    }
    .view-tab.active {
      background: var(--accent);
      border-color: var(--accent);
      color: white;
    }
    .view {
      display: grid;
      gap: 16px;
    }
    .view[hidden] { display: none; }
    .view-heading {
      display: grid;
      gap: 6px;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #f8fbff;
    }
    .metric strong { display: block; font-size: 1.25rem; }
    .workbench {
      display: grid;
      grid-template-columns: .85fr 1.55fr .8fr;
      gap: 16px;
      align-items: start;
    }
    .case-grid, .training-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      align-items: start;
    }
    .guide-layout {
      display: grid;
      grid-template-columns: minmax(220px, .7fr) minmax(0, 1.6fr);
      gap: 16px;
      align-items: start;
    }
    .guide-progress { display: grid; gap: 8px; }
    .guide-progress div {
      border-left: 4px solid var(--line);
      padding: 8px 10px;
      background: #f8fbff;
    }
    .guide-progress div.current { border-left-color: var(--accent); }
    .guide-progress div.complete { border-left-color: var(--ok); }
    .guide-action { display: grid; gap: 12px; }
    .guide-nav { display: flex; gap: 8px; flex-wrap: wrap; }
    .guide-nav button { min-width: 120px; }
    .guide-solution { border-left: 4px solid var(--ok); padding-left: 12px; }
    .guide-question {
      display: grid;
      gap: 10px;
      margin-top: 14px;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }
    .guide-options { display: grid; gap: 8px; }
    .guide-options label { display: flex; gap: 8px; align-items: flex-start; }
    .guide-question-feedback { margin: 0; min-height: 1.4em; }
    .case-grid .wide { grid-column: 1 / -1; }
    .event-list {
      display: grid;
      gap: 8px;
      margin-top: 10px;
    }
    .event-list div {
      border-left: 4px solid var(--accent);
      background: #f8fbff;
      padding: 10px;
    }
    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: .9rem;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }
    th { color: var(--muted); }
    .queue {
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }
    .queue button {
      width: 100%;
      text-align: left;
      background: #f8fbff;
    }
    .queue button.selected {
      border-color: var(--accent);
      box-shadow: inset 4px 0 0 var(--accent);
    }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      border: 1px solid var(--line);
      background: white;
      font-size: .82rem;
      font-weight: 700;
    }
    .alert-text { color: var(--alert); font-weight: 700; }
    .ok-text { color: var(--ok); font-weight: 700; }
    .timeline {
      list-style: none;
      padding: 0;
      margin: 10px 0 0;
      display: grid;
      gap: 8px;
    }
    .timeline li {
      border-left: 4px solid var(--accent);
      background: #f8fbff;
      padding: 10px;
    }
    .timeline li.alert { border-left-color: var(--alert); }
    .kv {
      display: grid;
      gap: 8px;
      margin-top: 10px;
    }
    .kv div {
      border-bottom: 1px solid var(--line);
      padding-bottom: 8px;
    }
    .note-form { display: grid; gap: 8px; margin-top: 12px; }
    .filters { display: grid; gap: 8px; margin-top: 10px; }
    @media (max-width: 1100px) {
      .workbench, .case-grid, .training-grid, .guide-layout { grid-template-columns: 1fr; }
      .case-grid .wide { grid-column: auto; }
    }
    @media (max-width: 700px) {
      main { padding: 12px; }
      header { padding: 18px 12px; }
      h1 { font-size: 1.55rem; }
      .cards { grid-template-columns: 1fr; }
      .toolbar > label, .toolbar > strong { width: 100%; }
      .toolbar select, .toolbar button { width: 100%; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Identity Detection Live Lab</h1>
    <p>Analyst Workbench for local synthetic identity incidents.</p>
  </header>
  <main>
    <div class="warning">__SCOPE_WARNING__</div>
    <nav class="view-nav" aria-label="Workbench views">
      <button class="view-tab active" data-view="overview" aria-selected="true">Overview</button>
      <button class="view-tab" data-view="incidents" aria-selected="false">Incidents</button>
      <button class="view-tab" data-view="case" aria-selected="false">Case run</button>
      <button class="view-tab" data-view="training" aria-selected="false">Guided training</button>
    </nav>

    <section class="view" data-view-panel="overview">
      <section class="panel view-heading">
        <h2>Scenario workspace</h2>
        <p>Run a synthetic detection scenario, then review its evidence in Incidents.</p>
      </section>
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
        <button id="reset">Reset scenario</button>
        <button id="reset-runtime">Reset runtime state</button>
        <button id="export-json">Export JSON</button>
        <button id="export-md">Export MD</button>
      </section>
      <section class="cards">
        <div class="metric"><span>Detection</span><strong id="detection">-</strong></div>
        <div class="metric"><span>Severity</span><strong id="severity">-</strong></div>
        <div class="metric"><span>Expected</span><strong id="expected">-</strong></div>
        <div class="metric"><span>Runtime</span><strong id="status">Ready</strong></div>
        <div class="metric"><span>Benign events</span><strong id="benign-count">0</strong></div>
        <div class="metric"><span>Signal events</span><strong id="signal-count">0</strong></div>
      </section>
      <section class="panel view-heading">
        <h2>Next step</h2>
        <p>When the scenario reaches an alert, open the incident queue to inspect
          entities, rule evidence and analyst notes.</p>
        <div><button data-open-view="incidents" class="primary">Review incidents</button></div>
      </section>
    </section>

    <section class="view" data-view-panel="incidents" hidden>
      <section class="panel view-heading">
        <h2>Incident investigation</h2>
        <p>Filter the local queue, review the evidence and record an analyst action.</p>
      </section>
      <section class="workbench">
      <div class="panel">
        <h2>Incident queue</h2>
        <p id="queue-summary">No incidents yet.</p>
        <div class="filters">
          <select id="filter-status">
            <option value="">All statuses</option>
            <option>New</option>
            <option>Investigating</option>
            <option>Benign</option>
            <option>Suspicious</option>
            <option>Escalated</option>
            <option>Closed</option>
          </select>
          <select id="filter-severity">
            <option value="">All severities</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
          <input id="filter-entity" placeholder="Filter by account, IP or host">
        </div>
        <div id="incident-queue" class="queue"></div>
      </div>
      <div class="panel">
        <h2>Incident detail</h2>
        <p id="summary"></p>
        <h3>Event stream</h3>
        <div class="table-wrap"><table>
            <thead>
              <tr>
                <th>Time</th><th>Table</th><th>Account</th><th>IP</th><th>Host</th><th>Result</th><th>Detail</th>
              </tr>
            </thead>
            <tbody id="events"></tbody>
          </table></div>
        <h3>Timeline</h3>
        <ul id="timeline" class="timeline"></ul>
      </div>
      <div class="panel">
        <h2>Entities</h2>
        <div id="entities" class="kv"></div>
        <h3>Rule evaluation</h3>
        <p id="rule-reason">Waiting for synthetic events.</p>
        <p id="matched-fields"></p>
        <div class="note-form">
          <h3>Analyst action</h3>
          <select id="analyst-status">
            <option>New</option>
            <option>Investigating</option>
            <option>Benign</option>
            <option>Suspicious</option>
            <option>Escalated</option>
            <option>Closed</option>
          </select>
          <textarea id="analyst-note" placeholder="Analyst note"></textarea>
          <button id="save-note">Save note</button>
          <p id="note-status"></p>
          <h3>Notes</h3>
          <div id="notes" class="kv"></div>
        </div>
      </div>
    </section>
    </section>

    <section class="view" data-view-panel="case" hidden>
      <section class="panel view-heading">
        <h2>Guided case investigation</h2>
        <p>Emit one event at a time, review the synthetic evidence and close the case
          with a defensible decision.</p>
      </section>
      <section class="toolbar">
        <strong>Case run</strong>
        <select id="case-select"></select>
        <button id="case-start" class="primary">Start Case run</button>
        <button id="case-tick">Next case event</button>
        <button id="case-export-json">Export case JSON</button>
        <button id="case-export-md">Export case MD</button>
        <span id="case-status">No active case.</span>
      </section>
      <section class="case-grid">
        <div class="panel">
          <h2>Case overview</h2>
          <p id="case-summary">Start a case run to load its synthetic evidence.</p>
          <h3>Entities</h3>
          <div id="case-entities" class="kv"></div>
        </div>
        <div class="panel">
          <h2>Analyst tasks</h2>
          <div id="case-tasks" class="kv"></div>
          <div class="note-form">
            <h3>Close case</h3>
            <select id="case-decision">
              <option>Suspicious</option>
              <option>Escalated</option>
              <option>Benign</option>
              <option>Closed</option>
            </select>
            <textarea id="case-note" placeholder="Case decision note"></textarea>
            <button id="case-close">Close case</button>
            <p id="case-note-status"></p>
          </div>
        </div>
        <div class="panel wide">
          <h2>Case event stream</h2>
          <div id="case-events" class="event-list"><div>No case events yet.</div></div>
        </div>
      </section>
    </section>

    <section class="view" data-view-panel="training" hidden>
      <section class="panel view-heading">
        <h2>Guided Training</h2>
        <p>Choose a synthetic case, then work through one clear investigation step at a time.</p>
      </section>
      <section class="toolbar">
        <strong>Choose a training case</strong>
        <select id="training-select"></select>
        <button id="training-start" class="primary">Start guided training</button>
        <button id="training-hint">Hint</button>
        <button id="training-export-json">Export training JSON</button>
        <button id="training-export-md">Export training MD</button>
        <span id="training-status">Choose a case to begin.</span>
      </section>
      <section class="guide-layout">
        <div class="panel">
          <h2>Learning path</h2>
          <div id="training-progress" class="guide-progress"></div>
          <h3>Learning objectives</h3>
          <div id="learning-objectives" class="kv"></div>
        </div>
        <div class="panel">
          <p id="training-step-count" class="pill">Step 0</p>
          <h2 id="training-step-title">Choose a case</h2>
          <p id="training-step-instruction">Select a case and start the guided investigation.</p>
          <div id="training-step-content" class="guide-action"></div>
          <p id="training-feedback">Guidance will appear here as you progress.</p>
          <p id="training-hint-output"></p>
          <div class="guide-nav">
            <button id="training-back">Back</button>
            <button id="training-next" class="primary">Continue</button>
          </div>
          <div id="training-outcome" hidden>
            <h3>Training outcome</h3>
            <p id="instructor-score">No active training score.</p>
            <div id="instructor-assessment" class="kv"></div>
            <details class="guide-solution" id="facilitator-notes" hidden>
              <summary>Facilitator notes</summary>
              <p>The alert is justified by a high-risk Entra sign-in, repeated Windows failures,
                and a later successful logon for the same account and source IP. The unrelated
                benign events add context but do not cancel that correlation.</p>
            </details>
          </div>
          <div id="facilitator-review" class="note-form" hidden>
            <h3>Facilitator review</h3>
            <select id="instructor-rating">
              <option>Needs guided practice</option>
              <option>Developing</option>
              <option>Ready for independent review</option>
            </select>
            <textarea id="instructor-observation" placeholder="Facilitator observation"></textarea>
            <button id="instructor-review-save">Save facilitator review</button>
            <p id="instructor-review-status"></p>
          </div>
        </div>
      </section>
    </section>
  </main>
  <script>
    const state = {
      scenarios: [],
      scenario: null,
      timer: null,
      incident: null,
      selectedIncidentId: null,
      cases: [],
      activeCaseRun: null,
      trainingModules: [],
      activeTraining: null,
      incidents: []
    };

    const $ = (id) => document.getElementById(id);
    const h = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[char]));

    function setView(name) {
      document.querySelectorAll('[data-view-panel]').forEach((panel) => {
        panel.hidden = panel.dataset.viewPanel !== name;
      });
      document.querySelectorAll('[data-view]').forEach((button) => {
        const active = button.dataset.view === name;
        button.classList.toggle('active', active);
        button.setAttribute('aria-selected', String(active));
      });
    }

    async function loadScenarios() {
      const response = await fetch('/api/scenarios');
      state.scenarios = await response.json();
      $('scenario').innerHTML = state.scenarios
        .map((item) => {
          const label = `${item.scenario_id} - ${item.title}`;
          return `<option value="${h(item.scenario_id)}">${h(label)}</option>`;
        })
        .join('');
      await loadScenario(state.scenarios[0].scenario_id);
      await loadTrainingModules();
      await loadCases();
      await loadIncidents();
    }

    async function loadTrainingModules() {
      const response = await fetch('/api/training');
      const payload = await response.json();
      state.trainingModules = payload.modules;
      $('training-select').innerHTML = state.trainingModules.map((item) =>
        `<option value="${h(item.module_id)}">${h(item.module_id)} - ${h(item.title)}</option>`
      ).join('');
      if (payload.runs.length && !state.activeTraining) {
        await loadTrainingRun(payload.runs[0].id);
      } else if (state.trainingModules.length) {
        renderTrainingModulePreview(state.trainingModules[0]);
      }
    }

    function renderTrainingModulePreview(module) {
      $('learning-objectives').innerHTML = module.objectives.map((objective) =>
        `<div>${h(objective)}</div>`
      ).join('');
      $('training-progress').innerHTML = module.learning_flow.map((step, index) =>
        `<div><strong>${index + 1}. ${h(step.title)}</strong><br>` +
        `<small>${h(step.instruction)}</small></div>`
      ).join('');
      $('training-step-count').textContent = 'Choose a case';
      $('training-step-title').textContent = module.title;
      $('training-step-instruction').textContent = module.summary;
      $('training-step-content').innerHTML =
        '<div><strong>What you will do</strong><br>' + h(module.instructor_brief) + '</div>';
      $('training-feedback').textContent = 'Start guided training when you are ready.';
      $('training-hint-output').textContent = '';
      $('training-outcome').hidden = true;
      $('facilitator-review').hidden = true;
      $('facilitator-notes').hidden = true;
      $('training-back').disabled = true;
      $('training-next').disabled = true;
    }

    async function startTrainingRun() {
      pause();
      const response = await fetch('/api/training/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({module_id: $('training-select').value || 'TRAIN-001'})
      });
      const payload = await response.json();
      renderTrainingRun(payload);
      await loadIncidents(payload.case_run.incident ? payload.case_run.incident.id : null);
    }

    async function loadTrainingRun(id) {
      const response = await fetch(`/api/training/${id}`);
      if (!response.ok) return;
      const payload = await response.json();
      renderTrainingRun(payload);
      await loadIncidents(payload.case_run.incident ? payload.case_run.incident.id : null);
    }

    async function loadCases() {
      const response = await fetch('/api/cases');
      const payload = await response.json();
      state.cases = payload.cases;
      $('case-select').innerHTML = state.cases.map((item) =>
        `<option value="${h(item.case_id)}">${h(item.case_id)} - ${h(item.title)}</option>`
      ).join('');
      if (payload.runs.length && !state.activeCaseRun) {
        await loadCaseRun(payload.runs[0].id);
      }
    }

    async function startCaseRun() {
      pause();
      const response = await fetch('/api/cases/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({case_id: $('case-select').value || 'CASE-001'})
      });
      const payload = await response.json();
      renderCaseRun(payload);
      if (state.activeTraining) {
        await loadTrainingRun(state.activeTraining.run.id);
      }
      await loadIncidents(payload.incident ? payload.incident.id : null);
    }

    async function loadCaseRun(id) {
      const response = await fetch(`/api/cases/${id}`);
      if (!response.ok) return;
      const payload = await response.json();
      renderCaseRun(payload);
      await loadIncidents(payload.incident ? payload.incident.id : null);
    }

    async function tickCaseRun() {
      if (!state.activeCaseRun) {
        await startCaseRun();
        return;
      }
      const response = await fetch(`/api/cases/${state.activeCaseRun.run.id}/tick`, {
        method: 'POST'
      });
      const payload = await response.json();
      renderCaseRun(payload);
      await loadIncidents(payload.incident ? payload.incident.id : null);
    }

    async function loadScenario(id) {
      const response = await fetch(`/api/scenarios/${id}`);
      state.scenario = await response.json();
      $('summary').textContent = state.scenario.summary;
      $('detection').textContent = state.scenario.primary_detection;
      $('severity').textContent = state.scenario.severity;
      $('expected').textContent = state.scenario.expected_result;
      const stateResponse = await fetch(`/api/state?scenario=${state.scenario.scenario_id}`);
      const payload = await stateResponse.json();
      renderState(payload);
      await loadIncidents(payload.incident ? payload.incident.id : null);
    }

    async function reset() {
      clearInterval(state.timer);
      state.timer = null;
      const response = await fetch(`/api/reset?scenario=${state.scenario.scenario_id}`, {
        method: 'POST'
      });
      const payload = await response.json();
      state.selectedIncidentId = null;
      $('note-status').textContent = '';
      renderState(payload);
      await loadIncidents();
    }

    async function resetRuntime() {
      pause();
      await fetch('/api/runtime/reset', { method: 'POST' });
      state.selectedIncidentId = null;
      state.incident = null;
      state.activeCaseRun = null;
      state.activeTraining = null;
      $('case-status').textContent = 'No active case.';
      $('training-status').textContent = 'Choose a case to begin.';
      $('case-tasks').innerHTML = '';
      $('learning-objectives').innerHTML = '';
      $('training-progress').innerHTML = '';
      $('training-step-count').textContent = 'Step 0';
      $('training-step-title').textContent = 'Choose a case';
      $('training-step-instruction').textContent =
        'Select a case and start the guided investigation.';
      $('training-step-content').innerHTML = '';
      $('training-feedback').textContent = 'Guidance will appear here as you progress.';
      $('training-hint-output').textContent = '';
      $('training-outcome').hidden = true;
      $('facilitator-review').hidden = true;
      $('facilitator-notes').hidden = true;
      $('training-back').disabled = true;
      $('training-next').disabled = true;
      $('instructor-score').textContent = 'No active training score.';
      $('instructor-assessment').innerHTML = '';
      $('instructor-rating').value = 'Developing';
      $('instructor-observation').value = '';
      $('instructor-review-status').textContent = '';
      $('case-note-status').textContent = '';
      await loadIncidents();
      if (state.scenario) {
        await reset();
      }
      await loadTrainingModules();
      await loadCases();
    }

    function start() {
      if (!state.scenario || state.timer) return;
      $('status').textContent = 'Running';
      state.timer = setInterval(tick, Number($('speed').value));
      tick();
    }

    function pause() {
      if (state.timer) {
        clearInterval(state.timer);
        state.timer = null;
        $('status').textContent = 'Paused';
      }
    }

    async function tick() {
      const response = await fetch(`/api/tick?scenario=${state.scenario.scenario_id}`, {
        method: 'POST'
      });
      const payload = await response.json();
      renderState(payload);
      await loadIncidents(payload.incident ? payload.incident.id : null);
      if (payload.complete) {
        clearInterval(state.timer);
        state.timer = null;
      }
    }

    async function loadIncidents(preferredId = null) {
      const response = await fetch('/api/incidents');
      const incidents = await response.json();
      state.incidents = incidents;
      const statusFilter = $('filter-status').value;
      const severityFilter = $('filter-severity').value;
      const entityFilter = $('filter-entity').value.toLowerCase();
      const filtered = incidents.filter((incident) => {
        const entity = `${incident.account} ${incident.ip} ${incident.host}`.toLowerCase();
        return (!statusFilter || incident.status === statusFilter)
          && (!severityFilter || incident.severity === severityFilter)
          && (!entityFilter || entity.includes(entityFilter));
      });
      $('queue-summary').textContent = filtered.length
        ? `${filtered.length} incident(s) in local queue.`
        : 'No incidents yet.';
      $('incident-queue').innerHTML = filtered.map((incident) => {
        const selected = incident.id === state.selectedIncidentId ? 'selected' : '';
        return `
        <button data-incident="${incident.id}" class="${selected}">
          <span class="pill">${h(incident.status)}</span>
          <strong>${h(incident.detection)}</strong><br>
          ${h(incident.account)} | ${h(incident.ip)}<br>
          <small>${h(incident.scenario_id)} | notes: ${h(incident.note_count)}</small>
        </button>`;
      }).join('');
      document.querySelectorAll('[data-incident]').forEach((button) => {
        button.addEventListener('click', () => selectIncident(Number(button.dataset.incident)));
      });
      const targetId = preferredId || state.selectedIncidentId || (filtered[0] && filtered[0].id);
      if (targetId) {
        await selectIncident(Number(targetId), false);
      }
    }

    async function selectIncident(id, refreshQueue = true) {
      const response = await fetch(`/api/incidents/${id}`);
      if (!response.ok) return;
      const detail = await response.json();
      state.selectedIncidentId = id;
      state.incident = detail.incident;
      renderIncidentDetail(detail);
      if (refreshQueue) {
        await loadIncidents(id);
      }
    }

    function renderState(payload) {
      state.incident = payload.incident;
      renderEvents(payload.events);
      renderEvaluation(payload.evaluation);
      renderTimeline(payload.events, payload.incident);
      renderEntities({});
      renderNotes(payload.analyst_notes || []);
      renderCounts(payload.counts || {});
      if (payload.incident) {
        state.selectedIncidentId = payload.incident.id;
        $('status').textContent = 'Alert';
      } else if (payload.complete) {
        $('status').textContent = 'Complete';
      } else if (payload.event_count > 0) {
        $('status').textContent = 'Observing';
      } else {
        $('status').textContent = 'Ready';
      }
    }

    function renderIncidentDetail(detail) {
      state.incident = detail.incident;
      $('summary').textContent = `${detail.scenario.scenario_id}: ${detail.scenario.summary}`;
      $('analyst-status').value = detail.incident.status;
      renderEvents(detail.events);
      renderEvaluation(detail.evaluation);
      renderTimeline(detail.events, detail.incident);
      renderEntities(detail.entities);
      renderNotes(detail.notes);
      renderCounts({});
      $('status').textContent = detail.incident.status;
    }

    function renderCaseRun(payload) {
      state.activeCaseRun = payload;
      state.incident = payload.incident;
      if (payload.incident) state.selectedIncidentId = payload.incident.id;
      $('summary').textContent = `${payload.case.case_id}: ${payload.case.summary}`;
      $('detection').textContent = payload.case.primary_detection;
      $('severity').textContent = payload.case.severity;
      $('expected').textContent = 'Alert';
      $('status').textContent = payload.run.status;
      const caseProgress = `${payload.event_count}/${payload.case.event_total} events`;
      $('case-status').textContent =
        `${payload.case.case_id} run ${payload.run.id} | ${caseProgress} | ${payload.run.status}`;
      $('case-summary').textContent = payload.case.summary;
      $('case-events').innerHTML = payload.events.length ? payload.events.map((event) => `
        <div>
          <strong>t+${h(event.offset)}s | ${h(event.table)}</strong><br>
          ${h(event.account)} | ${h(event.ip)} | ${h(event.result)}<br>
          <small>${h(event.detail)}</small>
        </div>`).join('') : '<div>No case events yet.</div>';
      const entityGroups = ['accounts', 'ips', 'hosts', 'sources', 'tables'];
      $('case-entities').innerHTML = entityGroups.map((group) => {
        const values = (payload.entities || {})[group] || [];
        return `<div><strong>${h(group)}</strong><br>${h(values.join(', ') || '-')}</div>`;
      }).join('');
      renderEvents(payload.events);
      renderEvaluation(payload.evaluation);
      renderTimeline(payload.events, payload.incident);
      renderEntities(payload.entities || {});
      renderCounts(payload.counts || {});
      renderCaseTasks(payload.tasks || []);
      renderNotes([]);
    }

    function renderTrainingRun(payload) {
      state.activeTraining = payload;
      renderCaseRun(payload.case_run);
      $('training-status').textContent =
        `${payload.module.module_id} run ${payload.run.id} | ${payload.run.status}`;
      $('learning-objectives').innerHTML = payload.module.objectives.map((objective) =>
        `<div>${h(objective)}</div>`
      ).join('');
      $('training-feedback').textContent = payload.feedback;
      $('training-hint-output').textContent = payload.latest_hint
        ? `Hint: ${payload.latest_hint}`
        : (payload.hints.length ? `Hint: ${payload.hints[payload.hints.length - 1].hint}` : '');
      renderTrainingGuide(payload);
      $('instructor-score').textContent =
        `Score ${payload.instructor.score}/${payload.instructor.max_score} | ` +
        `${payload.instructor.readiness} | hints used: ${payload.instructor.hints_used}`;
      $('instructor-assessment').innerHTML = payload.instructor.criteria.map((criterion) =>
        `<div><strong>${h(criterion.name)}</strong><br>` +
        `${h(criterion.points)}/${h(criterion.max_points)} pts | ${h(criterion.status)}</div>`
      ).join('') + `<div><strong>Recommendation</strong><br>` +
        `${h(payload.instructor.recommendation)}</div>`;
      const allowedRatings = [
        'Needs guided practice',
        'Developing',
        'Ready for independent review'
      ];
      const suggestedRating = allowedRatings.includes(payload.instructor.readiness)
        ? payload.instructor.readiness
        : 'Developing';
      $('instructor-rating').value = payload.review ? payload.review.rating : suggestedRating;
      $('instructor-observation').value = payload.review ? payload.review.observation : '';
      $('instructor-review-status').textContent = payload.review
        ? `Review saved: ${payload.review.rating}`
        : '';
    }

    function trainingEntities(entities) {
      const groups = ['accounts', 'ips', 'hosts', 'sources', 'tables'];
      return groups.map((group) => `<div><strong>${h(group)}</strong><br>` +
        `${h((entities[group] || []).join(', ') || '-')}</div>`).join('');
    }

    function trainingQuestionControl(payload, flowId) {
      const question = payload.questions.find((item) => item.flow_id === flowId);
      if (!question) return '';
      const enoughEvents = payload.case_run.event_count >= question.minimum_events;
      const alertReady = !question.requires_alert || payload.case_run.evaluation.status === 'Alert';
      const ready = enoughEvents && alertReady;
      const state = question.correct
        ? 'Correct decision recorded.'
        : question.answered
        ? question.feedback
        : ready
        ? 'Choose the answer you can support from the evidence shown here.'
        : question.requires_alert
        ? 'Continue the timeline until the evaluator reaches Alert before answering.'
        : `Reveal at least ${question.minimum_events} timeline events before answering.`;
      return `<div class="guide-question"><strong>${h(question.prompt)}</strong>` +
        `<div class="guide-options">${question.options.map((option) =>
          `<label><input type="radio" name="training-question-${h(question.question_id)}" ` +
          `value="${h(option.value)}" ${!ready || question.correct ? 'disabled' : ''}> ` +
          `${h(option.label)}</label>`
        ).join('')}</div>` +
        `<button data-training-answer="${h(question.question_id)}" ` +
        `${!ready || question.correct ? 'disabled' : ''}>Check reasoning</button>` +
        `<p class="guide-question-feedback ` +
        `${question.correct ? 'ok-text' : question.answered ? 'alert-text' : ''}">` +
        `${h(state)}</p></div>`;
    }

    function renderTrainingGuide(payload) {
      const guide = payload.guide;
      const step = guide.current;
      const caseRun = payload.case_run;
      $('training-progress').innerHTML = guide.steps.map((item) =>
        `<div class="${h(item.state)}"><strong>${h(item.position)}. ${h(item.title)}</strong><br>` +
        `<small>${h(item.state === 'current' ? item.instruction : item.state)}</small></div>`
      ).join('');
      $('training-step-count').textContent =
        `Step ${guide.current_step + 1} of ${guide.total_steps}`;
      $('training-step-title').textContent = step.title;
      $('training-step-instruction').textContent = step.instruction;
      $('training-back').disabled = guide.current_step === 0;
      $('training-next').disabled = guide.current_step >= guide.maximum_step;
      const nextStep = guide.steps[guide.current_step + 1];
      $('training-next').textContent = nextStep
        ? `Continue: ${nextStep.title}`
        : 'Training complete';
      $('training-outcome').hidden = step.flow_id !== 'outcome';
      const caseClosed = caseRun.run.status === 'Closed';
      $('facilitator-notes').hidden = step.flow_id !== 'outcome' || !caseClosed;
      $('facilitator-review').hidden = step.flow_id !== 'outcome' || !caseClosed;

      let content = '';
      if (step.flow_id === 'briefing') {
        content = `<div><strong>Case:</strong> ${h(caseRun.case.case_id)} - ` +
          `${h(caseRun.case.title)}</div>` +
          `<div><strong>Primary detection:</strong> ${h(caseRun.case.primary_detection)}</div>`;
      } else if (step.flow_id === 'timeline') {
        content = `<button id="training-case-tick" class="primary">Reveal next event</button>` +
          `<div class="event-list">${caseRun.events.length ? caseRun.events.map((event) =>
            `<div><strong>t+${h(event.offset)}s ${h(event.table)}</strong><br>` +
            `${h(event.detail)}<br>` +
            `<small>${h(event.source)} | ${h(event.severity)}</small></div>`
          ).join('') : '<div>No events revealed yet.</div>'}</div>` +
          trainingQuestionControl(payload, 'timeline');
      } else if (step.flow_id === 'entities') {
        content = `<div class="kv">${trainingEntities(caseRun.entities || {})}</div>` +
          trainingQuestionControl(payload, 'entities');
      } else if (step.flow_id === 'rule') {
        const evaluatorReason = caseRun.evaluation.reason || 'Keep revealing events.';
        const matchedFields = (caseRun.evaluation.matched_fields || []).join(' | ') || '-';
        const revealControl = caseRun.evaluation.status !== 'Alert' && !caseRun.complete
          ? '<button id="training-case-tick" class="primary">Reveal next event</button>'
          : '';
        content = revealControl + `<div><strong>Evaluator state:</strong> ` +
          `${h(caseRun.evaluation.status)}</div>` +
          `<div><strong>Why:</strong><br>${h(evaluatorReason)}</div>` +
          `<div><strong>Matched fields:</strong><br>${h(matchedFields)}</div>` +
          trainingQuestionControl(payload, 'rule');
      } else if (step.flow_id === 'triage') {
        content = `<div><strong>Evidence available:</strong> ${h(caseRun.event_count)} events | ` +
          `${h(caseRun.evaluation.status)} evaluator state.</div>` +
          trainingQuestionControl(payload, 'triage');
      } else if (step.flow_id === 'close') {
        content = `<select id="training-case-decision"><option>Suspicious</option>` +
          `<option>Escalated</option><option>Benign</option><option>Closed</option></select>` +
          `<textarea id="training-case-note" ` +
          `placeholder="Explain the evidence behind your decision"></textarea>` +
          `<button id="training-case-close" class="primary">Close guided case</button>` +
          `<p id="training-case-close-status"></p>`;
      } else {
        content = caseRun.run.status === 'Closed'
          ? '<div><strong>Case closed.</strong> Review your score, feedback and ' +
            'facilitator notes.</div>'
          : '<div>Close the case in the previous step to unlock the complete outcome.</div>';
      }
      $('training-step-content').innerHTML = content;
      document.querySelectorAll('[data-training-answer]').forEach((button) => {
        button.addEventListener('click', () => submitTrainingAnswer(
          button.dataset.trainingAnswer
        ));
      });
      const tickButton = $('training-case-tick');
      if (tickButton) tickButton.addEventListener('click', tickTrainingCase);
      const closeButton = $('training-case-close');
      if (closeButton) closeButton.addEventListener('click', closeGuidedTrainingCase);
    }

    function renderEvents(events) {
      $('events').innerHTML = events.map((event) => `
        <tr>
          <td>t+${h(event.offset)}s</td>
          <td><span class="pill">${h(event.table)}</span></td>
          <td>${h(event.account)}</td>
          <td>${h(event.ip)}</td>
          <td>${h(event.host)}</td>
          <td>
            ${h(event.result)}<br>
            <small>${h(event.severity || '')} ${h(event.classification || '')}</small>
          </td>
          <td>${h(event.detail)}</td>
        </tr>
      `).join('');
    }

    function renderEvaluation(evaluation) {
      $('rule-reason').textContent = evaluation.reason || 'Waiting for synthetic events.';
      $('matched-fields').textContent = (evaluation.matched_fields || []).join(' | ');
    }

    function renderTimeline(events, incident) {
      const items = events.map((event) => ({
        status: 'event',
        message: `${event.table}: ${event.detail}`
      }));
      if (incident) {
        items.push({
          status: 'alert',
          message: `Incident #${incident.id}: ${incident.reason}`
        });
      }
      $('timeline').innerHTML = items.map((item) => {
        const className = item.status === 'alert' ? 'alert' : '';
        const textClass = item.status === 'alert' ? 'alert-text' : 'ok-text';
        const label = item.status === 'alert' ? 'ALERT' : 'EVENT';
        return `<li class="${className}">` +
          `<strong class="${textClass}">${label}</strong>` +
          `<p>${h(item.message)}</p></li>`;
      }).join('');
    }

    function renderEntities(entities) {
      const groups = ['accounts', 'ips', 'hosts', 'sources', 'tables'];
      $('entities').innerHTML = groups.map((group) => {
        const values = entities[group] || [];
        return `<div><strong>${h(group)}</strong><br>${h(values.join(', ') || '-')}</div>`;
      }).join('');
    }

    function renderNotes(notes) {
      $('notes').innerHTML = notes.length ? notes.map((note) => `
        <div><strong>${h(note.status)}</strong><br>${h(note.note)}<br><small>${h(note.created_at)}</small></div>
      `).join('') : '<div>No notes yet.</div>';
    }

    function renderCounts(counts) {
      $('benign-count').textContent = counts.benign || 0;
      $('signal-count').textContent = counts.signal || 0;
    }

    function renderCaseTasks(tasks) {
      $('case-tasks').innerHTML = tasks.length ? tasks.map((task) => `
        <div>
          <label>
            <input
              type="checkbox"
              data-task="${h(task.task_id)}"
              ${task.completed ? 'checked' : ''}
            >
            ${h(task.label)}
          </label>
        </div>
      `).join('') : '<div>No active case tasks.</div>';
      document.querySelectorAll('[data-task]').forEach((checkbox) => {
        checkbox.addEventListener('change', () => updateCaseTask(
          checkbox.dataset.task,
          checkbox.checked
        ));
      });
    }

    async function updateCaseTask(taskId, completed) {
      if (!state.activeCaseRun) return;
      const response = await fetch(`/api/cases/${state.activeCaseRun.run.id}/task`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({task_id: taskId, completed})
      });
      const payload = await response.json();
      renderCaseRun(payload);
      if (state.activeTraining) {
        await loadTrainingRun(state.activeTraining.run.id);
      }
    }

    async function updateTrainingCheckpoint(checkpointId, completed) {
      if (!state.activeTraining) return;
      const response = await fetch(`/api/training/${state.activeTraining.run.id}/checkpoint`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({checkpoint_id: checkpointId, completed})
      });
      renderTrainingRun(await response.json());
    }

    async function submitTrainingAnswer(questionId) {
      if (!state.activeTraining) return;
      const selected = document.querySelector(
        `input[name="training-question-${questionId}"]:checked`
      );
      if (!selected) {
        $('training-hint-output').textContent = 'Choose an answer before checking your reasoning.';
        return;
      }
      const response = await fetch(`/api/training/${state.activeTraining.run.id}/answer`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({question_id: questionId, answer: selected.value})
      });
      const payload = await response.json();
      if (!response.ok) {
        $('training-hint-output').textContent = payload.error || 'The answer could not be checked.';
        return;
      }
      renderTrainingRun(payload);
    }

    async function moveTrainingGuide(delta) {
      if (!state.activeTraining) return;
      const target = state.activeTraining.guide.current_step + delta;
      const response = await fetch(`/api/training/${state.activeTraining.run.id}/guide`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({step_index: target})
      });
      renderTrainingRun(await response.json());
    }

    async function tickTrainingCase() {
      if (!state.activeTraining) return;
      const response = await fetch(
        `/api/cases/${state.activeTraining.case_run.run.id}/tick`,
        {method: 'POST'}
      );
      const casePayload = await response.json();
      renderCaseRun(casePayload);
      await loadTrainingRun(state.activeTraining.run.id);
      await loadIncidents(casePayload.incident ? casePayload.incident.id : null);
    }

    async function closeGuidedTrainingCase() {
      if (!state.activeTraining) return;
      const response = await fetch(
        `/api/cases/${state.activeTraining.case_run.run.id}/close`,
        {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            decision: $('training-case-decision').value,
            note: $('training-case-note').value
          })
        }
      );
      const casePayload = await response.json();
      await loadTrainingRun(state.activeTraining.run.id);
      await loadIncidents(casePayload.incident ? casePayload.incident.id : null);
      if (state.activeTraining.guide.current.flow_id === 'close') {
        await moveTrainingGuide(1);
      }
    }

    async function exportEvidence(format) {
      const suffix = state.selectedIncidentId
        ? `incident=${state.selectedIncidentId}&format=${format}`
        : `scenario=${state.scenario.scenario_id}&format=${format}`;
      const response = await fetch(`/api/evidence?${suffix}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const id = state.selectedIncidentId
        ? `incident-${state.selectedIncidentId}`
        : state.scenario.scenario_id;
      link.href = url;
      link.download = `${id}-live-evidence.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    }

    async function exportCaseEvidence(format) {
      if (!state.activeCaseRun) {
        $('case-note-status').textContent = 'Start a case run first.';
        return;
      }
      const id = state.activeCaseRun.run.id;
      const response = await fetch(`/api/evidence?case=${id}&format=${format}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `case-${id}-evidence.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    }

    async function exportTrainingEvidence(format) {
      if (!state.activeTraining) {
        $('training-feedback').textContent = 'Start guided training first.';
        return;
      }
      const id = state.activeTraining.run.id;
      const response = await fetch(`/api/evidence?training=${id}&format=${format}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `training-${id}-evidence.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    }

    async function requestHint() {
      if (!state.activeTraining) {
        $('training-feedback').textContent = 'Start guided training first.';
        return;
      }
      const response = await fetch(`/api/training/${state.activeTraining.run.id}/hint`, {
        method: 'POST'
      });
      renderTrainingRun(await response.json());
    }

    async function saveInstructorReview() {
      if (!state.activeTraining) {
        $('instructor-review-status').textContent = 'Close a guided training case first.';
        return;
      }
      const response = await fetch(
        `/api/training/${state.activeTraining.run.id}/instructor-review`,
        {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            rating: $('instructor-rating').value,
            observation: $('instructor-observation').value
          })
        }
      );
      const payload = await response.json();
      renderTrainingRun(payload);
      $('instructor-review-status').textContent = `Review saved: ${payload.review.rating}`;
    }

    async function closeCase() {
      if (!state.activeCaseRun) {
        $('case-note-status').textContent = 'Start a case run first.';
        return;
      }
      const response = await fetch(`/api/cases/${state.activeCaseRun.run.id}/close`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          decision: $('case-decision').value,
          note: $('case-note').value
        })
      });
      const payload = await response.json();
      renderCaseRun(payload);
      if (state.activeTraining) {
        await loadTrainingRun(state.activeTraining.run.id);
      }
      $('case-note-status').textContent = `Closed: ${payload.run.decision}`;
      await loadIncidents(payload.incident ? payload.incident.id : null);
    }

    async function saveNote() {
      if (!state.selectedIncidentId) {
        $('note-status').textContent = 'Run a scenario until an incident is created.';
        return;
      }
      const response = await fetch(`/api/incidents/${state.selectedIncidentId}/analyst-action`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          status: $('analyst-status').value,
          note: $('analyst-note').value
        })
      });
      const payload = await response.json();
      $('note-status').textContent = `Saved: ${payload.status}`;
      $('analyst-note').value = '';
      await selectIncident(state.selectedIncidentId);
    }

    $('scenario').addEventListener('change', (event) => loadScenario(event.target.value));
    $('start').addEventListener('click', start);
    $('pause').addEventListener('click', pause);
    $('reset').addEventListener('click', reset);
    $('reset-runtime').addEventListener('click', resetRuntime);
    $('filter-status').addEventListener('change', () => loadIncidents());
    $('filter-severity').addEventListener('change', () => loadIncidents());
    $('filter-entity').addEventListener('input', () => loadIncidents());
    $('training-start').addEventListener('click', startTrainingRun);
    $('training-hint').addEventListener('click', requestHint);
    $('training-export-json').addEventListener('click', () => exportTrainingEvidence('json'));
    $('training-export-md').addEventListener('click', () => exportTrainingEvidence('md'));
    $('training-back').addEventListener('click', () => moveTrainingGuide(-1));
    $('training-next').addEventListener('click', () => moveTrainingGuide(1));
    $('instructor-review-save').addEventListener('click', saveInstructorReview);
    $('case-start').addEventListener('click', startCaseRun);
    $('case-tick').addEventListener('click', tickCaseRun);
    $('case-export-json').addEventListener('click', () => exportCaseEvidence('json'));
    $('case-export-md').addEventListener('click', () => exportCaseEvidence('md'));
    $('case-close').addEventListener('click', closeCase);
    $('export-json').addEventListener('click', () => exportEvidence('json'));
    $('export-md').addEventListener('click', () => exportEvidence('md'));
    $('save-note').addEventListener('click', saveNote);
    document.querySelectorAll('[data-view]').forEach((button) => {
      button.addEventListener('click', () => setView(button.dataset.view));
    });
    document.querySelectorAll('[data-open-view]').forEach((button) => {
      button.addEventListener('click', () => setView(button.dataset.openView));
    });
    setView('overview');
    loadScenarios();
  </script>
</body>
</html>
"""
    return html.replace("__SCOPE_WARNING__", SCOPE_WARNING)


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
        if parsed.path == "/api/state":
            params = parse_qs(parsed.query)
            scenario_id = params.get("scenario", ["SENT-006-POS"])[0]
            self._send_json(live_state(scenario_id))
            return
        if parsed.path == "/api/training":
            self._send_json(training_index())
            return
        if parsed.path.startswith("/api/training/"):
            training_run_id = parsed.path.strip("/").split("/")[2]
            try:
                self._send_json(training_run_detail(int(training_run_id)))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=404)
            return
        if parsed.path == "/api/cases":
            self._send_json(case_index())
            return
        if parsed.path.startswith("/api/cases/"):
            case_run_id = parsed.path.strip("/").split("/")[2]
            try:
                self._send_json(case_run_detail(int(case_run_id)))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=404)
            return
        if parsed.path == "/api/incidents":
            self._send_json(incident_queue())
            return
        if parsed.path.startswith("/api/incidents/"):
            incident_id = parsed.path.rsplit("/", maxsplit=1)[-1]
            try:
                detail = incident_detail(int(incident_id))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=404)
                return
            if detail is None:
                self._send_json({"error": "incident not found"}, status=404)
                return
            self._send_json(detail)
            return
        if parsed.path == "/api/evidence":
            params = parse_qs(parsed.query)
            incident_param = params.get("incident", [None])[0]
            case_param = params.get("case", [None])[0]
            training_param = params.get("training", [None])[0]
            scenario_id = params.get("scenario", ["SENT-006-POS"])[0]
            output_format = params.get("format", ["json"])[0]
            if training_param is not None:
                try:
                    training_run_id = int(training_param)
                    detail = training_run_detail(training_run_id)
                    if output_format == "md":
                        self._send_text(
                            training_evidence_markdown(training_run_id),
                            "text/markdown; charset=utf-8",
                        )
                        return
                    self._send_json(detail)
                    return
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                    return
            if case_param is not None:
                try:
                    case_run_id = int(case_param)
                    detail = case_run_detail(case_run_id)
                    if output_format == "md":
                        self._send_text(
                            case_evidence_markdown(case_run_id),
                            "text/markdown; charset=utf-8",
                        )
                        return
                    self._send_json(detail)
                    return
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                    return
            if incident_param is not None:
                try:
                    incident_id = int(incident_param)
                    detail = incident_detail(incident_id)
                    if detail is None:
                        self._send_json({"error": "incident not found"}, status=404)
                        return
                    if output_format == "md":
                        self._send_text(
                            incident_evidence_markdown(incident_id),
                            "text/markdown; charset=utf-8",
                        )
                        return
                    self._send_json(detail)
                    return
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=404)
                    return
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
            if parsed.path == "/api/runtime/reset":
                self._send_json(reset_runtime())
                return
            if parsed.path == "/api/tick":
                self._send_json(tick_run(scenario_id))
                return
            if parsed.path == "/api/training/start":
                payload = self._read_json_body()
                self._send_json(start_training_run(str(payload.get("module_id", "TRAIN-001"))))
                return
            if parsed.path.startswith("/api/training/") and parsed.path.endswith("/answer"):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    submit_training_answer(
                        int(parts[2]),
                        str(payload.get("question_id", "")),
                        str(payload.get("answer", "")),
                    )
                )
                return
            if parsed.path.startswith("/api/training/") and parsed.path.endswith("/checkpoint"):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    update_training_checkpoint(
                        int(parts[2]),
                        str(payload.get("checkpoint_id", "")),
                        bool(payload.get("completed", True)),
                    )
                )
                return
            if parsed.path.startswith("/api/training/") and parsed.path.endswith("/guide"):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    set_training_guide_step(
                        int(parts[2]),
                        int(payload.get("step_index", 0)),
                    )
                )
                return
            if parsed.path.startswith("/api/training/") and parsed.path.endswith(
                "/instructor-review"
            ):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    save_instructor_review(
                        int(parts[2]),
                        str(payload.get("rating", "Developing")),
                        str(payload.get("observation", "")),
                    )
                )
                return
            if parsed.path.startswith("/api/training/") and parsed.path.endswith("/hint"):
                parts = parsed.path.strip("/").split("/")
                self._send_json(request_training_hint(int(parts[2])))
                return
            if parsed.path == "/api/cases/start":
                payload = self._read_json_body()
                self._send_json(start_case_run(str(payload.get("case_id", "CASE-001"))))
                return
            if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/tick"):
                parts = parsed.path.strip("/").split("/")
                self._send_json(tick_case_run(int(parts[2])))
                return
            if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/task"):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    update_case_task(
                        int(parts[2]),
                        str(payload.get("task_id", "")),
                        bool(payload.get("completed", True)),
                    )
                )
                return
            if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/close"):
                parts = parsed.path.strip("/").split("/")
                payload = self._read_json_body()
                self._send_json(
                    close_case_run(
                        int(parts[2]),
                        str(payload.get("decision", "Closed")),
                        str(payload.get("note", "")),
                    )
                )
                return
            if parsed.path.startswith("/api/incidents/") and parsed.path.endswith(
                "/analyst-action"
            ):
                parts = parsed.path.strip("/").split("/")
                incident_id = int(parts[2])
                payload = self._read_json_body()
                result = update_incident_action(
                    incident_id,
                    str(payload.get("status", "Investigating")),
                    str(payload.get("note", "")),
                )
                self._send_json(result)
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
