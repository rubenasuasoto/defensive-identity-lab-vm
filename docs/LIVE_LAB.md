# Live lab

The live lab is a local synthetic detection environment for defensive identity review.

It does not connect to Azure, Microsoft Graph, Microsoft Sentinel, production Windows hosts, tenants, credentials, tokens or real logs.

Events are emitted into a local SQLite store, evaluated by a local detection engine and converted into synthetic incidents when the rule conditions are met. The Analyst Workbench keeps incidents, entities, status changes and notes between browser reloads.

## Start

```powershell
.\scripts\start-live-lab.ps1
```

Open:

```text
http://127.0.0.1:8090/
```

## Scenarios

- `SENT-006-POS`: cross-source identity incident.
- `ENTRA-003-POS`: MFA denied repeatedly followed by success.
- `AUTH-003-POS`: Windows success after repeated failures.

## Reviewer flow

1. Select `SENT-006-POS`.
2. Click `Start`.
3. Watch the event stream populate.
4. Review the rule evaluation panel as the engine waits for enough evidence.
5. Select the generated item in `Incident queue`.
6. Review `Incident detail`, `Entities` and `Rule evaluation`.
7. Set an analyst status such as `Investigating`, `Suspicious` or `Closed`.
8. Add an analyst note.
9. Export JSON or Markdown evidence for the selected incident.

## Analyst Workbench

The Workbench is intentionally local and synthetic, but it behaves like a small analyst console:

- `Incident queue`: all generated incidents in the local SQLite runtime store.
- `Incident detail`: timeline, related synthetic events and alert reason.
- `Entities`: accounts, IPs, hosts, sources and tables seen in the incident.
- `Rule evaluation`: why the local evaluator alerted and which fields matched.
- `Analyst action`: persistent status and notes.
- `Case run`: a guided SOC-style investigation with benign noise and one primary alert.
- `Analyst tasks`: checklist items for account, IP, host, MFA and correlation review.

Allowed statuses:

```text
New, Investigating, Benign, Suspicious, Escalated, Closed
```

## Case run

`CASE-001` is a synthetic cross-source identity investigation. It mixes benign Windows, Entra and audit activity with a primary `SENT-006` correlation:

1. Start `CASE-001`.
2. Click `Next case event` to emit benign and alertable events into the same timeline.
3. Review the filtered incident queue, entities and rule evaluation.
4. Complete analyst tasks.
5. Close the case with `Benign`, `Suspicious`, `Escalated` or `Closed`.
6. Export case evidence as JSON or Markdown.

The case remains local in `live_lab.sqlite` until `Reset runtime state` is used.

## Guided Training v0.8.0

`TRAIN-001` teaches the `CASE-001` cross-source workflow and `TRAIN-002` teaches
the `CASE-002` Entra MFA-denial workflow. Both are guided case journeys rather
than collections of separate panels:

- Choose a synthetic case and read the briefing.
- Reveal timeline events and identify benign context by choosing the event that is unrelated.
- Correlate entities, then select the account and IP that explain the cross-source signal.
- Reach the local alert, explain the rule sequence, choose a triage action and close the case with a decision note.
- Review feedback, assessment and facilitator notes after closure.

`Back` and `Continue` move through the path. The current step is stored locally,
so a learner can refresh the browser and resume without restarting the case.

The guided screen includes an internal `Evidence desk` with Timeline, Entities,
Incident and Rule evaluation tabs. Learners can inspect those views while staying
inside the lesson. Each objective uses two screens: a `Lab activity` screen with
the Evidence desk, followed by a separate `Knowledge check` screen with no
evidence panel. The Timeline question is therefore never displayed beside the
events used to answer it.

Learning objectives open in a modal when a learner starts a case and remain
available from the `Learning objectives` button. Progressive hints remain
available without revealing the facilitator notes. Each decision records attempts
locally and unlocks the next guided screen only when the reasoning is correct.
The final outcome contains feedback, assessment and lesson notes, but no
facilitator-review controls. The `Case run` and `Incidents` views remain available
as free-practice Workbench tools.

Expected decisions are `Suspicious` or `Escalated`. Closing as `Benign` produces corrective feedback because the correlated cloud and endpoint evidence should be investigated.

`TRAIN-002` uses only synthetic Entra-style events: two MFA denials followed by a
success for the same account and IP. It has no tenant connection, token, live
Graph call or real authentication data.

## Local state

The live lab writes local runtime state to:

```text
live_lab.sqlite
```

The database stores synthetic events, incidents and analyst notes. It is ignored by Git and can be deleted when you want a clean local runtime state.

Use `Reset scenario` to clear the active scenario. Use `Reset runtime state` to clear all local synthetic events, incidents and notes from the Workbench.

## Persistent startup on Windows

Install a persistent launcher that starts the Live Lab when the lab user signs in:

```powershell
.\scripts\install-live-lab-task.ps1
```

The installer first tries to create a least-privilege Scheduled Task for the current user. If Windows blocks task registration for the local account, it creates a Startup folder fallback instead. Both options run the same local command:

```text
identitylab live --host 127.0.0.1 --port 8090
```

Open the Workbench:

```powershell
.\scripts\open-live-lab.ps1
```

Uninstall the Scheduled Task or Startup folder fallback:

```powershell
.\scripts\uninstall-live-lab-task.ps1
```

Task logs are local and ignored by Git:

```text
runtime/logs/live-lab.log
```

## Scope

Synthetic lab only. No production logs, credentials, tenants, tokens, malware, offensive simulations or host-changing actions.
