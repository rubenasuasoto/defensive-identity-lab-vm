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

Allowed statuses:

```text
New, Investigating, Benign, Suspicious, Escalated, Closed
```

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
