# Live lab

The live lab is a local synthetic detection environment for defensive identity review.

It does not connect to Azure, Microsoft Graph, Microsoft Sentinel, production Windows hosts, tenants, credentials, tokens or real logs.

Events are emitted into a local SQLite store, evaluated by a local detection engine and converted into synthetic incidents when the rule conditions are met.

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
5. Review the incident timeline when the alert fires.
6. Add an analyst status and note.
7. Export JSON or Markdown evidence.

## Local state

The live lab writes local runtime state to:

```text
live_lab.sqlite
```

The database stores synthetic events, incidents and analyst notes. It is ignored by Git and can be deleted when you want a clean local runtime state.

## Scope

Synthetic lab only. No production logs, credentials, tenants, tokens, malware, offensive simulations or host-changing actions.
