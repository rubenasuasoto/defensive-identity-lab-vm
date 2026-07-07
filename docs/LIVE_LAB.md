# Live lab

The live lab is a local synthetic replay environment for defensive identity detection review.

It does not connect to Azure, Microsoft Graph, Microsoft Sentinel, production Windows hosts, tenants, credentials, tokens or real logs.

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
4. Review the incident timeline when the alert fires.
5. Export JSON or Markdown evidence.

## Scope

Synthetic lab only. No production logs, credentials, tenants, tokens, malware, offensive simulations or host-changing actions.
