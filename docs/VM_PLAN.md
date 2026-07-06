# VM plan

This document describes the future local VM direction for the defensive identity lab set.

The VM must remain defensive and synthetic. It must not connect to production tenants, ingest real logs, store credentials, deploy payloads or modify Windows security settings.

## VM-A: Static review station

Goal: provide a local landing page and offline-friendly review flow.

Required evidence:

- `identitylab all` output.
- Screenshot or saved copy of `site/index.html`.
- Public URL verification for the hub GitBook, the three lab demos and the three lab GitBook spaces.

## VM-B: Local clone workspace

Goal: clone the three labs as sibling directories and run their validation commands.

Expected layout:

```text
Desktop/
  defensive-identity-lab-vm/
  windows-authentication-detection-lab/
  microsoft-entra-detection-lab/
  microsoft-sentinel-kql-detection-lab/
```

Validation commands:

```powershell
cd ..\windows-authentication-detection-lab
uv run authlab all
uv run authlab demo

cd ..\microsoft-entra-detection-lab
uv run entralab all
uv run entralab demo

cd ..\microsoft-sentinel-kql-detection-lab
uv run sentinellab all
uv run sentinellab demo
```

Required evidence:

- `reports/latest` from each lab.
- CLI output showing all synthetic cases pass.
- A short note confirming no real logs, tenants, credentials or tokens were used.

## VM-C: Guided local review

Goal: make the VM feel like one coherent lab without merging the projects.

Recommended flow:

1. Open the hub.
2. Open Windows `AUTH-003-POS`.
3. Open Entra `ENTRA-003-POS`.
4. Open Sentinel `SENT-006-POS`.
5. Review the linked GitBook playbooks.

Required evidence:

- One screenshot per lab demo.
- The Sentinel `SENT-006-POS` walkthrough.
- Validation reports from all three labs.
