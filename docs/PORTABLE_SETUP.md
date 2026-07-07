# Portable setup

Use this guide when preparing the lab on another computer.

The lab does not require the same user profile or Desktop path. The only expected layout is that the hub and the three labs are sibling directories under the same parent folder.

## Requirements

- Windows 10/11, macOS or Linux.
- Git.
- Python 3.12.
- `uv`.
- Optional on Windows: WSL with Ubuntu if you want a lightweight Linux workspace.

## Setup

Clone the hub:

```powershell
git clone https://github.com/rubenasuasoto/defensive-identity-lab-vm.git
cd defensive-identity-lab-vm
uv sync --extra dev --locked
```

Clone the three sibling labs:

```powershell
.\scripts\bootstrap-sibling-labs.ps1
```

Check readiness:

```powershell
.\scripts\vm-readiness.ps1
```

Run all local validations:

```powershell
.\scripts\run-all-labs.ps1
```

Generate evidence:

```powershell
.\scripts\vm-evidence.ps1
```

Start the local hub:

```powershell
.\scripts\start-local-hub.ps1
```

Open:

```text
http://127.0.0.1:8088/
```

Start the dynamic Live Lab:

```powershell
.\scripts\start-live-lab.ps1
```

Open:

```text
http://127.0.0.1:8090/
```

## Persistent Live Lab startup

On the dedicated lab computer, install persistent startup:

```powershell
.\scripts\install-live-lab-task.ps1
```

The installer tries a least-privilege Scheduled Task first. If the local account cannot register tasks, it falls back to the current user's Startup folder.

This starts `identitylab live --host 127.0.0.1 --port 8090` when the user signs in and writes local logs under:

```text
runtime/logs/
```

Open the Workbench:

```powershell
.\scripts\open-live-lab.ps1
```

Remove the Scheduled Task or Startup folder fallback:

```powershell
.\scripts\uninstall-live-lab-task.ps1
```

## Scope

This setup uses synthetic data only. It does not connect to production tenants, ingest real logs, store credentials, run payloads or modify Windows security settings.
