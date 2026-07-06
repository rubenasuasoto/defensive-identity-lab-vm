# Defensive Identity Lab VM

[![Validate hub](https://github.com/rubenasuasoto/defensive-identity-lab-vm/actions/workflows/validate.yml/badge.svg)](https://github.com/rubenasuasoto/defensive-identity-lab-vm/actions/workflows/validate.yml)

A lightweight public hub and future local VM plan for three defensive identity detection labs:

- Windows Authentication Detection Lab
- Microsoft Entra Detection Lab
- Microsoft Sentinel KQL Detection Lab

The hub does not duplicate those projects. It links their public demos, GitBook documentation, repositories and recommended walkthroughs from one static page.

> Synthetic lab only. No production logs, credentials, tenants, tokens, malware, offensive simulations or host-changing actions.

## Public Hub

Expected GitHub Pages URL:

<https://rubenasuasoto.github.io/defensive-identity-lab-vm/>

## Connected Labs

| Lab | Layer | Public demo | Docs |
|---|---|---|---|
| Windows Authentication Detection Lab | Endpoint authentication | <https://rubenasuasoto.github.io/windows-authentication-detection-lab/reports/latest/demo.html> | <https://2dam-7.gitbook.io/window-auth/> |
| Microsoft Entra Detection Lab | Cloud identity | <https://rubenasuasoto.github.io/microsoft-entra-detection-lab/reports/latest/demo.html> | <https://2dam-7.gitbook.io/window-entra/> |
| Microsoft Sentinel KQL Detection Lab | SIEM correlation | <https://rubenasuasoto.github.io/microsoft-sentinel-kql-detection-lab/reports/latest/demo.html> | <https://2dam-7.gitbook.io/window-sentinel/> |

## Recommended Walkthrough

1. Start with `AUTH-003-POS` in the Windows lab to review repeated authentication failures followed by success.
2. Move to `ENTRA-003-POS` in the Entra lab to review repeated MFA denials followed by a successful sign-in.
3. Finish with `SENT-006-POS` in the Sentinel lab to correlate cloud identity and endpoint authentication signals.

## Quick Start

Requirements: Python 3.12 and `uv`.

```powershell
uv sync --extra dev --locked
uv run identitylab build-site
uv run identitylab verify
uv run identitylab all
```

Open:

```text
site/index.html
```

## VM Direction

This repo is the coordination layer for a future local VM. The first version is intentionally static and safe: it provides a landing page, a verification command and documentation for cloning the three labs as sibling directories.

See [`docs/VM_PLAN.md`](docs/VM_PLAN.md) for the phased VM plan and evidence checklist.
