from __future__ import annotations

import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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


def evidence_markdown(scenario: LiveScenario) -> str:
    lines = [
        f"# Live lab evidence: {scenario.scenario_id}",
        "",
        f"- Title: {scenario.title}",
        f"- Primary detection: {scenario.primary_detection}",
        f"- Severity: {scenario.severity}",
        f"- Expected result: {scenario.expected_result}",
        f"- Analyst goal: {scenario.analyst_goal}",
        "",
        "## Events",
        "",
    ]
    for event in scenario.events:
        lines.append(
            "- "
            f"t+{event['offset']}s {event['table']} {event['account']} "
            f"{event['ip']} {event['result']} - {event['detail']}"
        )
    lines.extend(["", "## Scope", "", SCOPE_WARNING, ""])
    return "\n".join(lines)


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
      </div>
    </section>
  </main>
  <script>
    const state = {{
      scenarios: [],
      scenario: null,
      eventIndex: 0,
      stepIndex: 0,
      timer: null,
      paused: false
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
      reset();
    }}

    function reset() {{
      clearInterval(state.timer);
      state.timer = null;
      state.eventIndex = 0;
      state.stepIndex = 0;
      state.paused = false;
      $('events').innerHTML = '';
      $('timeline').innerHTML = '';
      $('summary').textContent = state.scenario.summary;
      $('detection').textContent = state.scenario.primary_detection;
      $('severity').textContent = state.scenario.severity;
      $('expected').textContent = state.scenario.expected_result;
      $('status').textContent = 'Ready';
    }}

    function start() {{
      if (!state.scenario || state.timer) return;
      $('status').textContent = 'Running';
      state.timer = setInterval(tick, 900);
      tick();
    }}

    function pause() {{
      if (state.timer) {{
        clearInterval(state.timer);
        state.timer = null;
        $('status').textContent = 'Paused';
      }}
    }}

    function tick() {{
      if (state.eventIndex >= state.scenario.events.length) {{
        clearInterval(state.timer);
        state.timer = null;
        if ($('status').textContent !== 'Alert') $('status').textContent = 'Complete';
        return;
      }}
      state.eventIndex += 1;
      renderEvent(state.scenario.events[state.eventIndex - 1]);
      renderDetectionSteps();
    }}

    function renderEvent(event) {{
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>t+${{event.offset}}s</td>
        <td><span class="pill">${{event.table}}</span></td>
        <td>${{event.account}}</td>
        <td>${{event.ip}}</td>
        <td>${{event.host}}</td>
        <td>${{event.result}}</td>
        <td>${{event.detail}}</td>
      `;
      $('events').appendChild(row);
    }}

    function renderDetectionSteps() {{
      while (
        state.stepIndex < state.scenario.detection_steps.length &&
        state.scenario.detection_steps[state.stepIndex].after_event <= state.eventIndex
      ) {{
        const step = state.scenario.detection_steps[state.stepIndex];
        const item = document.createElement('li');
        item.className = step.status === 'alert' ? 'alert' : '';
        const className = step.status === 'alert' ? 'alert-text' : 'ok-text';
        const status = step.status.toUpperCase();
        item.innerHTML =
          `<strong class="${{className}}">${{status}}</strong>` +
          `<p>${{step.message}}</p>`;
        $('timeline').appendChild(item);
        if (step.status === 'alert') $('status').textContent = 'Alert';
        state.stepIndex += 1;
      }}
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

    $('scenario').addEventListener('change', (event) => loadScenario(event.target.value));
    $('start').addEventListener('click', start);
    $('pause').addEventListener('click', pause);
    $('reset').addEventListener('click', reset);
    $('export-json').addEventListener('click', () => exportEvidence('json'));
    $('export-md').addEventListener('click', () => exportEvidence('md'));
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
                self._send_text(evidence_markdown(scenario), "text/markdown; charset=utf-8")
                return
            self._send_json(scenario_to_dict(scenario))
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
