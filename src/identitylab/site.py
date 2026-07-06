from __future__ import annotations

from html import escape
from pathlib import Path

from identitylab.config import HubConfig, load_config
from identitylab.paths import SITE_INDEX


def build_site(output: Path = SITE_INDEX, config: HubConfig | None = None) -> Path:
    cfg = config or load_config()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_site(cfg), encoding="utf-8", newline="\n")
    return output


def render_site(config: HubConfig) -> str:
    lab_cards = "\n".join(_render_lab_card(lab) for lab in config.labs)
    journey = "\n".join(
        f"""
        <li>
          <span class="step">{step["step"]}</span>
          <div>
            <strong>{escape(step["scenario"])} - {escape(step["title"])}</strong>
            <p>{escape(step["description"])}</p>
          </div>
        </li>
        """
        for step in config.end_to_end_walkthrough
    )
    total_rules = sum(len(lab.detections) for lab in config.labs)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Defensive Identity Lab Hub</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #172033;
      --muted: #526072;
      --line: #d9e1ec;
      --panel: #ffffff;
      --bg: #f4f7fb;
      --accent: #0d6efd;
      --accent-dark: #084298;
      --ok: #147a3d;
      --warn-bg: #fff6dd;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      color: var(--ink);
      background: var(--bg);
      line-height: 1.5;
    }}
    header {{
      background: #101828;
      color: #ffffff;
      padding: 36px 24px 28px;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ font-size: 2.4rem; }}
    h2 {{ font-size: 1.45rem; margin-bottom: 14px; }}
    h3 {{ font-size: 1.05rem; }}
    p {{ margin: 8px 0 0; }}
    a {{ color: var(--accent-dark); font-weight: 700; }}
    .hero {{
      max-width: 1180px;
      margin: 0 auto;
    }}
    .hero p {{
      max-width: 820px;
      color: #d5deea;
      font-size: 1.05rem;
    }}
    .warning {{
      background: var(--warn-bg);
      border: 1px solid #e9c86a;
      padding: 12px 14px;
      margin: 18px 0 22px;
      font-weight: 700;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 22px;
    }}
    .metric, .panel, .lab {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    .metric {{ padding: 16px; }}
    .metric strong {{ display: block; font-size: 1.7rem; }}
    .metric span {{ color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
    }}
    .lab {{ padding: 18px; display: flex; flex-direction: column; gap: 12px; }}
    .layer {{
      display: inline-block;
      color: var(--ok);
      font-size: .82rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .detections {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .detections span {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: .82rem;
      background: #f8fafc;
    }}
    .links {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      margin-top: auto;
    }}
    .links a {{
      display: block;
      text-align: center;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      text-decoration: none;
      background: #f8fbff;
    }}
    .panel {{ padding: 18px; margin-top: 18px; }}
    .journey {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 12px;
    }}
    .journey li {{
      display: grid;
      grid-template-columns: 38px minmax(0, 1fr);
      gap: 12px;
      align-items: start;
    }}
    .step {{
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: var(--accent);
      color: #ffffff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
    }}
    code {{
      background: #eef3f9;
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: 2px 5px;
    }}
    footer {{
      color: var(--muted);
      padding: 24px;
      text-align: center;
    }}
    @media (max-width: 900px) {{
      .grid, .metrics {{ grid-template-columns: 1fr; }}
      .links {{ grid-template-columns: 1fr; }}
      h1 {{ font-size: 2rem; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="hero">
      <h1>Defensive Identity Lab Hub</h1>
      <p>
        A public entry point for Windows authentication, Microsoft Entra ID
        and Microsoft Sentinel KQL detection labs.
      </p>
      <p><a href="{escape(config.hub_docs_url)}">Open hub documentation</a></p>
    </div>
  </header>
  <main>
    <div class="warning">{escape(config.scope_warning)}</div>
    <section class="metrics" aria-label="Lab metrics">
      <div class="metric"><strong>{len(config.labs)}</strong><span>connected labs</span></div>
      <div class="metric"><strong>{total_rules}</strong><span>defensive detections</span></div>
      <div class="metric"><strong>SENT-006-POS</strong><span>end-to-end incident</span></div>
    </section>
    <section>
      <h2>Labs</h2>
      <div class="grid">
        {lab_cards}
      </div>
    </section>
    <section class="panel">
      <h2>Recommended walkthrough</h2>
      <ol class="journey">
        {journey}
      </ol>
    </section>
    <section class="panel">
      <h2>Local VM preparation</h2>
      <p>
        Use this hub as the future VM landing page. Clone the three labs as
        sibling directories, run each validation command, and keep evidence
        under each lab's <code>reports/latest</code> directory.
      </p>
      <p><a href="{escape(config.hub_docs_url)}">Read the public VM guide</a></p>
    </section>
  </main>
  <footer>
    Static hub. No backend, live tenants or production data.
  </footer>
</body>
</html>
"""


def _render_lab_card(lab: object) -> str:
    detections = "\n".join(f"<span>{escape(item)}</span>" for item in lab.detections)
    return f"""
    <article class="lab">
      <span class="layer">{escape(lab.layer)}</span>
      <h3>{escape(lab.name)}</h3>
      <p>{escape(lab.summary)}</p>
      <p><strong>Primary walkthrough:</strong> {escape(lab.primary_walkthrough)}</p>
      <div class="detections" aria-label="{escape(lab.short_name)} detections">
        {detections}
      </div>
      <div class="links">
        <a href="{escape(lab.demo_url)}">Demo</a>
        <a href="{escape(lab.docs_url)}">GitBook</a>
        <a href="{escape(lab.repo_url)}">Repo</a>
      </div>
    </article>
    """
