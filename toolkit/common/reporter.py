"""Shared HTML report generation for all toolkit modules."""

from datetime import datetime
from pathlib import Path


class HTMLReporter:
    """Generate styled HTML reports."""

    CSS = """
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           margin: 0; padding: 2rem; background: #0d1117; color: #c9d1d9; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
    h2 { color: #79c0ff; margin-top: 2rem; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 1rem 1.25rem; margin: 1rem 0; }
    .score { font-size: 3rem; font-weight: bold; }
    .bar { height: 12px; border-radius: 6px; background: #21262d; margin: 0.5rem 0; }
    .bar-fill { height: 100%; border-radius: 6px; transition: width 0.5s; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; }
    .red { color: #f85149; } .green { color: #3fb950; } .yellow { color: #d29922; }
    .bg-red { background: #f8514920; } .bg-green { background: #3fb95020; } .bg-yellow { background: #d2992220; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
    th { background: #161b22; color: #58a6ff; padding: 10px; text-align: left; border: 1px solid #30363d; }
    td { padding: 8px 10px; border: 1px solid #30363d; }
    tr:hover { background: #161b22; }
    .meta { color: #8b949e; font-size: 0.85rem; }
    """

    def __init__(self, title: str):
        self.title = title
        self.sections: list[str] = []

    def add_section(self, title: str, content: str):
        self.sections.append(f"<h2>{title}</h2>\n{content}")

    def add_card(self, content: str):
        self.sections.append(f'<div class="card">{content}</div>')

    def add_table(self, headers: list[str], rows: list[list[str]]):
        h = "".join(f"<th>{h}</th>" for h in headers)
        r = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
        self.sections.append(f"<table><tr>{h}</tr>{r}</table>")

    def render(self, output_path: str | None = None) -> str:
        path = Path(output_path or f"reports_output/{self.title.lower().replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M}.html")
        path.parent.mkdir(parents=True, exist_ok=True)

        body = "\n".join(self.sections)
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{self.title}</title>
<style>{self.CSS}</style></head><body>
<div class="container">
<h1>{self.title}</h1>
<p class="meta">Generated: {datetime.now():%Y-%m-%d %H:%M}</p>
{body}
</div></body></html>"""

        path.write_text(html)
        return str(path)
