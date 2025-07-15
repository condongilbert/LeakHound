import json
from datetime import datetime
from pathlib import Path

def save_report(results, config):
    format = config.get("report_format", "markdown").lower()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_path = Path(config.get("report_output_path", f"./reports/leakhound_report.{format}"))

    if config.get("timestamp_reports", True):
        filename = base_path.with_name(f"{base_path.stem}_{timestamp}{base_path.suffix}")
    else:
        filename = base_path

    if format == "markdown":
        content = render_markdown(results)
    elif format == "json":
        content = json.dumps(results, indent=2)
    else:
        raise ValueError(f"Unsupported report format: {format}")

    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ Report saved to: {filename}")

def render_markdown(results):
    if not results:
        return "# Leak Hound Report\n\n✅ No secrets or credentials were detected.\n"

    md = ["# 🔐 Leak Hound Scan Report", ""]
    for r in results:
        md.append(f"### [{r['severity'].upper()}] {r['description']}")
        md.append(f"- **File**: `{r['file']}`")
        md.append(f"- **Line**: {r['line']}")
        md.append(f"- **Rule**: `{r['rule']}`")
        md.append(f"- **Match (partial)**: `{r['match'][:80]}...`" if len(r['match']) > 80 else f"- **Match**: `{r['match']}`")
        md.append("")
    return "\n".join(md)
