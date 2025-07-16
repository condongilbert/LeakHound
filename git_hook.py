import subprocess
import json
import os
from scanner import scan_file, load_config, load_rules

def get_staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip().splitlines()

def run_pre_commit():
    config = load_config()
    rules = load_rules(config.get("rules_file", "rules.json"))

    staged_files = get_staged_files()
    print(f"🔍 Leak Hound is scanning {len(staged_files)} staged file(s)...\n")

    findings = []
    for file in staged_files:
        if not os.path.isfile(file):
            continue
        results = scan_file(file, rules, config)
        findings.extend(results)

    if not findings:
        print("✅ No secrets found. Commit approved.\n")
        return 0  # Success

    print("❌ Leak Hound detected potential secrets:\n")
    for r in findings:
        print(f"[{r['severity'].upper()}] {r['file']}:{r['line']} - {r['description']}")

    if config.get("git_hooks", {}).get("block_on_leak", True):
        print("\n🚫 Commit blocked due to secret detection.\n")
        return 1  # Block commit
    else:
        print("\n⚠️ Leak detected, but commit is allowed by config.\n")
        return 0  # Allow commit

if __name__ == "__main__":
    exit(run_pre_commit())
