import os
import re
import yaml
import json
from pathlib import Path

# === Load config and rules ===
def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def load_rules(rules_path):
    with open(rules_path, "r") as f:
        return json.load(f)

# === Entropy check ===
def calculate_entropy(s):
    import math
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

# === Scan a single file ===
def scan_file(filepath, rules, config):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                for rule_name, rule in rules.items():
                    if re.search(rule["regex"], line):
                        entropy_val = calculate_entropy(line.strip())
                        if config.get("use_entropy", False) and entropy_val < config.get("entropy_threshold", 4.5):
                            continue
                        findings.append({
                            "file": str(filepath),
                            "line": i,
                            "match": line.strip(),
                            "rule": rule_name,
                            "description": rule["description"],
                            "severity": rule["severity"]
                        })
    except Exception as e:
        print(f"[!] Failed to scan {filepath}: {e}")
    return findings

# === Scan directory recursively ===
def scan_directory(config, rules):
    results = []
    base_path = Path(config.get("scan_path", "./"))
    exclude = config.get("exclude_patterns", [])
    for root, _, files in os.walk(base_path):
        if any(ex in root for ex in exclude):
            continue
        for file in files:
            full_path = Path(root) / file
            if any(full_path.match(p) for p in exclude):
                continue
            results.extend(scan_file(full_path, rules, config))
    return results

# === Main entrypoint ===
def main():
    config = load_config()
    rules = load_rules(config.get("rules_file", "rules.json"))
    results = scan_directory(config, rules)

    print(f"\nScan complete. {len(results)} potential leaks found.")
    for r in results:
        print(f"[{r['severity'].upper()}] {r['file']}:{r['line']} - {r['description']}")

    return results

if __name__ == "__main__":
    main()