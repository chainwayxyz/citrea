'''
Use to remove specific label selectors and variables from Grafana dashboards.
After updating a prod dashboard run this on the updated file to create a user dashboard.
Usage:
python <path_to_script>/remove_labels.py resources/grafana/prod/<node_type>.dashboard.json > resources/grafana/user/<node_type>.dashboard.json
'''

import json
import re
import sys
from copy import deepcopy

LABEL_SELECTOR_REGEX = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{[^}]*\}')


def strip_label_selectors(expr: str) -> str:
    """
    Remove all PromQL label selectors from a query string.

    Examples:
      sequencer_current_l2_block{net_name="$net_name"}             -> sequencer_current_l2_block
      rate(foo_bar{job="x",net_name="$net_name"}[1m])              -> rate(foo_bar[1m])
      foo{a="1"} + bar{b="2"}                                      -> foo + bar
    """
    if not isinstance(expr, str):
        return expr

    previous = None
    current = expr
    # Run until no more replacements (handles multiple metrics in same expr)
    while previous != current:
        previous = current
        current = LABEL_SELECTOR_REGEX.sub(r"\1", current)
    return current


def process_dashboard(dashboard: dict) -> dict:
    db = deepcopy(dashboard)

    # Strip label filters from all targets.expr
    panels = db.get("panels", [])
    for panel in panels:
        targets = panel.get("targets", [])
        for t in targets:
            expr = t.get("expr")
            if expr:
                t["expr"] = strip_label_selectors(expr)

    # Remove "net_name" and "env_name" variable from templating.list
    templating = db.get("templating", {})
    variables = templating.get("list", [])
    templating["list"] = [
        v for v in variables if v.get("name") not in ("net_name", "env_name")
    ]
    db["templating"] = templating

    return db


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <dashboard.json>", file=sys.stderr)
        sys.exit(1)

    in_path = sys.argv[1]
    with open(in_path, "r", encoding="utf-8") as f:
        dashboard = json.load(f)

    cleaned = process_dashboard(dashboard)
    json.dump(cleaned, sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
