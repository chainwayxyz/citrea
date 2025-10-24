
import json
from argparse import ArgumentParser

def calculate_delta(base_value, patch_value)->float:
    return (patch_value - base_value) / base_value * 100

def main():
    parser = ArgumentParser(description='Compare proving stats between base and patch builds')
    parser.add_argument('--patch-file')
    parser.add_argument('--base-file')
    parser.add_argument('--patch-commit')
    parser.add_argument('--base-commit')

    args = parser.parse_args()

    with open(args.base_file, 'r') as f:
        base_data = json.load(f)
    with open(args.patch_file, 'r') as f:
        patch_data = json.load(f)
    
    assert base_data.keys() == patch_data.keys(), "Keys in the two files do not match."

    lines = []
    lines.append("## Proving stats report\n")
    patch_commit = args.patch_commit[:7]
    base_commit = args.base_commit[:7]
    
    commit_url_base = "https://github.com/chainwayxyz/citrea/commit/"
    patch_commit = f"[(`{patch_commit}`)]({commit_url_base}{patch_commit})"
    base_commit = f"[(`{base_commit}`)]({commit_url_base}{base_commit})"

    lines.append(f"Comparing patch{patch_commit} to base{base_commit}.\n")
    lines.append("|    | Metric                  | Base        | Patch           | Change     |")
    lines.append("|----|-------------------------|----------------|------------------|------------|")

    for key in base_data.keys():
        base_value = base_data[key]
        patch_value = patch_data[key]
        delta = calculate_delta(base_value, patch_value)

        if delta == 0:
            emoji = "✅"
            delta_str = "-"
        else:
            emoji = "📈" if delta > 0 else "📉"
            delta_str = f"{delta:+.2f}%"
        metric = key
        lines.append(f"| {emoji} | {metric:<23} | {base_value:,} | {patch_value:,} | {delta_str:<9} |")

    with open('comment-body.md', 'w') as f:
        f.write("\n".join(lines))
if __name__ == "__main__":
    main()
