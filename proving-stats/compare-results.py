
import json
from argparse import ArgumentParser

def calculate_delta(nightly_value, patch_value)->float:
    return (patch_value - nightly_value) / nightly_value * 100

def main():
    parser = ArgumentParser(description='Compare proving stats between nightly and patch builds')
    parser.add_argument('--patch-file')
    parser.add_argument('--nightly-file')
    parser.add_argument('--patch-commit')
    parser.add_argument('--nightly-commit')

    args = parser.parse_args()

    with open(args.nightly_file, 'r') as f:
        nightly_data = json.load(f)
    with open(args.patch_file, 'r') as f:
        patch_data = json.load(f)
    
    assert nightly_data.keys() == patch_data.keys(), "Keys in the two files do not match."

    lines = []
    lines.append("## Proving stats report\n")
    patch_commit = args.patch_commit[:7]
    nightly_commit = args.nightly_commit[:7]
    
    commit_url_base = "https://github.com/chainwayxyz/citrea/commit/"
    patch_commit = f"[(`{patch_commit}`)]({commit_url_base}{patch_commit})"
    nightly_commit = f"[(`{nightly_commit}`)]({commit_url_base}{nightly_commit})"

    lines.append(f"Comparing patch{patch_commit} to nightly{nightly_commit}.\n")
    lines.append("|    | Metric                  | Nightly        | Patch           | Change     |")
    lines.append("|----|-------------------------|----------------|------------------|------------|")

    for key in nightly_data.keys():
        nightly_value = nightly_data[key]
        patch_value = patch_data[key]
        delta = calculate_delta(nightly_value, patch_value)

        if delta == 0:
            emoji = "✅"
            delta_str = "-"
        else:
            emoji = "📈" if delta > 0 else "📉"
            delta_str = f"{delta:+.2f}%"
        metric = key
        lines.append(f"| {emoji} | {metric:<23} | {nightly_value:,} | {patch_value:,} | {delta_str:<9} |")

    with open('comment-body.md', 'w') as f:
        f.write("\n".join(lines))
if __name__ == "__main__":
    main()
