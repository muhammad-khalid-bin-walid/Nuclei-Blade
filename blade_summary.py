import re
import sys
from collections import Counter

def summarize_results(input_files):
    domains = Counter()
    cves = Counter()
    tags = Counter()

    for file in input_files:
        with open(file, 'r') as f:
            for line in f:
                # Extract domain (assuming URL format)
                domain_match = re.search(r'https?://([^/]+)', line)
                if domain_match:
                    domains[domain_match.group(1)] += 1
                
                # Extract CVE (e.g., CVE-2025-XXXX)
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', line)
                if cve_match and "critical" in line.lower():
                    cves[cve_match.group(0)] += 1
                
                # Extract tags (assuming tag format from nuclei output)
                tag_match = re.search(r'tags: ([\w,]+)', line)
                if tag_match:
                    for tag in tag_match.group(1).split(','):
                        tags[tag.strip()] += 1

    # Generate summary
    print("=== Nuclei Blade Summary ===")
    print("Top 5 Vulnerable Domains:")
    for domain, count in domains.most_common(5):
        print(f"  {domain}: {count} hits")
    print("Critical CVE Frequency:")
    for cve, count in cves.most_common():
        print(f"  {cve}: {count} occurrences")
    print("Tag Category Distribution:")
    for tag, count in tags.most_common():
        print(f"  {tag}: {count} instances")

    # Optional Markdown export
    with open("summary_report.md", "w") as f:
        f.write("# Nuclei Blade Summary Report\n")
        f.write("## Top 5 Vulnerable Domains\n")
        for domain, count in domains.most_common(5):
            f.write(f"- {domain}: {count} hits\n")
        f.write("## Critical CVE Frequency\n")
        for cve, count in cves.most_common():
            f.write(f"- {cve}: {count} occurrences\n")
        f.write("## Tag Category Distribution\n")
        for tag, count in tags.most_common():
            f.write(f"- {tag}: {count} instances\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python blade_summary.py <input_files>")
        sys.exit(1)
    summarize_results(sys.argv[1:])
