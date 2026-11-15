from pathlib import Path


def extract_report_counts(file_path: str | Path) -> dict[str, int]:
    fields = {
        "Total tools searched": "total_tools_searched",
        "Tools with matches": "tools_with_matches",
        "Total matches": "total_matches",
    }
    counts = {}

    with open(file_path, encoding="utf-8-sig") as report:
        for line in report:
            label, _, value = line.partition(":")
            key = fields.get(label.strip())
            if key is not None:
                counts[key] = int(value.strip())
                if len(counts) == len(fields):
                    return counts

    missing = [label for label, key in fields.items() if key not in counts]
    raise ValueError(f"Missing report fields: {', '.join(missing)}")

class ReportAnalyzer:
    @staticmethod
    def read_counts(file_path: str | Path) -> dict[str, int]:
        return extract_report_counts(file_path)  # Use the function from above.


report_path = ReportGenerator().create_report("report.txt")
counts = ReportAnalyzer.read_counts(report_path)

total_tools_searched = counts["total_tools_searched"]
tools_with_matches = counts["tools_with_matches"]
total_matches = counts["total_matches"]

percent_matches = 0
if (tools_with_matches > 0):
    percent_matches = tools_with_mathces / total_tools_searched
