"""Grade scanner counts directly, or read the same counts from a text report."""
from pathlib import Path
from typing import Mapping


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


def grade_counts(counts: Mapping[str, int]) -> dict:
    total_tools_searched = counts["total_tools_searched"]
    tools_with_matches = counts["tools_with_matches"]
    total_matches = counts["total_matches"]
    if not 0 <= tools_with_matches <= total_tools_searched or total_matches < 0:
        raise ValueError("Report counts must be nonnegative, with matched sites no greater than searched sites.")

    percent_matches = 0.0
    if total_tools_searched > 0:
        percent_matches = (tools_with_matches / total_tools_searched) * 100

    return {
        "percent_matches": round(percent_matches, 2),
        "total_sites": total_tools_searched,
        "sites_with_hits": tools_with_matches,
        "total_matches": total_matches,
    }


class ReportAnalyzer:
    @staticmethod
    def read_counts(file_path: str | Path) -> dict[str, int]:
        return extract_report_counts(file_path)  # Use the function from above.

    @staticmethod
    def grade_report(file_path: str | Path) -> dict:
        return grade_counts(extract_report_counts(file_path))
