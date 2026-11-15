import tempfile
from pathlib import Path
import unittest

from SecurityApp.GraderCode import ReportAnalyzer, grade_counts


class GraderTests(unittest.TestCase):
    def test_hit_percentage_counts_sites_not_repeated_text_occurrences(self):
        grade = grade_counts({'total_tools_searched': 10, 'tools_with_matches': 2, 'total_matches': 37})
        self.assertEqual(grade['percent_matches'], 20)
        self.assertEqual(grade['total_sites'], 10)
        self.assertEqual(grade['total_matches'], 37)
        self.assertEqual(grade['sites_with_hits'], 2)

    def test_no_finished_sites_and_rounding(self):
        self.assertEqual(grade_counts({'total_tools_searched': 0, 'tools_with_matches': 0, 'total_matches': 0})['percent_matches'], 0)
        self.assertEqual(grade_counts({'total_tools_searched': 3, 'tools_with_matches': 1, 'total_matches': 1})['percent_matches'], 33.33)

    def test_report_file_and_live_counts_use_the_same_grader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.txt'
            path.write_text('Total tools searched: 8\nTools with matches: 3\nTotal matches: 12\n')
            grade = ReportAnalyzer.grade_report(path)
        self.assertEqual(grade['percent_matches'], 37.5)
        self.assertEqual(grade['total_sites'], 8)
