import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from parser import LogFileError


class CliTests(unittest.TestCase):
    def test_json_export_contains_ranked_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, "detector.py", "sample_data/", "--output", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            report = json.loads(output.read_text())
            self.assertEqual(report["total_events"], 23)
            self.assertEqual(report["total_entities"], 5)
            self.assertEqual(report["results"][0]["entity"], "mallory")
            self.assertEqual(report["results"][0]["risk_level"], "CRITICAL")

    def test_empty_and_unsupported_input_fail_visibly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_file = Path(tmpdir) / "empty.csv"
            empty_file.write_text("")
            unsupported_file = Path(tmpdir) / "unsupported.log"
            unsupported_file.write_text("not a supported log format")

            for filepath in (empty_file, unsupported_file):
                with self.subTest(filepath=filepath):
                    result = subprocess.run(
                        [sys.executable, "detector.py", str(filepath)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(result.returncode, 1)
                    self.assertIn("Error:", result.stdout)
                    self.assertEqual(result.stderr, "")

    def test_directory_without_log_files_fails_visibly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [sys.executable, "detector.py", tmpdir],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("No supported log files", result.stdout)
            self.assertEqual(result.stderr, "")

    def test_unreadable_input_fails_visibly(self):
        import detector

        output = io.StringIO()
        with (
            patch("sys.argv", ["detector.py", "unreadable.log"]),
            patch("detector.os.path.exists", return_value=True),
            patch("detector.collect_log_files", return_value=["unreadable.log"]),
            patch("detector.parse_file", side_effect=LogFileError("Could not read log")),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            detector.main()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Error: Could not read log", output.getvalue())


if __name__ == "__main__":
    unittest.main()
