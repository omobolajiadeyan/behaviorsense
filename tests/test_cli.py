import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
