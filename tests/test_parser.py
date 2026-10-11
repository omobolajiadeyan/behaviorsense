import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from parser import LogFileError, parse_access_log, parse_csv_log, parse_file, parse_json_log


class ParserTests(unittest.TestCase):
    def test_csv_events_are_normalized(self):
        content = "\n".join([
            "timestamp,user,ip,event_type,endpoint,status,bytes",
            "2024-01-10T08:00:01,alice,192.0.2.10,login,/auth,success,512",
        ])

        events = parse_csv_log(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user"], "alice")
        self.assertEqual(events[0]["status"], "success")
        self.assertEqual(events[0]["bytes"], 512)

    def test_access_log_uses_ip_when_user_missing(self):
        content = '203.0.113.10 - - [10/Jan/2024:08:00:01 +0000] "GET /admin HTTP/1.1" 403 128'

        events = parse_access_log(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user"], "203.0.113.10")
        self.assertEqual(events[0]["status"], "failed")
        self.assertEqual(events[0]["endpoint"], "/admin")

    def test_json_lines_are_normalized(self):
        content = '{"timestamp":"2024-01-10T08:00:01","user":"bob","ip":"192.0.2.20","status_code":401,"bytes":"64"}'

        events = parse_json_log(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")
        self.assertEqual(events[0]["bytes"], 64)

    def test_parse_file_rejects_empty_and_unsupported_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_file = Path(tmpdir) / "empty.json"
            empty_file.write_text(" \n")
            unsupported_file = Path(tmpdir) / "events.log"
            unsupported_file.write_text("this is not a supported log format")
            unsupported_json = Path(tmpdir) / "unsupported.json"
            unsupported_json.write_text('{"unexpected":"data"}')

            for filepath in (empty_file, unsupported_file, unsupported_json):
                with self.subTest(filepath=filepath), self.assertRaises(LogFileError):
                    parse_file(str(filepath))

    def test_parse_file_surfaces_read_errors(self):
        with patch.object(Path, "read_text", side_effect=PermissionError("access denied")):
            with self.assertRaisesRegex(LogFileError, "Could not read"):
                parse_file("unreadable.csv")


if __name__ == "__main__":
    unittest.main()
