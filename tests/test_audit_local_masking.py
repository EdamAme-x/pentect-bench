"""The detector audit must preserve fixture bytes while adding read framing."""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_local_masking import wrapped


class AuditLocalMaskingTests(unittest.TestCase):
    def test_numbered_wrapper_keeps_each_line_and_exact_footer(self) -> None:
        output = wrapped("STATUS=ready\nAPI_TOKEN=synthetic\n")
        self.assertIn("1: STATUS=ready\n2: API_TOKEN=synthetic\n", output)
        self.assertIn("(End of file - total 2 lines)\n</content>", output)
        self.assertEqual(output.count("API_TOKEN=synthetic"), 1)


if __name__ == "__main__":
    unittest.main()
