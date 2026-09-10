from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from triagebloom.config import get_profile, load_config


class ConfigIsolationTests(unittest.TestCase):
    def test_mutating_one_profile_copy_does_not_modify_future_copies(self) -> None:
        first = get_profile("balanced")
        first.suppressed_rule_ids.add("TB-CORR-001")
        first.allow_users.add("user@example.com")

        second = get_profile("balanced")
        self.assertNotIn("TB-CORR-001", second.suppressed_rule_ids)
        self.assertNotIn("user@example.com", second.allow_users)

    def test_load_config_does_not_mutate_base_config_sets(self) -> None:
        base = get_profile("balanced")
        base.allow_users.add("existing@example.com")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"suppressed_rule_ids": ["TB-CORR-001"]}), encoding="utf-8")
            loaded = load_config(path, base)

        self.assertIn("existing@example.com", loaded.allow_users)
        self.assertIn("TB-CORR-001", loaded.suppressed_rule_ids)
        self.assertNotIn("TB-CORR-001", base.suppressed_rule_ids)


if __name__ == "__main__":
    unittest.main()
