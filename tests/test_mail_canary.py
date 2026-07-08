import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / ".github" / "scripts" / "mail_canary.py"
SPEC = importlib.util.spec_from_file_location("mail_canary", MODULE_PATH)
mail_canary = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mail_canary)


class MailCanaryTests(unittest.TestCase):
    def test_load_targets_from_json(self):
        raw = '[{"name":"direct","address":"a@example.com","verify_user":"u@example.com","verify_mailbox":"INBOX"}]'
        with mock.patch.dict(mail_canary.os.environ, {"MAIL_CANARY_TARGETS_JSON": raw}, clear=False):
            targets = mail_canary.load_targets()

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].name, "direct")
        self.assertEqual(targets[0].address, "a@example.com")

    def test_count_doveadm_matches_counts_non_empty_lines(self):
        output = "abc 1\n\nabc 2\n"
        self.assertEqual(mail_canary.count_doveadm_matches(output), 2)

    def test_render_issue_body_includes_target_details(self):
        results = [
            mail_canary.ProbeResult(
                name="direct",
                address="shrage@oneteamforward.com",
                verify_user="shrage@oneteamforward.com",
                verify_mailbox="INBOX",
                subject="status-mail-canary/direct/x",
                status="error",
                matches=0,
                duration_seconds=30.5,
                error="timeout",
            )
        ]
        with mock.patch.dict(
            mail_canary.os.environ,
            {
                "GITHUB_RUN_ID": "12345",
                "GITHUB_REPOSITORY": "shrage/status",
                "GITHUB_SERVER_URL": "https://github.com",
            },
            clear=False,
        ):
            body = mail_canary.render_issue_body(results)

        self.assertIn("Overall: failing", body)
        self.assertIn("direct", body)
        self.assertIn("timeout", body)
        self.assertIn("actions/runs/12345", body)


if __name__ == "__main__":
    unittest.main()
