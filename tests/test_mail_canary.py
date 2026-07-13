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
        raw = '[{"name":"direct","address":"a@example.com","verify_kind":"imap","verify_host":"imap.example.com","verify_port":993,"verify_password_env":"SECRET_ENV","verify_user":"u@example.com","verify_mailbox":"INBOX"}]'
        with mock.patch.dict(mail_canary.os.environ, {"MAIL_CANARY_TARGETS_JSON": raw}, clear=False):
            targets = mail_canary.load_targets()

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].name, "direct")
        self.assertEqual(targets[0].address, "a@example.com")
        self.assertEqual(targets[0].verify_kind, "imap")
        self.assertEqual(targets[0].verify_host, "imap.example.com")

    def test_run_probe_checks_atavya_visibility_when_configured(self):
        target = mail_canary.Target(
            name="personal",
            address="shrage@oneteamforward.com",
            verify_kind="imap",
            verify_user="shrage@oneteamforward.com",
            verify_mailbox="INBOX",
            atavya_scope="personal",
        )

        with mock.patch.object(mail_canary, "send_probe"), mock.patch.object(
            mail_canary, "poll_mailbox", return_value=1
        ), mock.patch.object(
            mail_canary, "poll_atavya_thread_visibility", return_value={"threadId": "thread-123"}
        ) as atavya_probe:
            result = mail_canary.run_probe(target)

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.atavya_thread_id, "thread-123")
        atavya_probe.assert_called_once_with(target, result.subject)

    def test_search_mailbox_supports_imap_verifier(self):
        imap_instances = []

        class FakeImap:
            def __init__(self, *_args, **_kwargs):
                self.deleted = []
                self.expunge_called = False
                imap_instances.append(self)

            def login(self, *_args, **_kwargs):
                return ("OK", [b"logged in"])

            def select(self, *_args, **_kwargs):
                return ("OK", [b"1"])

            def search(self, *_args, **_kwargs):
                return ("OK", [b"1 2"])

            def store(self, msg_id, *_args, **_kwargs):
                self.deleted.append(msg_id)
                return ("OK", [b"stored"])

            def expunge(self):
                self.expunge_called = True
                return ("OK", [b"expunged"])

            def logout(self):
                return None

        target = mail_canary.Target(
            name="imap-target",
            address="shrage@oneteamforward.com",
            verify_kind="imap",
            verify_user="shrage@oneteamforward.com",
            verify_mailbox="INBOX",
            verify_host="mail.oneteamforward.com",
            verify_port=993,
            verify_password_env="MAIL_CANARY_ONETEAM_IMAP_PASSWORD",
        )

        with mock.patch.object(mail_canary.imaplib, "IMAP4_SSL", side_effect=FakeImap), mock.patch.dict(
            mail_canary.os.environ,
            {"MAIL_CANARY_ONETEAM_IMAP_PASSWORD": "secret"},
            clear=False,
        ):
            matches = mail_canary.search_mailbox(target, "probe-subject")

        self.assertEqual(matches, 2)
        self.assertEqual(imap_instances[0].deleted, ["1", "2"])
        self.assertTrue(imap_instances[0].expunge_called)

    def test_cleanup_recent_canaries_deduplicates_imap_mailboxes(self):
        target = mail_canary.Target(
            name="imap-target",
            address="shrage@oneteamforward.com",
            verify_kind="imap",
            verify_user="shrage@oneteamforward.com",
            verify_mailbox="INBOX",
            verify_host="mail.oneteamforward.com",
            verify_port=993,
            verify_password_env="MAIL_CANARY_ONETEAM_IMAP_PASSWORD",
        )

        with mock.patch.object(mail_canary, "cleanup_imap_subject", return_value=3) as cleanup:
            count = mail_canary.cleanup_recent_canaries([target, target])

        self.assertEqual(count, 3)
        cleanup.assert_called_once_with(target, "status-mail-canary/")

    def test_count_doveadm_matches_counts_non_empty_lines(self):
        output = "abc 1\n\nabc 2\n"
        self.assertEqual(mail_canary.count_doveadm_matches(output), 2)

    def test_render_issue_body_includes_target_details(self):
        results = [
            mail_canary.ProbeResult(
                name="direct",
                address="shrage@oneteamforward.com",
                verify_kind="imap",
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
