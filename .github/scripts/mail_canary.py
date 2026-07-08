#!/usr/bin/env python3
import argparse
import dataclasses
import email.message
import json
import os
import shlex
import smtplib
import ssl
import subprocess
import sys
import time
import uuid
from typing import Any


def env_value(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclasses.dataclass
class Target:
    name: str
    address: str
    verify_user: str
    verify_mailbox: str


@dataclasses.dataclass
class ProbeResult:
    name: str
    address: str
    verify_user: str
    verify_mailbox: str
    subject: str
    status: str
    matches: int
    duration_seconds: float
    error: str | None = None


def load_targets() -> list[Target]:
    raw = env_value("MAIL_CANARY_TARGETS_JSON")
    if not raw:
        raise RuntimeError("MAIL_CANARY_TARGETS_JSON is required")
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or not parsed:
        raise RuntimeError("MAIL_CANARY_TARGETS_JSON must be a non-empty JSON array")
    targets: list[Target] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise RuntimeError("MAIL_CANARY_TARGETS_JSON entries must be objects")
        targets.append(
            Target(
                name=str(entry["name"]).strip(),
                address=str(entry["address"]).strip(),
                verify_user=str(entry["verify_user"]).strip(),
                verify_mailbox=str(entry.get("verify_mailbox", "INBOX")).strip() or "INBOX",
            )
        )
    return targets


def smtp_settings() -> dict[str, str]:
    settings = {
        "host": env_value("MAIL_CANARY_SMTP_HOST", "mail.smtp2go.com"),
        "port": env_value("MAIL_CANARY_SMTP_PORT", "2525"),
        "username": env_value("MAIL_CANARY_SMTP_USERNAME"),
        "password": env_value("MAIL_CANARY_SMTP_PASSWORD"),
        "from": env_value("MAIL_CANARY_FROM"),
        "use_starttls": env_value("MAIL_CANARY_SMTP_STARTTLS", "true").lower(),
    }
    if not all(settings.values()):
        missing = [key for key, value in settings.items() if not value]
        raise RuntimeError(f"Missing SMTP settings: {', '.join(missing)}")
    return settings


def build_subject(target: Target) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    token = uuid.uuid4().hex[:8]
    return f"status-mail-canary/{target.name}/{stamp}/{token}"


def send_probe(target: Target, subject: str) -> None:
    settings = smtp_settings()
    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings["from"]
    msg["To"] = target.address
    msg.set_content(f"External mail canary for {target.name}\nsubject={subject}\n")
    with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=30) as client:
        client.ehlo()
        if settings["use_starttls"] in {"1", "true", "yes", "on"}:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        client.login(settings["username"], settings["password"])
        client.send_message(msg)


def count_doveadm_matches(output: str) -> int:
    return len([line for line in output.splitlines() if line.strip()])


def search_mailbox(target: Target, subject: str) -> int:
    ssh_host = env_value("MAIL_CANARY_SSH_HOST")
    ssh_user = env_value("MAIL_CANARY_SSH_USER")
    ssh_timeout = int(env_value("MAIL_CANARY_SSH_TIMEOUT_SECONDS", "180"))
    if not ssh_host or not ssh_user:
        raise RuntimeError("MAIL_CANARY_SSH_HOST and MAIL_CANARY_SSH_USER are required")
    remote_cmd = "sudo doveadm search -u {user} mailbox {mailbox} subject {subject}".format(
        user=shlex.quote(target.verify_user),
        mailbox=shlex.quote(target.verify_mailbox),
        subject=shlex.quote(subject),
    )
    proc = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            f"{ssh_user}@{ssh_host}",
            remote_cmd,
        ],
        capture_output=True,
        text=True,
        timeout=ssh_timeout,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "ssh mailbox search failed").strip()
        raise RuntimeError(detail)
    return count_doveadm_matches(proc.stdout or "")


def poll_mailbox(target: Target, subject: str) -> int:
    wait_seconds = int(env_value("MAIL_CANARY_WAIT_SECONDS", "180"))
    poll_interval = max(int(env_value("MAIL_CANARY_POLL_INTERVAL_SECONDS", "10")), 1)
    deadline = time.time() + max(wait_seconds, 0)
    while True:
        matches = search_mailbox(target, subject)
        if matches > 0:
            return matches
        if time.time() >= deadline:
            return 0
        time.sleep(poll_interval)


def run_probe(target: Target) -> ProbeResult:
    subject = build_subject(target)
    started = time.time()
    try:
        send_probe(target, subject)
        matches = poll_mailbox(target, subject)
        if matches <= 0:
            raise RuntimeError("message not observed in verification mailbox before timeout")
        return ProbeResult(
            name=target.name,
            address=target.address,
            verify_user=target.verify_user,
            verify_mailbox=target.verify_mailbox,
            subject=subject,
            status="ok",
            matches=matches,
            duration_seconds=round(time.time() - started, 3),
        )
    except Exception as exc:
        return ProbeResult(
            name=target.name,
            address=target.address,
            verify_user=target.verify_user,
            verify_mailbox=target.verify_mailbox,
            subject=subject,
            status="error",
            matches=0,
            duration_seconds=round(time.time() - started, 3),
            error=str(exc),
        )


def render_issue_body(results: list[ProbeResult]) -> str:
    failing = [result for result in results if result.status != "ok"]
    status_line = "failing" if failing else "healthy"
    lines = [
        "External email canary summary.",
        "",
        f"Overall: {status_line}",
        "",
        "| Target | Delivery | Verify mailbox | Subject | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in results:
        detail = f"matches={result.matches}, {result.duration_seconds}s"
        if result.error:
            detail = f"error: {result.error}"
        lines.append(
            f"| {result.name} | {result.status} | `{result.verify_user}` / `{result.verify_mailbox}` | `{result.subject}` | {detail} |"
        )
    run_id = env_value("GITHUB_RUN_ID")
    repository = env_value("GITHUB_REPOSITORY")
    server_url = env_value("GITHUB_SERVER_URL", "https://github.com")
    if run_id and repository:
        lines.extend(["", f"Workflow run: {server_url}/{repository}/actions/runs/{run_id}"])
    return "\n".join(lines)


def command_probe(_args: argparse.Namespace) -> int:
    results = [run_probe(target) for target in load_targets()]
    payload: dict[str, Any] = {
        "ok": all(result.status == "ok" for result in results),
        "results": [dataclasses.asdict(result) for result in results],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


def command_issue_body(args: argparse.Namespace) -> int:
    with open(args.results_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    results = [ProbeResult(**entry) for entry in payload.get("results", [])]
    sys.stdout.write(render_issue_body(results) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe_parser = subparsers.add_parser("probe")
    probe_parser.set_defaults(func=command_probe)

    issue_parser = subparsers.add_parser("issue-body")
    issue_parser.add_argument("results_path")
    issue_parser.set_defaults(func=command_issue_body)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
