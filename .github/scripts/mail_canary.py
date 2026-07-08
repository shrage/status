#!/usr/bin/env python3
import argparse
import base64
import dataclasses
import email.message
import imaplib
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
from urllib import parse, request


def env_value(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclasses.dataclass
class Target:
    name: str
    address: str
    verify_kind: str
    verify_user: str
    verify_mailbox: str
    verify_host: str | None = None
    verify_port: int | None = None
    verify_password_env: str | None = None
    atavya_scope: str | None = None
    atavya_org_id: str | None = None


@dataclasses.dataclass
class ProbeResult:
    name: str
    address: str
    verify_kind: str
    verify_user: str
    verify_mailbox: str
    subject: str
    status: str
    matches: int
    duration_seconds: float
    error: str | None = None
    atavya_scope: str | None = None
    atavya_org_id: str | None = None
    atavya_thread_id: str | None = None


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
                verify_kind=str(entry.get("verify_kind", "ssh")).strip() or "ssh",
                verify_user=str(entry["verify_user"]).strip(),
                verify_mailbox=str(entry.get("verify_mailbox", "INBOX")).strip() or "INBOX",
                verify_host=str(entry.get("verify_host", "")).strip() or None,
                verify_port=int(entry.get("verify_port", 993)) if entry.get("verify_port") is not None else None,
                verify_password_env=str(entry.get("verify_password_env", "")).strip() or None,
                atavya_scope=str(entry.get("atavya_scope", "")).strip() or None,
                atavya_org_id=str(entry.get("atavya_org_id", "")).strip() or None,
            )
        )
    return targets


def fapi_domain(pk: str) -> str:
    token = pk.removeprefix("pk_live_").removeprefix("pk_test_")
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    return base64.b64decode(padded).decode("utf-8").rstrip("$")


def http_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[Any, list[str]]:
    final_headers = {"User-Agent": env_value("MAIL_CANARY_HTTP_USER_AGENT", "status-mail-canary/1.0")}
    if headers:
        final_headers.update(headers)
    req = request.Request(url, headers=final_headers, data=data, method=method)
    with request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        set_cookies = resp.headers.get_all("Set-Cookie") or []
        return body, set_cookies


_ATAVYA_JWT_CACHE: str | None = None


def atavya_session_jwt() -> str:
    global _ATAVYA_JWT_CACHE
    if _ATAVYA_JWT_CACHE:
        return _ATAVYA_JWT_CACHE

    base_url = env_value("MAIL_CANARY_ATAVYA_BASE", "https://app.atavya.com")
    test_email = env_value("MAIL_CANARY_ATAVYA_TEST_EMAIL", "shrage@smilowitz.com")
    clerk_secret = env_value("MAIL_CANARY_ATAVYA_CLERK_SECRET_KEY")
    clerk_publishable = env_value("MAIL_CANARY_ATAVYA_CLERK_PUBLISHABLE_KEY")
    if not clerk_secret or not clerk_publishable:
        raise RuntimeError("Atavya Clerk secrets are required for Atavya verification")

    fapi = fapi_domain(clerk_publishable)
    bapi = "https://api.clerk.com/v1"
    users, _ = http_json(
        f"{bapi}/users?email_address={parse.quote(test_email)}",
        headers={"Authorization": f"Bearer {clerk_secret}"},
    )
    if not isinstance(users, list) or not users:
        raise RuntimeError(f"No Clerk user for {test_email}")
    user_id = users[0]["id"]

    sign_in_token, _ = http_json(
        f"{bapi}/sign_in_tokens",
        method="POST",
        headers={"Authorization": f"Bearer {clerk_secret}", "Content-Type": "application/json"},
        data=json.dumps({"user_id": user_id, "expire_in_seconds": 900}).encode("utf-8"),
    )
    ticket = sign_in_token.get("token")
    if not ticket:
        raise RuntimeError("Failed to mint sign-in token")

    sign_in, cookies = http_json(
        f"https://{fapi}/v1/client/sign_ins?_clerk_js_version=5.50.0",
        method="POST",
        headers={"Origin": base_url, "Content-Type": "application/x-www-form-urlencoded"},
        data=f"strategy=ticket&ticket={parse.quote(ticket)}".encode("utf-8"),
    )
    sid = (((sign_in or {}).get("response") or {}).get("created_session_id"))
    if not sid:
        raise RuntimeError("Sign-in not completed")
    client_cookie = "; ".join(
        cookie.split(";", 1)[0]
        for cookie in cookies
        if cookie.startswith("__client=") or cookie.startswith("__client_uat=")
    )
    token_payload, _ = http_json(
        f"https://{fapi}/v1/client/sessions/{sid}/tokens?_clerk_js_version=5.50.0",
        method="POST",
        headers={"Origin": base_url, "Cookie": client_cookie},
        data=b"",
    )
    jwt = token_payload.get("jwt")
    if not jwt:
        raise RuntimeError("Failed to mint Atavya session token")
    _ATAVYA_JWT_CACHE = jwt
    return jwt


def find_thread_in_atavya(target: Target, subject: str) -> dict[str, Any] | None:
    base_url = env_value("MAIL_CANARY_ATAVYA_BASE", "https://app.atavya.com")
    jwt = atavya_session_jwt()
    query = {"limit": "100", "sort": "newest", "read": "all"}
    if target.atavya_scope == "organization":
        query["scope"] = "organization"
        query["orgId"] = target.atavya_org_id or ""
    else:
        query["scope"] = "personal"
    url = f"{base_url}/api/inbox/threads?{parse.urlencode(query)}"
    threads, _ = http_json(url, headers={"Authorization": f"Bearer {jwt}"})
    if not isinstance(threads, list):
        raise RuntimeError("Unexpected Atavya inbox response")
    for thread in threads:
        if isinstance(thread, dict) and str(thread.get("subject") or "") == subject:
            return thread
    return None


def poll_atavya_thread_visibility(target: Target, subject: str) -> dict[str, Any] | None:
    wait_seconds = int(env_value("MAIL_CANARY_ATAVYA_WAIT_SECONDS", "120"))
    poll_interval = max(int(env_value("MAIL_CANARY_ATAVYA_POLL_INTERVAL_SECONDS", "10")), 1)
    deadline = time.time() + max(wait_seconds, 0)
    while True:
        thread = find_thread_in_atavya(target, subject)
        if thread:
            return thread
        if time.time() >= deadline:
            return None
        time.sleep(poll_interval)


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
    if target.verify_kind == "imap":
        host = target.verify_host or env_value("MAIL_CANARY_IMAP_HOST")
        port = target.verify_port or int(env_value("MAIL_CANARY_IMAP_PORT", "993"))
        password_env = target.verify_password_env or "MAIL_CANARY_IMAP_PASSWORD"
        password = env_value(password_env)
        if not host:
            raise RuntimeError("IMAP verify host is required")
        if not password:
            raise RuntimeError(f"IMAP verify password env is missing: {password_env}")
        client = imaplib.IMAP4_SSL(host, port, timeout=45)
        try:
            status, _ = client.login(target.verify_user, password)
            if status != "OK":
                raise RuntimeError("IMAP login failed")
            status, _ = client.select(target.verify_mailbox)
            if status != "OK":
                raise RuntimeError(f"IMAP select failed for {target.verify_mailbox}")
            status, data = client.search(None, "SUBJECT", subject)
            if status != "OK":
                raise RuntimeError("IMAP search failed")
            raw_ids = (data[0] if data and data[0] is not None else b"").split()
            for msg_id in raw_ids:
                status, _ = client.store(msg_id.decode("ascii"), "+FLAGS", "\\Deleted")
                if status != "OK":
                    raise RuntimeError("IMAP delete flag update failed")
            if raw_ids:
                status, _ = client.expunge()
                if status != "OK":
                    raise RuntimeError("IMAP expunge failed")
            return len(raw_ids)
        finally:
            try:
                client.logout()
            except Exception:
                pass

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
        atavya_thread_id = None
        if target.atavya_scope:
            thread = poll_atavya_thread_visibility(target, subject)
            if not thread:
                raise RuntimeError("message not visible in Atavya inbox before timeout")
            atavya_thread_id = str(thread.get("threadId") or "") or None
        return ProbeResult(
            name=target.name,
            address=target.address,
            verify_kind=target.verify_kind,
            verify_user=target.verify_user,
            verify_mailbox=target.verify_mailbox,
            subject=subject,
            status="ok",
            matches=matches,
            duration_seconds=round(time.time() - started, 3),
            atavya_scope=target.atavya_scope,
            atavya_org_id=target.atavya_org_id,
            atavya_thread_id=atavya_thread_id,
        )
    except Exception as exc:
        return ProbeResult(
            name=target.name,
            address=target.address,
            verify_kind=target.verify_kind,
            verify_user=target.verify_user,
            verify_mailbox=target.verify_mailbox,
            subject=subject,
            status="error",
            matches=0,
            duration_seconds=round(time.time() - started, 3),
            error=str(exc),
            atavya_scope=target.atavya_scope,
            atavya_org_id=target.atavya_org_id,
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
