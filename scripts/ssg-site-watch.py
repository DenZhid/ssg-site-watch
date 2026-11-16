from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from urllib.parse import urlparse

MARKERS = ("Хеш коммита", "Дата сборки", "Версия набора данных")
MAX_BYTES = 2_000_000
EXCERPT_CHARS = 180
USER_AGENT = "ssg-site-watch/1.0"


class ConfigError(Exception):
    pass


def load_targets(path: Path) -> dict:
    if not path.is_file():
        raise ConfigError(f"targets file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"targets file is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("targets file must be a JSON object")
    targets = raw.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ConfigError("targets must be a non-empty list")
    timeout = raw.get("timeout_seconds", 20)
    if not isinstance(timeout, (int, float)) or not 3 <= float(timeout) <= 60:
        raise ConfigError("timeout_seconds must be a number from 3 to 60")
    markers = raw.get("markers", list(MARKERS))
    if (
        not isinstance(markers, list)
        or not markers
        or not all(isinstance(item, str) and item for item in markers)
    ):
        raise ConfigError("markers must be a non-empty list of strings")
    cleaned = []
    for index, item in enumerate(targets):
        if not isinstance(item, dict):
            raise ConfigError(f"targets[{index}] must be an object")
        name = item.get("name")
        url = item.get("url")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"targets[{index}].name must be a non-empty string")
        if not isinstance(url, str) or not url.strip():
            raise ConfigError(f"targets[{index}].url must be a non-empty string")
        cleaned.append({"name": name.strip(), "url": url.strip()})
    return {
        "targets": cleaned,
        "timeout_seconds": float(timeout),
        "markers": markers,
    }


def empty_rate_limit() -> dict:
    return {"remaining": None, "reset": None, "retry_after": None}


def rate_limit_from(headers) -> dict:
    info = empty_rate_limit()
    if headers is None:
        return info
    remaining = headers.get("X-RateLimit-Remaining")
    reset = headers.get("X-RateLimit-Reset")
    retry_after = headers.get("Retry-After")
    if remaining is not None:
        info["remaining"] = remaining.strip()
    if reset is not None:
        info["reset"] = reset.strip()
    if retry_after is not None:
        info["retry_after"] = retry_after.strip()
    return info


def remaining_is_zero(info: dict) -> bool:
    raw = info.get("remaining")
    if raw is None:
        return False
    try:
        return int(str(raw).strip()) <= 0
    except ValueError:
        return False


def read_limited(stream, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        block = stream.read(min(65536, limit - total))
        if not block:
            return b"".join(chunks), False
        chunks.append(block)
        total += len(block)
    extra = stream.read(1)
    return b"".join(chunks), bool(extra)


def decode_body(payload: bytes, headers) -> str:
    charset = "utf-8"
    if headers is not None:
        declared = headers.get_content_charset()
        if declared:
            charset = declared
    return payload.decode(charset, errors="replace")


def visible_excerpt(text: str) -> str:
    plain = re.sub(r"<[^>]+>", " ", text)
    plain = re.sub(r"\s+", " ", unescape(plain)).strip()
    if len(plain) <= EXCERPT_CHARS:
        return plain
    return plain[: EXCERPT_CHARS - 1] + "…"


def extract_markers(text: str, markers: list[str]) -> dict:
    found: dict[str, str | None] = {}
    for label in markers:
        start = text.find(label)
        if start < 0:
            found[label] = None
            continue
        window = text[start + len(label) : start + len(label) + 500]
        code = re.search(r"<code[^>]*>(.*?)</code>", window, flags=re.IGNORECASE | re.DOTALL)
        if code:
            value = re.sub(r"<[^>]+>", "", code.group(1))
        else:
            value = re.sub(r"<[^>]+>", " ", window)
        value = re.sub(r"\s+", " ", unescape(value)).strip()
        if not value or len(value) > 200:
            found[label] = None
        else:
            found[label] = value
    return found


def classify(http_status: int | None, text: str, truncated: bool, markers: list[str], rate_info: dict) -> str:
    if http_status == 429 or (http_status == 403 and remaining_is_zero(rate_info)):
        return "rate_limited"
    if http_status is None or http_status >= 400:
        return "http_error"
    if not text.strip():
        return "empty_result"
    parsed = extract_markers(text, markers)
    missing = [label for label, value in parsed.items() if value is None and label not in text]
    absent = [label for label in markers if label not in text]
    if truncated and absent:
        return "incomplete"
    if absent or not text.strip():
        return "empty_result"
    if missing and truncated:
        return "incomplete"
    return "ok"


def result_shell(name: str, url: str) -> dict:
    return {
        "name": name,
        "url": url,
        "final_url": None,
        "status": "source_unavailable",
        "http_status": None,
        "elapsed_ms": None,
        "error": None,
        "body_bytes": 0,
        "body_truncated": False,
        "markers": {label: None for label in MARKERS},
        "missing_markers": list(MARKERS),
        "rate_limit": empty_rate_limit(),
        "body_excerpt": None,
    }


def probe_one(name: str, url: str, timeout: float, markers: list[str]) -> dict:
    row = result_shell(name, url)
    row["markers"] = {label: None for label in markers}
    row["missing_markers"] = list(markers)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        row["error"] = "url scheme not allowed"
        return row

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
    opener.max_redirections = 5
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            payload, truncated = read_limited(response, MAX_BYTES)
            headers = response.headers
            final_url = response.geturl()
            http_status = getattr(response, "status", None) or response.getcode()
    except urllib.error.HTTPError as exc:
        payload, truncated = read_limited(exc, MAX_BYTES)
        headers = exc.headers
        final_url = exc.geturl()
        http_status = exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
        row["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        reason = getattr(exc, "reason", exc)
        row["error"] = str(reason)[:300]
        return row

    elapsed_ms = int((time.monotonic() - started) * 1000)
    text = unescape(decode_body(payload, headers))
    rate_info = rate_limit_from(headers)
    status = classify(http_status, text, truncated, markers, rate_info)
    parsed_markers = extract_markers(text, markers) if text.strip() else {label: None for label in markers}
    absent = [label for label in markers if label not in text]

    row.update(
        {
            "final_url": final_url,
            "status": status,
            "http_status": http_status,
            "elapsed_ms": elapsed_ms,
            "error": None,
            "body_bytes": len(payload),
            "body_truncated": truncated,
            "markers": parsed_markers,
            "missing_markers": absent,
            "rate_limit": rate_info,
            "body_excerpt": None if status == "ok" else visible_excerpt(text),
        }
    )
    if status == "rate_limited":
        retry = rate_info.get("retry_after") or rate_info.get("reset")
        row["error"] = f"rate limit exceeded; retry_after={retry}"
    elif status == "http_error":
        row["error"] = f"HTTP {http_status}"
    elif status == "empty_result":
        row["error"] = "empty body" if not text.strip() else "build stamp markers missing"
    elif status == "incomplete":
        row["error"] = "response truncated before all build stamp markers"
    return row


def summarize(rows: list[dict]) -> dict:
    summary = {
        "ok": 0,
        "source_unavailable": 0,
        "empty_result": 0,
        "rate_limited": 0,
        "http_error": 0,
        "incomplete": 0,
    }
    for row in rows:
        status = row.get("status")
        if status in summary:
            summary[status] += 1
    return summary


def emit(document: dict, exit_code: int) -> int:
    json.dump(document, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return exit_code


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Probe ssg-research pages.")
    default_targets = Path(__file__).resolve().parent.parent / "targets.json"
    parser.add_argument("--targets", type=Path, default=default_targets)
    args = parser.parse_args(argv)
    checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        config = load_targets(args.targets)
    except ConfigError as exc:
        return emit(
            {
                "checked_at": checked_at,
                "ok": False,
                "exit_code": 2,
                "error": str(exc),
                "summary": summarize([]),
                "targets": [],
            },
            2,
        )

    rows = [
        probe_one(item["name"], item["url"], config["timeout_seconds"], config["markers"])
        for item in config["targets"]
    ]
    summary = summarize(rows)
    all_unreachable = bool(rows) and summary["source_unavailable"] == len(rows)
    exit_code = 1 if all_unreachable else 0
    return emit(
        {
            "checked_at": checked_at,
            "ok": summary["ok"] == len(rows) and len(rows) > 0,
            "exit_code": exit_code,
            "error": "all targets unreachable" if all_unreachable else None,
            "summary": summary,
            "targets": rows,
        },
        exit_code,
    )


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    sys.exit(main(sys.argv[1:]))