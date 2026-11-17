#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import email.header
import email.utils
import fcntl
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = "https://cp.hornetsecurity.com/api/v0"
APP_ID = "8071586897"
CLASSIFICATIONS = [1, 2, 3, 5, 8, 11, 12]
LIMIT = 5000
POLL_INTERVAL_SECONDS = 60
RETRY_DELAYS_SECONDS = (1, 2, 4)
MAX_CHECKPOINT_IDS = 50000
INITIAL_LOOKBACK_HOURS = 2
VERSION_FILE = Path(__file__).with_name("VERSION")
__version__ = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.is_file() else "0.1.0"


def log(message: str) -> None:
    print(f"hornetsecurity-collector: {message}", file=sys.stderr, flush=True)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def format_api_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def retry_delay(attempt: int, retry_after: str | None = None) -> float:
    if retry_after:
        try:
            return min(30.0, max(0.0, float(retry_after)))
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(retry_after)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=dt.timezone.utc)
                return min(30.0, max(0.0, (parsed - utc_now()).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
    return RETRY_DELAYS_SECONDS[attempt] + random.uniform(0, 0.25)


def request_json(method: str, path: str, api_key: str,
                 params: dict[str, Any] | None = None,
                 payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    url = f"{BASE_URL}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "App-ID": APP_ID,
            "Authorization": f"Token {api_key}",
            "User-Agent": f"Hornetsecurity-by-Proofpoint-365-Total-Protection-for-Wazuh/{__version__}",
        },
    )
    for attempt in range(len(RETRY_DELAYS_SECONDS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
                try:
                    return response.status, json.loads(raw) if raw else None
                except json.JSONDecodeError as exc:
                    raise RuntimeError(f"API {method} {path} returned invalid JSON") from exc
        except urllib.error.HTTPError as exc:
            # Never include response bodies or request headers: either can contain tenant data.
            if exc.code == 429 or 500 <= exc.code <= 599:
                if attempt < len(RETRY_DELAYS_SECONDS):
                    delay = retry_delay(attempt, exc.headers.get("Retry-After"))
                    log(f"API {method} {path}: HTTP {exc.code}; retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{len(RETRY_DELAYS_SECONDS)})")
                    time.sleep(delay)
                    continue
            raise RuntimeError(f"API {method} {path} returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if attempt < len(RETRY_DELAYS_SECONDS):
                delay = retry_delay(attempt)
                reason = getattr(exc, "reason", exc)
                log(f"API {method} {path} network failure ({type(reason).__name__}); "
                    f"retrying in {delay:.1f}s (attempt {attempt + 1}/{len(RETRY_DELAYS_SECONDS)})")
                time.sleep(delay)
                continue
            raise RuntimeError(f"API {method} {path} failed after retries ({type(exc).__name__})") from exc
    raise RuntimeError(f"API {method} {path} failed after retries")


def resolve_object_id(scope: str, api_key: str) -> int:
    if scope.isdigit():
        return int(scope)
    _, result = request_json("GET", "/object/", api_key, params={"name": scope})
    object_id = result.get("object_id") if isinstance(result, dict) else None
    if not object_id:
        raise RuntimeError(f"Could not resolve Hornetsecurity scope {scope!r} to an object ID")
    try:
        return int(object_id)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"Hornetsecurity returned an invalid object ID for scope {scope!r}") from exc


def text_value(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return default


def nested_text(value: Any, default: str) -> str:
    if isinstance(value, dict):
        return text_value(value.get("text"), default)
    return default


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def encryption_label(value: Any) -> str:
    """Return a readable legend value while preserving the raw API value."""
    raw = text_value(value).strip()
    normalized = raw.casefold()
    if normalized in {"", "none", "no encryption"}:
        return "No encryption"
    if normalized in {"not available", "n/a", "not_available"}:
        return "Not available"
    return raw


def decode_subject(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        parts = email.header.decode_header(value)
        return "".join(
            part.decode(encoding or "utf-8", errors="replace") if isinstance(part, bytes) else part
            for part, encoding in parts
        )
    except (LookupError, UnicodeError, TypeError):
        return value


def event_from_email(object_id: int, email_data: dict[str, Any]) -> dict[str, Any]:
    inbound = email_data.get("direction") == 1
    status = nested_text(email_data.get("status"), "None")
    if status == "No status":
        status = "None"
    classification = nested_text(email_data.get("classification"), "Unknown")
    size = email_data.get("size") if isinstance(email_data.get("size"), dict) else {}
    size_text = "Unknown"
    if size.get("value") is not None and size.get("unit"):
        try:
            size_text = f"{round(float(size['value']), 2)} {size['unit']}"
        except (ValueError, TypeError):
            size_text = f"{size['value']} {size['unit']}"
    actions = email_data.get("last_remediation_actions")
    if not isinstance(actions, list):
        actions = []
    attachments = email_data.get("attachments")

    if not isinstance(attachments, list):
        attachments = []
    date_value = text_value(email_data.get("date"))
    if date_value:
        date_value = date_value.replace("T", " ").removesuffix("Z")
    has_url_rewritten = bool_value(email_data.get("has_url_rewritten", False))
    is_archived = bool_value(email_data.get("is_archived", False))
    remediation_action = text_value(actions[0]).capitalize() if actions else "No action"
    status_label = "No status" if status.strip().casefold() in {"", "none", "no status"} else status
    remediation_action_label = (
        "No action taken"
        if remediation_action.strip().casefold() in {"", "none", "no action"}
        else remediation_action
    )
    incoming_encryption = nested_text(email_data.get("crypt_type_in"), "None")
    outgoing_encryption = nested_text(email_data.get("crypt_type_out"), "None")
    event = {
        "integration": "hornetsecurity_by_proofpoint_365_total_protection_wazuh",
        "object_id": object_id,
        "msg_id": text_value(email_data.get("msg_id")),
        "message_id": text_value(email_data.get("message_id")),
        "date": date_value,
        "direction": "Inbound" if inbound else "Outbound",
        "from": text_value(email_data.get("comm_partner")) if inbound else text_value(email_data.get("owner")),
        "to": text_value(email_data.get("owner")) if inbound else text_value(email_data.get("comm_partner")),
        "subject": decode_subject(email_data.get("subject", "")),
        "remediation_action": remediation_action,
        "remediation_action_label": remediation_action_label,
        "attachments": "yes" if attachments else "no",
        "attachmentsList": json.dumps(attachments, ensure_ascii=False, separators=(",", ":")),
        "classification": classification.capitalize(),
        "reason": text_value(email_data.get("reason")),
        "reason_intern": text_value(email_data.get("reason_intern")),
        "gateway": text_value(email_data.get("gateway")),
        "source_hostname": text_value(email_data.get("source_hostname")),
        "source_ip": text_value(email_data.get("source_ip")),
        "destination_hostname": text_value(email_data.get("destination_hostname")),
        "destination_ip": text_value(email_data.get("destination_ip")),
        "incoming_encryption": incoming_encryption,
        "incoming_encryption_label": encryption_label(incoming_encryption),
        "outgoing_encryption": outgoing_encryption,
        "outgoing_encryption_label": encryption_label(outgoing_encryption),
        "private": bool_value(email_data.get("private", False)),
        "smtp_dialog": text_value(email_data.get("smtp_dialog")),
        "smtp_status": text_value(email_data.get("smtp_status")),
        "smtp_status_code": text_value(email_data.get("smtp_status_code")),
        "has_url_rewritten": has_url_rewritten,
        "url_rewritten_label": "Rewritten" if has_url_rewritten else "Not rewritten",
        "status": status.capitalize(),
        "status_label": status_label,
        "is_archived": is_archived,
        "archived_label": "Archived" if is_archived else "Not archived",
        "size": size_text,
    }
    return event


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_checkpoint(path: Path, lookback_hours: int, scope: str,
                    direction: str) -> tuple[dt.datetime, set[str], dt.datetime | None]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("scope") != scope or state.get("direction") != direction:
            log(f"Checkpoint {path.name}: scope or direction changed; starting a fresh checkpoint")
            return utc_now() - dt.timedelta(hours=lookback_hours), set(), None
        timestamp = parse_time(state["last_time"])
        raw_ids = state.get("last_ids", [])
        ids = {str(item) for item in raw_ids if item is not None} if isinstance(raw_ids, list) else set()
        last_run_value = state.get("last_run")
        last_run = parse_time(last_run_value) if last_run_value else None
        return timestamp, ids, last_run
    except FileNotFoundError:
        return utc_now() - dt.timedelta(hours=lookback_hours), set(), None
    except (OSError, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        log(f"Ignoring invalid checkpoint {path.name} ({type(exc).__name__})")
        return utc_now() - dt.timedelta(hours=lookback_hours), set(), None


def save_checkpoint(path: Path, last_time: dt.datetime, ids: set[str], last_run: dt.datetime,
                    scope: str, direction: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = {
        "scope": scope,
        "direction": direction,
        "last_time": format_api_time(last_time),
        "last_run": format_api_time(last_run),
        "last_ids": sorted(ids)[-MAX_CHECKPOINT_IDS:],
    }
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, separators=(",", ":")))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def output_directory() -> Path:
    configured_file = os.environ.get("HORNETSECURITY_OUTPUT_FILE")
    if configured_file:
        return Path(configured_file).parent
    return Path(os.environ.get("HORNETSECURITY_OUTPUT_DIR", "/var/ossec/logs/hornetsecurity"))


def cleanup_old_logs(directory: Path, retention_days: int) -> None:
    cutoff = utc_now().date() - dt.timedelta(days=retention_days)
    for candidate in directory.glob("events-????????.json"):
        try:
            file_date = dt.datetime.strptime(candidate.stem.removeprefix("events-"), "%Y%m%d").date()
            if file_date < cutoff:
                candidate.unlink(missing_ok=True)
        except (OSError, ValueError):
            log(f"Could not clean old event file {candidate.name}")


def emit_event(event: dict[str, Any]) -> None:
    serialized = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    directory = output_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    if os.environ.get("HORNETSECURITY_OUTPUT_FILE"):
        output_file = Path(os.environ["HORNETSECURITY_OUTPUT_FILE"])
    else:
        output_file = directory / f"events-{utc_now():%Y%m%d}.json"
    fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(serialized + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(serialized, flush=True)


def collect_input(input_config: dict[str, Any], api_key: str) -> int:
    scope = str(input_config.get("scope", "")).strip()
    direction = str(input_config.get("direction", "inbound_outbound")).lower()
    input_name = str(input_config.get("name") or scope).strip()
    if not input_name or not scope:
        raise RuntimeError("An enabled input must define non-empty 'name' and 'scope' values")
    if direction not in {"inbound_outbound", "inbound", "outbound"}:
        raise RuntimeError(f"Input {input_name!r}: direction must be inbound_outbound, inbound, or outbound")
    checkpoint_dir = Path(os.environ.get("HORNETSECURITY_CHECKPOINT_DIR", "/var/ossec/queue/hornetsecurity"))
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in input_name)
    checkpoint = checkpoint_dir / f"{safe_name}.json"
    last_seen, previous_ids, last_run = load_checkpoint(
        checkpoint, INITIAL_LOOKBACK_HOURS, scope, direction
    )
    run_started = utc_now()
    if last_run and 0 <= (run_started - last_run).total_seconds() < POLL_INTERVAL_SECONDS:
        log(f"Input {input_name!r}: interval not elapsed; next poll due in "
            f"{max(0, POLL_INTERVAL_SECONDS - int((run_started - last_run).total_seconds()))}s")
        return 0

    object_id = resolve_object_id(scope, api_key)
    date_from = format_api_time(last_seen - dt.timedelta(seconds=POLL_INTERVAL_SECONDS + 300))
    date_to_dt = utc_now()
    date_to = format_api_time(date_to_dt)
    emitted_ids: set[str] = set()
    overlap_ids: set[str] = set()
    latest_time = last_seen
    overlap_start = date_to_dt - dt.timedelta(seconds=POLL_INTERVAL_SECONDS + 300)
    offset = 0
    query: dict[str, Any] = {
        "classification": CLASSIFICATIONS,
        "date_from": date_from,
        "date_to": date_to,
        "cluster_id": 0,
        "offset": offset,
        "limit": LIMIT,
    }
    if direction == "inbound":
        query["direction"] = [1]
    elif direction == "outbound":
        query["direction"] = [2]

    while True:
        query["offset"] = offset
        _, result = request_json("POST", f"/emails/_search/?object_id={object_id}", api_key, payload=query)
        if not isinstance(result, dict):
            raise RuntimeError("Hornetsecurity email search returned an unexpected response")
        emails = result.get("emails") or []
        if not isinstance(emails, list):
            raise RuntimeError("Hornetsecurity email search returned an invalid emails list")
        try:
            total = int(result.get("num_found_items") or 0)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Hornetsecurity email search returned an invalid result count") from exc
        log(f"Input {input_name!r}: API window {date_from} to {date_to}, direction={direction}, "
            f"num_found_items={total}, returned={len(emails)}")
        if not emails:
            break
        for item in emails:
            if not isinstance(item, dict) or item.get("msg_id") is None:
                log(f"Input {input_name!r}: skipping malformed email record without msg_id")
                continue
            msg_id = str(item["msg_id"])
            raw_date = item.get("date")
            if isinstance(raw_date, str) and raw_date:
                try:
                    parsed_date = parse_time(raw_date)
                    latest_time = max(latest_time, parsed_date)
                    if parsed_date >= overlap_start:
                        overlap_ids.add(msg_id)
                except (ValueError, TypeError):
                    overlap_ids.add(msg_id)
            else:
                overlap_ids.add(msg_id)
            if msg_id in previous_ids or msg_id in emitted_ids:
                continue
            try:
                event = event_from_email(object_id, item)
                event["input_name"] = input_name
                event["scope"] = scope
                emit_event(event)
            except (TypeError, ValueError, OSError) as exc:
                raise RuntimeError(f"Input {input_name!r}: could not write event {msg_id} ({type(exc).__name__})") from exc
            emitted_ids.add(msg_id)
        offset += LIMIT
        if offset >= total or len(emails) < LIMIT:
            break

    # The API query intentionally re-reads the six-minute overlap on the next
    # poll, so only IDs from this completed window need to be retained.
    save_checkpoint(checkpoint, max(latest_time, date_to_dt), overlap_ids,
                    date_to_dt, scope, direction)
    log(f"Input {input_name!r}: collected {len(emitted_ids)} new emails for object_id={object_id}")
    return len(emitted_ids)


def validate_inputs(config_path: Path) -> list[dict[str, Any]]:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read input configuration {config_path} ({type(exc).__name__})") from exc
    inputs = config.get("inputs") if isinstance(config, dict) else None
    if not isinstance(inputs, list) or not inputs:
        raise RuntimeError(f"{config_path} must define a non-empty 'inputs' array")
    active: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise RuntimeError(f"Input at index {index} must be a JSON object")
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuntimeError(f"Input at index {index}: 'enabled' must be true or false")
        if enabled is False:
            continue
        name = str(item.get("name") or item.get("scope") or "").strip()
        if not name:
            raise RuntimeError(f"Enabled input at index {index} has no name")
        scope = item.get("scope")
        if isinstance(scope, bool) or not isinstance(scope, (str, int)) or not str(scope).strip():
            raise RuntimeError(f"Input {name!r}: 'scope' must be a non-empty string or object ID")
        direction = str(item.get("direction", "inbound_outbound")).lower()
        if direction not in {"inbound_outbound", "inbound", "outbound"}:
            raise RuntimeError(f"Input {name!r}: invalid direction {direction!r}")
        safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in name)
        if safe_name in names:
            raise RuntimeError(f"Enabled input names must be unique (checkpoint name collision: {safe_name!r})")
        names.add(safe_name)
        active.append(item)
    if not active:
        raise RuntimeError(f"{config_path} must contain at least one enabled input")
    return active


def collect() -> int:
    key_file = os.environ.get("HORNETSECURITY_API_KEY_FILE")
    try:
        api_key = Path(key_file).read_text(encoding="utf-8").strip() if key_file else ""
    except OSError as exc:
        raise RuntimeError(f"Could not read HORNETSECURITY_API_KEY_FILE ({type(exc).__name__})") from exc
    if key_file and not api_key:
        raise RuntimeError("HORNETSECURITY_API_KEY_FILE is empty")
    if not api_key:
        api_key = os.environ.get("HORNETSECURITY_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("HORNETSECURITY_API_KEY is required")
    config_path = Path(os.environ.get("HORNETSECURITY_CONFIG", "/var/ossec/etc/hornetsecurity/inputs.json"))
    inputs = validate_inputs(config_path)
    checkpoint_dir = Path(os.environ.get("HORNETSECURITY_CHECKPOINT_DIR", "/var/ossec/queue/hornetsecurity"))
    checkpoint_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(checkpoint_dir, 0o700)
    lock_path = checkpoint_dir / "collector.lock"
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.chmod(lock_path, 0o600)
    with os.fdopen(lock_fd, "w", encoding="utf-8") as lock_stream:
        try:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Another collector process is already running; skipping this invocation")
            return 0
        try:
            retention_days = int(os.environ.get("HORNETSECURITY_RETENTION_DAYS", "30"))
        except ValueError as exc:
            raise RuntimeError("HORNETSECURITY_RETENTION_DAYS must be an integer") from exc
        if not 1 <= retention_days <= 3650:
            raise RuntimeError("HORNETSECURITY_RETENTION_DAYS must be between 1 and 3650")
        directory = output_directory()
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chmod(directory, 0o750)
        if not os.environ.get("HORNETSECURITY_OUTPUT_FILE"):
            cleanup_old_logs(directory, retention_days)
        total = 0
        failures: list[str] = []
        for input_config in inputs:
            name = str(input_config.get("name") or input_config.get("scope") or "unknown")
            try:
                total += collect_input(input_config, api_key)
            except Exception as exc:
                log(f"Input {name!r} failed: {exc}")
                failures.append(name)
        log(f"Collected {total} new emails across {len(inputs)} enabled inputs")
        if failures:
            raise RuntimeError(f"Collection failed for {len(failures)} input(s): {', '.join(failures)}")
    return 0


if __name__ == "__main__":
    if "--version" in sys.argv[1:]:
        print(f"Hornetsecurity by Proofpoint 365 Total Protection for Wazuh {__version__}")
        sys.exit(0)
    if "--check-config" in sys.argv[1:]:
        try:
            config_path = Path(os.environ.get("HORNETSECURITY_CONFIG", "/var/ossec/etc/hornetsecurity/inputs.json"))
            inputs = validate_inputs(config_path)
            print(f"Configuration is valid ({len(inputs)} enabled input(s))")
            sys.exit(0)
        except Exception as error:
            log(str(error))
            sys.exit(1)
    try:
        sys.exit(collect())
    except Exception as error:
        log(str(error))
        sys.exit(1)
