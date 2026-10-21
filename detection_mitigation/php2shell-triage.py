#!/usr/bin/env python3
"""Offline heuristic triage for explicitly supplied PHP-serving logs."""

import argparse
import datetime as dt
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_INPUTS = 20
MAX_LINES_PER_INPUT = 10000
MAX_REPORTED_EVENTS = 1000
MAX_ACCESS_TIMESTAMPS = 10000
MAX_WINDOW_SECONDS = 3600

PHP_TIME = re.compile(r"\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})\]")
APACHE_ERROR_TIME = re.compile(
    r"\[(?:[A-Za-z]{3} )?(\d{2}-[A-Za-z]{3}-\d{4} "
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]"
)
APACHE_NATIVE_TIME = re.compile(
    r"\[([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)? \d{4})\]"
)
ISO_TIME = re.compile(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\]")
ACCESS_TIME = re.compile(
    r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"
)
WORKER_ID = re.compile(r"\bchild\s+(\d+)\b", re.IGNORECASE)
MEMORY_PATTERNS = (
    re.compile(r"\ballowed memory size of\b.*\bexhausted\b", re.IGNORECASE),
    re.compile(r"\bout of memory\b", re.IGNORECASE),
    re.compile(r"\bzend_mm_heap corrupted\b", re.IGNORECASE),
    re.compile(r"\b(?:memory allocation|malloc|realloc) (?:failed|failure)\b", re.IGNORECASE),
    re.compile(r"\bcannot allocate memory\b", re.IGNORECASE),
)
WORKER_CRASH_PATTERNS = (
    re.compile(r"(?:\[pool\b.*?\]\s*)?child\s+\d+\s+exited on signal\b", re.IGNORECASE),
    re.compile(r"\bphp-cgi\b.*\b(?:segmentation fault|segfault|signal\s+11)\b", re.IGNORECASE),
    re.compile(r"\b(?:apache|httpd)\b.*\bchild\b.*\bexit(?:ed)? signal\b", re.IGNORECASE),
    re.compile(r"\bchild\s+pid\s+\d+\s+exit signal\b", re.IGNORECASE),
)
APACHE_COMMON_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
PHP_TIME_FORMAT = "%d-%b-%Y %H:%M:%S"
APACHE_ERROR_TIME_FORMAT = "%d-%b-%Y %H:%M:%S"


class InputError(Exception):
    """An explicitly selected input could not be safely read or parsed."""


def _read_selected_file(path_text):
    path = Path(path_text)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InputError("input could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InputError("input is not a regular file")
        if info.st_size > MAX_INPUT_BYTES:
            raise InputError("input exceeds the 10 MiB limit")
        data = bytearray()
        while len(data) <= MAX_INPUT_BYTES:
            chunk = os.read(fd, min(65536, MAX_INPUT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_INPUT_BYTES:
            raise InputError("input exceeds the 10 MiB limit")
        return bytes(data).decode("utf-8", errors="replace")
    except OSError as exc:
        raise InputError("input could not be read safely") from exc
    finally:
        os.close(fd)


def _parse_time(line, log_kind):
    match = ACCESS_TIME.search(line) if log_kind == "access" else None
    if match:
        try:
            return dt.datetime.strptime(match.group(1), APACHE_COMMON_TIME_FORMAT)
        except ValueError:
            return None
    match = ISO_TIME.search(line)
    if match:
        try:
            return dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
        except ValueError:
            return None
    match = APACHE_NATIVE_TIME.search(line)
    if match:
        value = match.group(1)
        for time_format in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                return dt.datetime.strptime(value, time_format)
            except ValueError:
                continue
        return None
    match = APACHE_ERROR_TIME.search(line) or PHP_TIME.search(line)
    if not match:
        return None
    value = match.group(1)
    for time_format in (APACHE_ERROR_TIME_FORMAT, PHP_TIME_FORMAT):
        try:
            return dt.datetime.strptime(value.split(".")[0], time_format)
        except ValueError:
            continue
    return None


def _event_type(line, log_kind):
    if log_kind == "access":
        return None
    if any(pattern.search(line) for pattern in MEMORY_PATTERNS):
        return "memory_error"
    if any(pattern.search(line) for pattern in WORKER_CRASH_PATTERNS):
        return "web_worker_crash"
    return None


def _worker_id(line):
    match = WORKER_ID.search(line)
    return match.group(1) if match else None


def _runtime_assessment(path_text):
    try:
        document = json.loads(_read_selected_file(path_text))
    except (json.JSONDecodeError, InputError) as exc:
        raise InputError("runtime evidence must be a readable JSON object") from exc
    if not isinstance(document, dict):
        raise InputError("runtime evidence must be a JSON object")
    confirmed = document.get("serving_runtime_confirmed") is True
    patch_status = document.get("vendor_patch_status", "unknown")
    if patch_status not in ("patched", "unpatched", "unknown"):
        raise InputError("vendor_patch_status must be patched, unpatched, or unknown")
    return {
        "provided": True,
        "serving_runtime_confirmed": confirmed,
        "vendor_patch_status": patch_status,
        "potential_exposure": confirmed and patch_status == "unpatched",
    }


def analyze(error_logs=(), access_logs=(), runtime_evidence=None, window_seconds=60):
    if len(error_logs) + len(access_logs) + bool(runtime_evidence) > MAX_INPUTS:
        raise InputError("select no more than 20 input files")
    events = []
    requests = []
    files_read = 0
    malformed_lines = 0
    timestamped_lines = 0
    observed_counts = {"memory_error": 0, "web_worker_crash": 0}
    omitted_events = 0
    access_count = 0
    omitted_access_timestamps = 0

    for log_kind, paths in (("error", error_logs), ("access", access_logs)):
        for path_text in paths:
            contents = _read_selected_file(path_text)
            files_read += 1
            input_id = files_read
            lines = contents.splitlines()
            if len(lines) > MAX_LINES_PER_INPUT:
                raise InputError("input exceeds the 10,000-line limit")
            for line_number, line in enumerate(lines, 1):
                parsed_time = _parse_time(line, log_kind)
                if parsed_time:
                    timestamped_lines += 1
                elif line.strip() and (log_kind == "access" or "[" in line):
                    malformed_lines += 1
                if log_kind == "access":
                    if parsed_time:
                        access_count += 1
                        if len(requests) < MAX_ACCESS_TIMESTAMPS:
                            requests.append(parsed_time)
                        else:
                            omitted_access_timestamps += 1
                    continue
                kind = _event_type(line, log_kind)
                if kind:
                    observed_counts[kind] += 1
                    if len(events) >= MAX_REPORTED_EVENTS:
                        omitted_events += 1
                        continue
                    events.append({
                        "id": len(events) + 1,
                        "input_id": input_id,
                        "type": kind,
                        "line": line_number,
                        "time": parsed_time,
                        "worker": _worker_id(line),
                        "nearby_requests": 0,
                        "same_worker_signal_ids": [],
                    })

    runtime = _runtime_assessment(runtime_evidence) if runtime_evidence else {
        "provided": False,
        "serving_runtime_confirmed": False,
        "vendor_patch_status": "unknown",
        "potential_exposure": False,
    }
    for event in events:
        if event["time"] is None:
            continue
        for request_time in requests:
            if event["time"].tzinfo is not None and request_time.tzinfo is None:
                continue
            if event["time"].tzinfo is None and request_time.tzinfo is not None:
                continue
            if abs((event["time"] - request_time).total_seconds()) <= window_seconds:
                event["nearby_requests"] += 1
        if event["worker"]:
            for other in events:
                if other is event or other["worker"] != event["worker"] or other["time"] is None:
                    continue
                if event["time"].tzinfo is not None and other["time"].tzinfo is None:
                    continue
                if event["time"].tzinfo is None and other["time"].tzinfo is not None:
                    continue
                if abs((event["time"] - other["time"]).total_seconds()) <= window_seconds:
                    event["same_worker_signal_ids"].append(other["id"])

    statuses = []
    if sum(observed_counts.values()):
        statuses.append("telemetry_anomaly_observed")
    if runtime["potential_exposure"]:
        statuses.append("potential_exposure")
    if not statuses:
        statuses.append("insufficient_evidence")

    public_events = [
        {key: value for key, value in event.items() if key not in ("time", "worker")}
        for event in events
    ]
    return {
        "tool": "php2shell-triage",
        "schema_version": 1,
        "status": statuses[0],
        "statuses": statuses,
        "cve_specific_indicator_verified": False,
        "summary": {
            "error_events": sum(observed_counts.values()),
            "memory_errors": observed_counts["memory_error"],
            "web_worker_crashes": observed_counts["web_worker_crash"],
            "access_requests": access_count,
            "files_read": files_read + bool(runtime_evidence),
            "timestamped_lines": timestamped_lines,
            "malformed_or_untimestamped_lines": malformed_lines,
            "omitted_events_from_report": omitted_events,
            "omitted_access_timestamps_from_correlation": omitted_access_timestamps,
        },
        "events": public_events,
        "runtime_evidence": runtime,
        "limitations": [
            "Signals are generic heuristics, not PHP2Shell or CVE-specific indicators.",
            "Temporal proximity to access requests does not prove causation or exploitation.",
            "A clean or patched assessment does not establish that a system was never compromised.",
            "No conclusion is possible when serving-runtime provenance or telemetry is incomplete.",
        ],
    }


def _human_report(report):
    summary = report["summary"]
    lines = [
        "PHP2Shell defensive triage (offline heuristic; not a vulnerability scanner)",
        "Status: " + ", ".join(report["statuses"]),
        "CVE-specific indicator verified: no",
        ("Observed generic signals: " + str(summary["error_events"]) +
         " (memory errors: " + str(summary["memory_errors"]) +
         ", web-worker crashes: " + str(summary["web_worker_crashes"]) + ")"),
        "Access requests in supplied logs: " + str(summary["access_requests"]),
        "Runtime evidence: " + (
            "confirmed serving runtime; vendor patch status " +
            report["runtime_evidence"]["vendor_patch_status"]
            if report["runtime_evidence"]["serving_runtime_confirmed"]
            else "not confirmed"
        ),
    ]
    if report["events"]:
        lines.append("Signals (log contents omitted):")
        for event in report["events"]:
            lines.append(
                "  input {input_id}, line {line}: {type}; nearby access records: "
                "{nearby_requests}".format(**event)
            )
    lines.extend((
        "No findings do not mean not vulnerable or not compromised.",
        "Use the documented operator steps to verify and patch the actual serving runtime.",
    ))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--error-log", action="append", default=[], metavar="FILE",
                        help="explicit local PHP-FPM/Apache error log (repeatable)")
    parser.add_argument("--access-log", action="append", default=[], metavar="FILE",
                        help="explicit local Apache access log (repeatable)")
    parser.add_argument("--runtime-evidence", metavar="JSON_FILE",
                        help="explicit local JSON evidence; see the README")
    parser.add_argument("--window-seconds", type=int, default=60,
                        help="maximum correlation window (0-3600; default 60)")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    args = parser.parse_args(argv)
    if not 0 <= args.window_seconds <= MAX_WINDOW_SECONDS:
        parser.error("--window-seconds must be between 0 and 3600")
    if not args.error_log and not args.access_log and not args.runtime_evidence:
        parser.error("provide at least one explicit log or --runtime-evidence file")
    try:
        report = analyze(args.error_log, args.access_log, args.runtime_evidence, args.window_seconds)
    except InputError as exc:
        if args.format == "json":
            print(json.dumps({"tool": "php2shell-triage", "error": str(exc)}, sort_keys=True))
        else:
            print("Input error: " + str(exc), file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True))
    else:
        print(_human_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
