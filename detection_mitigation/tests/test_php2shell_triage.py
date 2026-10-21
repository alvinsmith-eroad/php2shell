import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "php2shell-triage.py"
FIXTURES = ROOT / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location("php2shell_triage", SCRIPT)
TRIAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRIAGE)


class TriageTests(unittest.TestCase):
    def test_memory_and_worker_crash_are_generic_anomalies(self):
        report = TRIAGE.analyze([str(FIXTURES / "error-positive.log")])
        self.assertEqual(report["status"], "telemetry_anomaly_observed")
        self.assertEqual(report["summary"]["memory_errors"], 1)
        self.assertEqual(report["summary"]["web_worker_crashes"], 1)
        self.assertFalse(report["cve_specific_indicator_verified"])
        self.assertEqual(report["events"][0]["same_worker_signal_ids"], [])

    def test_access_correlation_observes_timezone_and_window(self):
        nearby = TRIAGE.analyze(
            [str(FIXTURES / "error-iso.log")],
            [str(FIXTURES / "access.log")],
            window_seconds=60,
        )
        distant = TRIAGE.analyze(
            [str(FIXTURES / "error-iso.log")],
            [str(FIXTURES / "access.log")],
            window_seconds=1,
        )
        self.assertEqual(nearby["events"][0]["nearby_requests"], 1)
        self.assertEqual(distant["events"][0]["nearby_requests"], 0)

    def test_negative_and_missing_telemetry_remain_unknown(self):
        report = TRIAGE.analyze([str(FIXTURES / "error-unrelated.log")])
        self.assertEqual(report["statuses"], ["insufficient_evidence"])
        self.assertEqual(report["events"], [])
        empty = TRIAGE.analyze([str(FIXTURES / "error-malformed.log")])
        self.assertEqual(empty["status"], "insufficient_evidence")
        self.assertGreater(empty["summary"]["malformed_or_untimestamped_lines"], 0)

    def test_memory_signal_without_a_parseable_timestamp_is_still_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            error = Path(directory) / "error.log"
            error.write_text("[not-a-date] PHP Fatal error: Out of memory\n")
            report = TRIAGE.analyze([str(error)])
        self.assertEqual(report["status"], "telemetry_anomaly_observed")
        self.assertEqual(report["events"][0]["nearby_requests"], 0)

    def test_reported_event_count_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            error = Path(directory) / "many-events.log"
            error.write_text("Out of memory\n" * (TRIAGE.MAX_REPORTED_EVENTS + 5))
            report = TRIAGE.analyze([str(error)])
        self.assertEqual(len(report["events"]), TRIAGE.MAX_REPORTED_EVENTS)
        self.assertEqual(report["summary"]["error_events"], TRIAGE.MAX_REPORTED_EVENTS + 5)
        self.assertEqual(report["summary"]["omitted_events_from_report"], 5)

    def test_confirmed_unpatched_runtime_is_potential_exposure(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "runtime.json"
            evidence.write_text(json.dumps({
                "serving_runtime_confirmed": True,
                "vendor_patch_status": "unpatched",
            }))
            report = TRIAGE.analyze(runtime_evidence=str(evidence))
        self.assertEqual(report["statuses"], ["potential_exposure"])

    def test_rejects_symlinks_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.log"
            target.write_text("log")
            link = Path(directory) / "link.log"
            link.symlink_to(target)
            with self.assertRaises(TRIAGE.InputError):
                TRIAGE.analyze([str(link)])

            large = Path(directory) / "large.log"
            with large.open("wb") as output:
                output.truncate(TRIAGE.MAX_INPUT_BYTES + 1)
            with self.assertRaises(TRIAGE.InputError):
                TRIAGE.analyze([str(large)])

            fifo = Path(directory) / "input.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(TRIAGE.InputError):
                TRIAGE.analyze([str(fifo)])

    def test_invalid_encoding_is_replaced_without_exposing_log_text(self):
        with tempfile.TemporaryDirectory() as directory:
            error = Path(directory) / "invalid-encoding.log"
            error.write_bytes(b"[21-Oct-2026 10:00:00] PHP Warning: \xff\n")
            report = TRIAGE.analyze([str(error)])
        self.assertEqual(report["status"], "insufficient_evidence")
        self.assertEqual(report["summary"]["timestamped_lines"], 1)

    def test_cli_json_is_bounded_and_omits_log_content(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--error-log", str(FIXTURES / "error-positive.log"),
             "--format", "json"],
            check=True, capture_output=True, text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "telemetry_anomaly_observed")
        self.assertNotIn("Allowed memory size", result.stdout)
        self.assertNotIn("192.0.2.20", result.stdout)

    def test_timestamp_timezone_mismatch_is_not_correlated(self):
        with tempfile.TemporaryDirectory() as directory:
            error = Path(directory) / "error.log"
            error.write_text("[21-Oct-2026 10:00:00] PHP Fatal error: Out of memory\n")
            access = Path(directory) / "access.log"
            access.write_text(
                '192.0.2.20 - - [21/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n'
            )
            report = TRIAGE.analyze([str(error)], [str(access)])
        self.assertEqual(report["events"][0]["nearby_requests"], 0)

    def test_same_worker_events_correlate_only_when_identity_is_present(self):
        with tempfile.TemporaryDirectory() as directory:
            error = Path(directory) / "error.log"
            error.write_text(
                "[2026-10-21T10:00:00+00:00] [pool www] child 77 exited on signal 11\n"
                "[2026-10-21T10:00:10+00:00] child 77 PHP Fatal error: Out of memory\n"
            )
            report = TRIAGE.analyze([str(error)])
        self.assertEqual(report["events"][0]["same_worker_signal_ids"], [2])
        self.assertEqual(report["events"][1]["same_worker_signal_ids"], [1])


if __name__ == "__main__":
    unittest.main()
