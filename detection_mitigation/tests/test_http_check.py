import importlib.util
import json
import socket
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "php2shell-http-check.py"
SPEC = importlib.util.spec_from_file_location("php2shell_http_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class FakeResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value
        self.closed = False

    def getcode(self):
        return self.status

    def getheaders(self):
        return self.headers.items()

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self):
        self.response = None
        self.hostname = None
        self.address = None
        self.timeout = None
        self.method = None
        self.path = None
        self.headers = None
        self.closed = False

    def factory(self, hostname, address, timeout):
        self.hostname = hostname
        self.address = address
        self.timeout = timeout
        return self

    def connect(self):
        pass

    def request(self, method, path, headers):
        self.method = method
        self.path = path
        self.headers = headers

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def fake_connection(response):
    connection = FakeConnection()
    connection.response = response
    return connection, connection.factory


class HttpCheckTests(unittest.TestCase):
    def setUp(self):
        self.dns = patch.object(
            CHECK.socket,
            "getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        )
        self.dns.start()
        self.addCleanup(self.dns.stop)

    def test_disclosed_php_version_is_observed_but_not_assessed_vulnerable(self):
        response = FakeResponse(200, {"X-Powered-By": "PHP/8.2.1", "Server": "nginx"})
        connection, factory = fake_connection(response)
        report = CHECK.check_url("https://example.test/wp-login.php", factory)
        self.assertEqual(report["status"], "php_version_disclosed")
        self.assertEqual(report["php_version_disclosed"], "8.2.1")
        self.assertEqual(report["vulnerability_status"], "not_determined")
        self.assertEqual(connection.method, "GET")
        self.assertEqual(connection.path, "/wp-login.php")
        self.assertEqual(connection.timeout, CHECK.TIMEOUT_SECONDS)
        self.assertEqual(connection.address, "93.184.216.34")
        self.assertTrue(response.closed)

    def test_missing_version_is_not_a_safe_verdict(self):
        connection, factory = fake_connection(FakeResponse(200, {"Server": "nginx"}))
        report = CHECK.check_url(
            "https://example.test/",
            factory,
        )
        self.assertEqual(report["status"], "no_php_version_disclosed")
        self.assertEqual(report["vulnerability_status"], "not_determined")

    def test_php_version_can_be_found_in_server_header(self):
        connection, factory = fake_connection(FakeResponse(200, {"Server": "PHP/8.4.0"}))
        report = CHECK.check_url(
            "https://example.test/",
            factory,
        )
        self.assertEqual(report["php_version_disclosed"], "8.4.0")

    def test_redirect_response_is_reported_without_following(self):
        connection, factory = fake_connection(
            FakeResponse(302, {"Location": "https://other.test/login"})
        )
        report = CHECK.check_url(
            "https://example.test/",
            factory,
        )
        self.assertEqual(report["status"], "redirect_not_followed")
        self.assertIsNone(report["php_version_disclosed"])
        self.assertEqual(connection.method, "GET")

    def test_connection_failure_is_inconclusive(self):
        connection, factory = fake_connection(FakeResponse(200, {}))

        def fail_connect():
            raise socket.timeout()

        connection.connect = fail_connect
        report = CHECK.check_url("https://example.test/", factory)
        self.assertEqual(report["status"], "connection_failed")
        self.assertEqual(report["vulnerability_status"], "not_determined")
        self.assertTrue(connection.closed)

    def test_url_validation_rejects_plain_http_credentials_and_private_hosts(self):
        with self.assertRaises(CHECK.CheckInputError):
            CHECK.validate_url("http://example.test/")
        with self.assertRaises(CHECK.CheckInputError):
            CHECK.validate_url("https://example.test:8443/")
        with self.assertRaises(CHECK.CheckInputError):
            CHECK.validate_url("https://127.0.0.1/")
        with patch.object(
            CHECK.socket,
            "getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.0.0.2", 443))],
        ):
            with self.assertRaises(CHECK.CheckInputError):
                CHECK.validate_url("https://internal.example/")

    def test_report_headers_are_sanitized_and_json_safe(self):
        connection, factory = fake_connection(
            FakeResponse(200, {"X-Powered-By": "PHP/8.2.1\r\nInjected: value"})
        )
        report = CHECK.check_url(
            "https://example.test/",
            factory,
        )
        encoded = json.dumps(report)
        self.assertNotIn("\r", encoded)
        self.assertNotIn("\n", encoded)
        self.assertNotIn("\r\n", report["x_powered_by_header"])
        self.assertTrue(report["exploitation_attempted"] is False)


if __name__ == "__main__":
    unittest.main()
